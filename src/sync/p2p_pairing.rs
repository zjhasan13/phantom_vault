//! A15: mandatory LAN pairing.
//!
//! The old P2P gate was an optional 6-digit PIN sent over plaintext HTTP; an
//! unpaired client could pull ciphertext. A15 adds:
//! - a per-device Ed25519 key (DPAPI-sealed seed),
//! - a one-time high-entropy pairing code (64 bits, displayed once),
//! - an HMAC proof so the code never crosses the wire,
//! - a DPAPI-sealed paired-device list, and
//! - Ed25519-signed `pull`/`sync` requests (unpaired/invalid â‡’ 403).
//!
//! Honest limits: HTTP is still plaintext on the LAN; the signature protects
//! request authenticity/integrity, not confidentiality (the payload is already
//! ciphertext). Response signing is a follow-up. The code is single-use and
//! expires; re-pair to add another device.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use subtle::ConstantTimeEq;

const CODE_TTL_SECS: u64 = 5 * 60;
const CLOCK_SKEW_SECS: u64 = 120;

fn device_path() -> PathBuf {
    std::env::var("PV_P2P_DEVICE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("p2p_device.dpapi"))
}

fn paired_path() -> PathBuf {
    std::env::var("PV_P2P_PAIRED_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("p2p_paired.dpapi"))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.trim().as_bytes();
    if !b.len().is_multiple_of(2) || !b.iter().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        out.push(u8::from_str_radix(std::str::from_utf8(&b[i..i + 2]).ok()?, 16).ok()?);
    }
    Some(out)
}

fn sha_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Per-device Ed25519 key, DPAPI-sealed. Created on first use.
pub fn device_signing_key() -> Result<ed25519_dalek::SigningKey, String> {
    use rand_core::RngCore;
    let path = device_path();
    if !path.exists() {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let blob = crate::core::memory::DpapiGuard::protect(&seed)
            .map_err(|e| format!("device key seal failed: {e}"))?;
        let tmp = path.with_extension("dpapi.tmp");
        std::fs::write(&tmp, &blob).map_err(|e| format!("device key write: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("device key swap: {e}"))?;
    }
    let blob = std::fs::read(&path).map_err(|e| format!("device key read: {e}"))?;
    let secret = crate::core::memory::DpapiGuard::unprotect(&blob)
        .map_err(|_| "device key unseal failed".to_string())?;
    if secret.expose().len() != 32 {
        return Err("device key has the wrong length".to_string());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(secret.expose());
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

pub fn device_pub_hex() -> Result<String, String> {
    let sk = device_signing_key()?;
    Ok(hex(sk.verifying_key().as_bytes()))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PairedPeer {
    pub name: String,
    pub pubkey: String,
    /// Last address used for this peer (LAN only; re-pair if it changes).
    #[serde(default)]
    pub addr: String,
}

fn load_pairs() -> Vec<PairedPeer> {
    let Ok(blob) = std::fs::read(paired_path()) else {
        return Vec::new();
    };
    let Ok(secret) = crate::core::memory::DpapiGuard::unprotect(&blob) else {
        return Vec::new();
    };
    serde_json::from_slice(secret.expose()).unwrap_or_default()
}

fn save_pairs(pairs: &[PairedPeer]) -> Result<(), String> {
    let blob = serde_json::to_vec(pairs).map_err(|e| format!("paired list encode: {e}"))?;
    let sealed = crate::core::memory::DpapiGuard::protect(&blob)
        .map_err(|e| format!("paired list seal: {e}"))?;
    let path = paired_path();
    let tmp = path.with_extension("dpapi.tmp");
    std::fs::write(&tmp, &sealed).map_err(|e| format!("paired list write: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("paired list swap: {e}"))?;
    Ok(())
}

pub fn add_peer(name: &str, pubkey_hex: &str, addr: &str) -> Result<(), String> {
    if pubkey_hex.len() != 64 || !pubkey_hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid device public key".to_string());
    }
    let mut pairs = load_pairs();
    pairs.retain(|p| p.pubkey != pubkey_hex);
    pairs.push(PairedPeer {
        name: name.trim().to_string(),
        pubkey: pubkey_hex.to_lowercase(),
        addr: addr.to_string(),
    });
    save_pairs(&pairs)
}

pub fn is_paired(pubkey_hex: &str) -> bool {
    let k = pubkey_hex.trim().to_lowercase();
    load_pairs().iter().any(|p| p.pubkey == k)
}

pub fn peer_for_addr(addr: &str) -> Option<PairedPeer> {
    load_pairs().into_iter().find(|p| p.addr == addr)
}

#[allow(dead_code)]
pub fn paired_count() -> usize {
    load_pairs().len()
}

/// A15b: paired-device management UI.
pub fn list_pairs() -> Vec<PairedPeer> {
    load_pairs()
}

pub fn forget(pubkey_hex: &str) -> Result<(), String> {
    let key = pubkey_hex.trim().to_lowercase();
    let mut pairs = load_pairs();
    let before = pairs.len();
    pairs.retain(|p| p.pubkey != key);
    if pairs.len() == before {
        return Err("device is not paired".to_string());
    }
    save_pairs(&pairs)
}

// ---- one-time pairing code ------------------------------------------------

struct Session {
    code: String,
    expires: u64,
    used: bool,
}

fn session() -> &'static std::sync::Mutex<Option<Session>> {
    static S: std::sync::OnceLock<std::sync::Mutex<Option<Session>>> = std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(None))
}

/// Return the current valid code, or mint a new one (invalidating the old).
pub fn open_session() -> String {
    use rand_core::RngCore;
    let mut guard = session().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(s) = guard.as_ref() {
        if !s.used && s.expires > now_secs() {
            return s.code.clone();
        }
    }
    let mut buf = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut buf);
    let code = hex(&buf); // 16 hex chars = 64 bits; never sent over the wire
    *guard = Some(Session {
        code: code.clone(),
        expires: now_secs() + CODE_TTL_SECS,
        used: false,
    });
    code
}

pub fn current_code() -> Option<String> {
    let guard = session().lock().unwrap_or_else(|p| p.into_inner());
    guard
        .as_ref()
        .filter(|s| !s.used && s.expires > now_secs())
        .map(|s| s.code.clone())
}

/// Consume the code if it matches (constant-time). Single-use.
pub fn consume_code(candidate: &str) -> bool {
    let mut guard = session().lock().unwrap_or_else(|p| p.into_inner());
    let Some(s) = guard.as_mut() else {
        return false;
    };
    if s.used || s.expires <= now_secs() {
        return false;
    }
    let ok: bool = s
        .code
        .as_bytes()
        .ct_eq(candidate.trim().as_bytes())
        .into();
    if ok {
        s.used = true;
    }
    ok
}

pub fn revoke_session() {
    *session().lock().unwrap_or_else(|p| p.into_inner()) = None;
}

// ---- HMAC proofs ----------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

fn mac(code: &str, msg: &str) -> String {
    let mut m = <HmacSha256 as Mac>::new_from_slice(code.as_bytes()).expect("hmac key");
    m.update(msg.as_bytes());
    hex(&m.finalize().into_bytes())
}

fn mac_ok(code: &str, msg: &str, proof: &str) -> bool {
    let want = mac(code, msg);
    want.as_bytes().ct_eq(proof.trim().as_bytes()).into()
}

pub fn pair_request_proof(code: &str, client_pub: &str, nonce: &str) -> String {
    mac(code, &format!("pair|{client_pub}|{nonce}"))
}

pub fn pair_ack_proof(code: &str, host_pub: &str, client_pub: &str, nonce: &str) -> String {
    mac(code, &format!("ack|{host_pub}|{client_pub}|{nonce}"))
}

/// Server side: validate the client's proof, then persist the pairing.
/// Returns the host public key + ack proof for the client to verify.
pub fn accept_pair(
    client_name: &str,
    client_pub: &str,
    nonce: &str,
    proof: &str,
    client_addr: &str,
) -> Result<(String, String), String> {
    let code = current_code().ok_or_else(|| "no active pairing code".to_string())?;
    if !mac_ok(&code, &format!("pair|{client_pub}|{nonce}"), proof) {
        return Err("pairing proof rejected".to_string());
    }
    let host_pub = device_pub_hex()?;
    add_peer(client_name, client_pub, client_addr)?;
    // The code is single-use: consume only after the peer is stored.
    consume_code(&code);
    Ok((
        host_pub.clone(),
        pair_ack_proof(&code, &host_pub, client_pub, nonce),
    ))
}

// ---- signed requests ------------------------------------------------------

fn canonical(method: &str, path: &str, body: &[u8], time: u64) -> String {
    format!("{method}\n{path}\n{}\n{time}", sha_hex(body))
}

pub fn sign_request(method: &str, path: &str, body: &[u8]) -> Result<(String, String, String), String> {
    use ed25519_dalek::Signer as _;
    let sk = device_signing_key()?;
    let time = now_secs();
    let sig = sk.sign(canonical(method, path, body, time).as_bytes());
    Ok((
        hex(sk.verifying_key().as_bytes()),
        time.to_string(),
        hex(&sig.to_bytes()),
    ))
}

pub fn verify_request(
    method: &str,
    path: &str,
    body: &[u8],
    key_hex: &str,
    time_str: &str,
    sig_hex: &str,
) -> Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let key = key_hex.trim().to_lowercase();
    if !is_paired(&key) {
        return Err("device is not paired".to_string());
    }
    let time = time_str.parse::<u64>().map_err(|_| "bad request time".to_string())?;
    let now = now_secs();
    if time.abs_diff(now) > CLOCK_SKEW_SECS {
        return Err("stale request".to_string());
    }
    let kb = unhex(&key).ok_or_else(|| "bad device key".to_string())?;
    if kb.len() != 32 {
        return Err("bad device key length".to_string());
    }
    let mut karr = [0u8; 32];
    karr.copy_from_slice(&kb);
    let vk = VerifyingKey::from_bytes(&karr).map_err(|_| "bad device key".to_string())?;
    let sb = unhex(sig_hex).ok_or_else(|| "bad signature".to_string())?;
    if sb.len() != 64 {
        return Err("bad signature length".to_string());
    }
    let mut sarr = [0u8; 64];
    sarr.copy_from_slice(&sb);
    vk.verify_strict(
        canonical(method, path, body, time).as_bytes(),
        &Signature::from_bytes(&sarr),
    )
    .map_err(|_| "bad request signature".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!("pv-pair-{tag}-{}.dpapi", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn device_key_is_stable_and_pairing_roundtrips() {
        let _g = crate::sync::TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("PV_P2P_DEVICE_FILE", tmp("dev"));
        std::env::set_var("PV_P2P_PAIRED_FILE", tmp("paired"));
        let _ = std::fs::remove_file(device_path());
        let _ = std::fs::remove_file(paired_path());
        revoke_session();
        let pub1 = device_pub_hex().unwrap();
        assert_eq!(pub1, device_pub_hex().unwrap());

        let code = open_session();
        let client_pub = "11".repeat(32);
        let nonce = "abcd";
        let proof = pair_request_proof(&code, &client_pub, nonce);
        let (host_pub, ack) = accept_pair("laptop", &client_pub, nonce, &proof, "192.0.2.5").unwrap();
        assert_eq!(host_pub, pub1);
        assert!(mac_ok(&code, &format!("ack|{host_pub}|{client_pub}|{nonce}"), &ack));
        assert!(is_paired(&client_pub));
        // Single-use: a second pairing with the old code is refused.
        assert!(accept_pair("x", &client_pub, nonce, &proof, "192.0.2.6").is_err());
        let _ = std::fs::remove_file(device_path());
        let _ = std::fs::remove_file(paired_path());
    }

    #[test]
    fn wrong_pairing_proof_and_unpaired_requests_are_refused() {
        let _g = crate::sync::TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("PV_P2P_DEVICE_FILE", tmp("dev2"));
        std::env::set_var("PV_P2P_PAIRED_FILE", tmp("paired2"));
        let _ = std::fs::remove_file(device_path());
        let _ = std::fs::remove_file(paired_path());
        revoke_session();
        open_session();
        let client_pub = "22".repeat(32);
        assert!(accept_pair("x", &client_pub, "n", "deadbeef", "192.0.2.7").is_err());
        assert!(!is_paired(&client_pub));
        let (k, t, s) = sign_request("GET", "/p2p/pull", b"").unwrap();
        assert!(verify_request("GET", "/p2p/pull", b"", &k, &t, &s).is_err());
        let _ = std::fs::remove_file(device_path());
        let _ = std::fs::remove_file(paired_path());
    }

    #[test]
    fn forget_removes_a_paired_device() {
        let _g = crate::sync::TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("PV_P2P_DEVICE_FILE", tmp("dev4"));
        std::env::set_var("PV_P2P_PAIRED_FILE", tmp("paired4"));
        let _ = std::fs::remove_file(paired_path());
        let key = "33".repeat(32);
        add_peer("phone", &key, "192.0.2.9").unwrap();
        assert!(is_paired(&key));
        assert_eq!(list_pairs().len(), 1);
        forget(&key).unwrap();
        assert!(!is_paired(&key));
        assert!(forget(&key).is_err());
        let _ = std::fs::remove_file(paired_path());
    }

    #[test]
    fn signed_requests_verify_and_reject_tamper() {
        let _g = crate::sync::TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("PV_P2P_DEVICE_FILE", tmp("dev3"));
        std::env::set_var("PV_P2P_PAIRED_FILE", tmp("paired3"));
        let _ = std::fs::remove_file(device_path());
        let _ = std::fs::remove_file(paired_path());
        revoke_session();
        let code = open_session();
        let (k, t, s) = sign_request("POST", "/p2p/sync", b"{}").unwrap();
        // Pair the device itself so the key is trusted.
        let _ = code;
        add_peer("self", &k, "127.0.0.1").unwrap();
        assert!(verify_request("POST", "/p2p/sync", b"{}", &k, &t, &s).is_ok());
        assert!(verify_request("POST", "/p2p/sync", b"{\"x\":1}", &k, &t, &s).is_err());
        assert!(verify_request("GET", "/p2p/pull", b"{}", &k, &t, &s).is_err());
        // Stale timestamp.
        let old = (now_secs() - 999).to_string();
        assert!(verify_request("POST", "/p2p/sync", b"{}", &k, &old, &s).is_err());
        let _ = std::fs::remove_file(device_path());
        let _ = std::fs::remove_file(paired_path());
    }
}
