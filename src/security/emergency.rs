//! Phase 2 — Emergency timed-grant access.
//!
//! Static Shamir/PDF recovery is untouched. New flow: grantee creates a
//! REQUEST (PQ public key + wait) → grantor APPROVES → enforced WAIT →
//! grantor seals the 5 Shamir shards into an ENVELOPE for the grantee key →
//! grantee opens it at/after maturity (takeover = the existing shard-
//! recovery path, never a new unlock bypass).
//!
//! Relay transport: separate `emergency/<id>.<kind>.json` objects in the
//! SAME private repo (never the vault blob path/message); ciphertext +
//! metadata only, fixed generic commit message, size-capped. Manual
//! copy-paste transport shares the same encode/decode (offline-friendly).

use crate::core::pq_hybrid::{PqHybridEngine, EK_LEN};
use crate::error::{Result, VaultError};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use hkdf::Hkdf;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const GRANT_VERSION: u32 = 1;
/// Wait floor (1h) and cap (30d) — too short defeats the dead-man purpose,
/// unbounded waits strand grants.
pub const MIN_WAIT_SECS: u64 = 3_600;
pub const MAX_WAIT_SECS: u64 = 30 * 86_400;
/// Relay objects are tiny JSON — anything bigger is hostile/malformed.
pub const MAX_RELAY_BYTES: usize = 64 * 1024;
/// Canonical HKDF info — both sides must agree bit-for-bit.
const ENVELOPE_INFO: &[u8] = b"phantom_vault_emergency_grant_v1";

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn b64e(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| VaultError::Security("grant field is not base64".into()))
}

// ---------------------------------------------------------------------------
// Request: grantee PQ public key + enforced wait. No secrets inside.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireRequest {
    v: u32,
    grantee_pub_b64: String,
    wait_secs: u64,
    nonce_b64: String,
    requested_at: u64,
}

#[derive(Debug, Clone)]
pub struct GrantRequest {
    pub grantee_pub: Vec<u8>,
    pub wait_secs: u64,
    pub nonce: [u8; 16],
    pub requested_at: u64,
}

impl GrantRequest {
    /// Grantee side: bind a fresh wait to a PQ encapsulation key. Refuses
    /// bad key lengths and out-of-range waits LOUD (never silent-clamp —
    /// the wait is the security property).
    pub fn create(grantee_pub: &[u8], wait_secs: u64, now: u64) -> Result<Self> {
        if grantee_pub.len() != EK_LEN {
            return Err(VaultError::Security("bad grantee PQ key length".into()));
        }
        if !(MIN_WAIT_SECS..=MAX_WAIT_SECS).contains(&wait_secs) {
            return Err(VaultError::Security("wait out of range (1h..30d)".into()));
        }
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        Ok(Self {
            grantee_pub: grantee_pub.to_vec(),
            wait_secs,
            nonce,
            requested_at: now,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let w = WireRequest {
            v: GRANT_VERSION,
            grantee_pub_b64: b64e(&self.grantee_pub),
            wait_secs: self.wait_secs,
            nonce_b64: b64e(&self.nonce),
            requested_at: self.requested_at,
        };
        serde_json::to_vec(&w).map_err(|_| VaultError::Security("grant encode failed".into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RELAY_BYTES {
            return Err(VaultError::Security("grant object too large".into()));
        }
        let w: WireRequest = serde_json::from_slice(bytes)
            .map_err(|_| VaultError::Security("grant object corrupt".into()))?;
        if w.v != GRANT_VERSION {
            return Err(VaultError::Security("unsupported grant version".into()));
        }
        let grantee_pub = b64d(&w.grantee_pub_b64)?;
        let nonce_raw = b64d(&w.nonce_b64)?;
        if grantee_pub.len() != EK_LEN || nonce_raw.len() != 16 {
            return Err(VaultError::Security("grant field length mismatch".into()));
        }
        if !(MIN_WAIT_SECS..=MAX_WAIT_SECS).contains(&w.wait_secs) {
            return Err(VaultError::Security("wait out of range (1h..30d)".into()));
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_raw);
        Ok(Self {
            grantee_pub,
            wait_secs: w.wait_secs,
            nonce,
            requested_at: w.requested_at,
        })
    }

    /// Stable grant id: sha256 hex of the canonical encoding. Used as the
    /// relay filename stem and the approval/envelope binding.
    pub fn id(&self) -> Result<String> {
        Ok(hex(&Sha256::digest(self.encode()?)))
    }
}

// ---------------------------------------------------------------------------
// Approval: grantor binds request id → release time. Maturity is checked by
// `seal_envelope`, never trusted from the relay object alone.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireApproval {
    v: u32,
    request_id: String,
    approved_at: u64,
    release_at: u64,
}

#[derive(Debug, Clone)]
pub struct GrantApproval {
    pub request_id: String,
    pub approved_at: u64,
    pub release_at: u64,
}

impl GrantApproval {
    pub fn approve(request_id: &str, wait_secs: u64, now: u64) -> Result<Self> {
        if request_id.len() != 64 || !request_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VaultError::Security("bad grant id".into()));
        }
        if !(MIN_WAIT_SECS..=MAX_WAIT_SECS).contains(&wait_secs) {
            return Err(VaultError::Security("wait out of range (1h..30d)".into()));
        }
        Ok(Self {
            request_id: request_id.to_lowercase(),
            approved_at: now,
            release_at: now.saturating_add(wait_secs),
        })
    }

    pub fn is_mature(&self, now: u64) -> bool {
        now >= self.release_at
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let w = WireApproval {
            v: GRANT_VERSION,
            request_id: self.request_id.clone(),
            approved_at: self.approved_at,
            release_at: self.release_at,
        };
        serde_json::to_vec(&w).map_err(|_| VaultError::Security("approval encode failed".into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RELAY_BYTES {
            return Err(VaultError::Security("approval object too large".into()));
        }
        let w: WireApproval = serde_json::from_slice(bytes)
            .map_err(|_| VaultError::Security("approval object corrupt".into()))?;
        if w.v != GRANT_VERSION {
            return Err(VaultError::Security("unsupported approval version".into()));
        }
        Self::approve(&w.request_id, w.release_at.saturating_sub(w.approved_at), w.approved_at)
            .map(|mut a| {
                a.release_at = w.release_at;
                a
            })
    }
}

// ---------------------------------------------------------------------------
// Envelope: the 5 Shamir shards sealed for the grantee key. Seal refuses
// unless the approval is mature AND bound to this exact request.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireEnvelope {
    v: u32,
    request_id: String,
    kem_ct_b64: String,
    nonce_b64: String,
    sealed_b64: String,
}

#[derive(Debug, Clone)]
pub struct GrantEnvelope {
    pub request_id: String,
    pub kem_ct: Vec<u8>,
    pub nonce: [u8; 24],
    pub sealed: Vec<u8>,
}

fn envelope_key(shared: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; 32];
    hk.expand(ENVELOPE_INFO, &mut okm)
        .map_err(|_| VaultError::Crypto("grant HKDF expansion failed".into()))?;
    Ok(okm)
}

/// Grantor side: seal all 5 shards. Needs the unlocked master upstream
/// (callers split via `Shamir::split` — shards never touch disk or logs).
pub fn seal_envelope(
    req: &GrantRequest,
    approval: &GrantApproval,
    shards: &[String],
    now: u64,
) -> Result<GrantEnvelope> {
    let id = req.id()?;
    if approval.request_id != id {
        return Err(VaultError::Security("approval is for another grant".into()));
    }
    if !approval.is_mature(now) {
        return Err(VaultError::Security("grant not mature — wait longer".into()));
    }
    if shards.len() != 5 || shards.iter().any(|s| s.trim().is_empty()) {
        return Err(VaultError::Security("envelope needs exactly 5 shards".into()));
    }
    let (ct, ss) = PqHybridEngine::encapsulate(&req.grantee_pub)?;
    let mut key = envelope_key(ss.expose())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let plain =
        serde_json::to_vec(shards).map_err(|_| VaultError::Security("shard encode failed".into()))?;
    let sealed = cipher
        .encrypt(&nonce, plain.as_slice())
        .map_err(|_| VaultError::Crypto("grant seal failed".into()))?;
    key.zeroize();
    let mut nonce_arr = [0u8; 24];
    nonce_arr.copy_from_slice(nonce.as_slice());
    Ok(GrantEnvelope {
        request_id: id,
        kem_ct: ct,
        nonce: nonce_arr,
        sealed,
    })
}

/// Grantee side: open with the decapsulation key. Wrong key / tampered
/// envelope fails closed; returned shards feed the EXISTING shard-recovery
/// path (no new unlock bypass).
pub fn open_envelope(env: &GrantEnvelope, decapsulation_key: &[u8]) -> Result<Vec<String>> {
    let ss = PqHybridEngine::decapsulate(decapsulation_key, &env.kem_ct)?;
    let mut key = envelope_key(ss.expose())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = chacha20poly1305::XNonce::from_slice(&env.nonce);
    let plain = cipher
        .decrypt(nonce, env.sealed.as_slice())
        .map_err(|_| VaultError::Crypto("grant open failed".into()))?;
    key.zeroize();
    let shards: Vec<String> = serde_json::from_slice(&plain)
        .map_err(|_| VaultError::Security("grant payload corrupt".into()))?;
    if shards.len() != 5 || shards.iter().any(|s| s.trim().is_empty()) {
        return Err(VaultError::Security("grant payload corrupt".into()));
    }
    Ok(shards)
}

impl GrantEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let w = WireEnvelope {
            v: GRANT_VERSION,
            request_id: self.request_id.clone(),
            kem_ct_b64: b64e(&self.kem_ct),
            nonce_b64: b64e(&self.nonce),
            sealed_b64: b64e(&self.sealed),
        };
        serde_json::to_vec(&w).map_err(|_| VaultError::Security("envelope encode failed".into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RELAY_BYTES {
            return Err(VaultError::Security("envelope object too large".into()));
        }
        let w: WireEnvelope = serde_json::from_slice(bytes)
            .map_err(|_| VaultError::Security("envelope object corrupt".into()))?;
        if w.v != GRANT_VERSION {
            return Err(VaultError::Security("unsupported envelope version".into()));
        }
        if w.request_id.len() != 64 || !w.request_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VaultError::Security("bad grant id".into()));
        }
        let kem_ct = b64d(&w.kem_ct_b64)?;
        let nonce_raw = b64d(&w.nonce_b64)?;
        let sealed = b64d(&w.sealed_b64)?;
        if nonce_raw.len() != 24 || sealed.is_empty() {
            return Err(VaultError::Security("envelope field length mismatch".into()));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_raw);
        Ok(Self {
            request_id: w.request_id.to_lowercase(),
            kem_ct,
            nonce,
            sealed,
        })
    }
}

// ---------------------------------------------------------------------------
// Relay paths: strict stems only — no listing, no search, no metadata.
// ---------------------------------------------------------------------------

/// `emergency/<64-hex-id>.<kind>.json`. Anything else is refused.
pub fn relay_path(id: &str, kind: &str) -> Result<String> {
    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VaultError::Security("bad grant id".into()));
    }
    if !matches!(kind, "request" | "approved" | "envelope") {
        return Err(VaultError::Security("bad relay kind".into()));
    }
    Ok(format!("emergency/{}.{}.json", id.to_lowercase(), kind))
}

// ---------------------------------------------------------------------------
// Relay transport: thin create-or-update / fetch over the existing private
// repo credentials. Mirrors the vault-sync privacy contract (fixed generic
// commit message, size caps, token zeroized by the caller worker).
// ---------------------------------------------------------------------------

/// Fetch one relay object. None = not published yet (fresh grant).
async fn relay_fetch(
    octo: &octocrab::Octocrab,
    owner: &str,
    repo: &str,
    path: &str,
) -> Result<Option<(Vec<u8>, String)>> {
    use base64::Engine as _;
    let items = match octo.repos(owner, repo).get_content().path(path).send().await {
        Ok(items) => items,
        Err(e) => {
            if crate::sync::github_sync::is_not_found(&e) {
                return Ok(None);
            }
            return Err(VaultError::Sync(format!("relay fetch failed: {e}")));
        }
    };
    let first = items
        .items
        .first()
        .ok_or_else(|| VaultError::Sync("relay object missing".into()))?;
    let sha = first.sha.clone();
    let decoded = first
        .decoded_content()
        .ok_or_else(|| VaultError::Sync("relay object unreadable".into()))?;
    if decoded.len() > MAX_RELAY_BYTES {
        return Err(VaultError::Sync("relay object suspiciously large".into()));
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(decoded.trim())
        .map_err(|e| VaultError::Sync(format!("relay object corrupt: {e}")))?;
    Ok(Some((raw, sha)))
}

/// Publish (create or update) one relay object. Returns the new remote sha.
/// Same privacy contract as vault sync: fixed generic commit message, no
/// timestamps/counts/names anywhere.
pub async fn relay_put(
    owner: &str,
    repo: &str,
    token: &str,
    path: &str,
    bytes: &[u8],
) -> Result<String> {
    use base64::Engine as _;
    if bytes.is_empty() || bytes.len() > MAX_RELAY_BYTES {
        return Err(VaultError::Sync("relay payload invalid".into()));
    }
    let octo = crate::sync::github_sync::client(token)?;
    let current = relay_fetch(&octo, owner, repo, path).await?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    if let Some((_, head)) = &current {
        octo.repos(owner, repo)
            .update_file(path, crate::sync::github_sync::COMMIT_MESSAGE, b64, head)
            .branch("main")
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("relay publish failed: {e}")))?;
    } else {
        octo.repos(owner, repo)
            .create_file(path, crate::sync::github_sync::COMMIT_MESSAGE, b64)
            .branch("main")
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("relay publish failed: {e}")))?;
    }
    let (_, new_sha) = relay_fetch(&octo, owner, repo, path)
        .await?
        .ok_or_else(|| VaultError::Sync("relay verify failed".into()))?;
    Ok(new_sha)
}

/// Fetch one relay object by stem id + kind. None = not published yet.
pub async fn relay_get(owner: &str, repo: &str, token: &str, id: &str, kind: &str) -> Result<Option<Vec<u8>>> {
    let octo = crate::sync::github_sync::client(token)?;
    let path = relay_path(id, kind)?;
    Ok(relay_fetch(&octo, owner, repo, &path).await?.map(|(b, _)| b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::pq_hybrid::PqHybridEngine;

    fn test_shards() -> Vec<String> {
        crate::security::shamir::Shamir::split("emergency-test-master-pw").unwrap()
    }

    #[test]
    fn request_roundtrip_and_id_stable() {
        let kp = PqHybridEngine::generate_keypair();
        let r = GrantRequest::create(&kp.encapsulation, 7_200, 1_000).unwrap();
        let bytes = r.encode().unwrap();
        let back = GrantRequest::decode(&bytes).unwrap();
        assert_eq!(back.grantee_pub, r.grantee_pub);
        assert_eq!(back.wait_secs, 7_200);
        assert_eq!(r.id().unwrap(), back.id().unwrap());
        assert_eq!(r.id().unwrap().len(), 64);
    }

    #[test]
    fn request_refuses_bad_inputs() {
        let kp = PqHybridEngine::generate_keypair();
        assert!(GrantRequest::create(&kp.encapsulation[..100], 7_200, 1_000).is_err());
        assert!(GrantRequest::create(&kp.encapsulation, 60, 1_000).is_err());
        assert!(GrantRequest::create(&kp.encapsulation, MAX_WAIT_SECS + 1, 1_000).is_err());
        assert!(GrantRequest::decode(b"not json").is_err());
        assert!(GrantRequest::decode(&vec![0u8; MAX_RELAY_BYTES + 1]).is_err());
        let mut badv = serde_json::to_vec(&WireRequest {
            v: 999,
            grantee_pub_b64: b64e(&kp.encapsulation),
            wait_secs: 7_200,
            nonce_b64: b64e(&[0u8; 16]),
            requested_at: 1_000,
        })
        .unwrap();
        let _ = &mut badv;
        assert!(GrantRequest::decode(&badv).is_err());
    }

    #[test]
    fn approval_maturity_and_binding() {
        let kp = PqHybridEngine::generate_keypair();
        let r = GrantRequest::create(&kp.encapsulation, 7_200, 1_000).unwrap();
        let id = r.id().unwrap();
        let a = GrantApproval::approve(&id, 7_200, 2_000).unwrap();
        assert_eq!(a.release_at, 9_200);
        assert!(!a.is_mature(9_199));
        assert!(a.is_mature(9_200));
        // Wrong-id approval never seals.
        let other = GrantApproval::approve(&hex(&[9u8; 32]), 7_200, 2_000).unwrap();
        assert!(seal_envelope(&r, &other, &test_shards(), 99_999).is_err());
        // Immature approval never seals.
        assert!(seal_envelope(&r, &a, &test_shards(), 9_199).is_err());
        // Bad shard counts never seal.
        assert!(seal_envelope(&r, &a, &test_shards()[..3], 99_999).is_err());
    }

    #[test]
    fn envelope_roundtrip_and_fail_closed() {
        let kp = PqHybridEngine::generate_keypair();
        let kp2 = PqHybridEngine::generate_keypair();
        let r = GrantRequest::create(&kp.encapsulation, 7_200, 1_000).unwrap();
        let a = GrantApproval::approve(&r.id().unwrap(), 7_200, 2_000).unwrap();
        let shards = test_shards();
        let env = seal_envelope(&r, &a, &shards, 99_999).unwrap();
        let bytes = env.encode().unwrap();
        let back = GrantEnvelope::decode(&bytes).unwrap();
        let opened = open_envelope(&back, kp.decapsulation.expose()).unwrap();
        assert_eq!(opened, shards);
        // Wrong recipient key fails closed.
        assert!(open_envelope(&back, kp2.decapsulation.expose()).is_err());
        // Tampered ciphertext fails closed.
        let mut evil = back.clone();
        let last = evil.sealed.len() - 1;
        evil.sealed[last] ^= 0x01;
        assert!(open_envelope(&evil, kp.decapsulation.expose()).is_err());
        // Corrupt / oversized / wrong-version decodes fail.
        assert!(GrantEnvelope::decode(b"nope").is_err());
        assert!(GrantEnvelope::decode(&vec![0u8; MAX_RELAY_BYTES + 1]).is_err());
    }

    #[test]
    fn relay_path_strict() {
        let id = hex(&[7u8; 32]);
        assert_eq!(
            relay_path(&id, "request").unwrap(),
            format!("emergency/{id}.request.json")
        );
        assert!(relay_path("short", "request").is_err());
        assert!(relay_path(&format!("{}!", &id[..63]), "request").is_err());
        assert!(relay_path(&id, "vault").is_err());
        assert!(relay_path(&id, "../escape").is_err());
    }
}
