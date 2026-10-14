//! Phase 1 — Per-item sharing grant envelopes (single-owner default).
//!
//! The vault stays single-owner: sharing one item mints a GRANT record
//! (metadata only, persisted in the vault) plus a sealed ENVELOPE for the
//! grantee PQ key (copy-paste transport). No shared passwords, no joint
//! vault, no server.
//!
//! Crypto honesty: an issued envelope copy cannot be un-issued — revoking
//! marks the grant AND requires rotating the item secret. Opening is
//! offline; revocation is enforced at seal/serve time, never inside an
//! already-issued envelope.

use crate::core::pq_hybrid::{PqHybridEngine, EK_LEN};
use crate::error::{Result, VaultError};
use crate::models::SharedGrant;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const SHARE_VERSION: u32 = 1;
/// Envelopes are small item payloads — anything bigger is hostile.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
/// MVP scope: logins only. Other kinds refuse LOUD at grant time.
pub const SUPPORTED_KIND: &str = "login";
/// Canonical HKDF info — both sides must agree bit-for-bit.
const SHARE_INFO: &[u8] = b"phantom_vault_share_grant_v1";

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
        .map_err(|_| VaultError::Security("share field is not base64".into()))
}

/// sha256 hex fingerprint of a grantee PQ encapsulation key (the key
/// itself never lands in the vault — 1184 bytes would bloat every save).
pub fn grantee_fingerprint(grantee_pub: &[u8]) -> Result<String> {
    if grantee_pub.len() != EK_LEN {
        return Err(VaultError::Security("bad grantee PQ key length".into()));
    }
    Ok(hex(&Sha256::digest(grantee_pub)))
}

/// Stable grant id binding kind + item + grantee key + time.
pub fn grant_id(item_kind: &str, item_id: &str, grantee_fp: &str, now: u64) -> String {
    let mut h = Sha256::new();
    h.update(b"phantom-vault-share-v1|");
    h.update(item_kind.as_bytes());
    h.update(b"|");
    h.update(item_id.as_bytes());
    h.update(b"|");
    h.update(grantee_fp.as_bytes());
    h.update(b"|");
    h.update(now.to_string().as_bytes());
    hex(&h.finalize())
}

/// Grantor side: mint a grant record. Non-login kinds and empty ids
/// refuse LOUD (never a half-grant).
pub fn create_grant(item_kind: &str, item_id: &str, grantee_pub: &[u8], now: u64) -> Result<SharedGrant> {
    if item_kind != SUPPORTED_KIND {
        return Err(VaultError::Security("only login items can be shared in this build".into()));
    }
    if item_id.trim().is_empty() {
        return Err(VaultError::Security("item id required".into()));
    }
    let grantee_fp = grantee_fingerprint(grantee_pub)?;
    let grant_id = grant_id(item_kind, item_id.trim(), &grantee_fp, now);
    Ok(SharedGrant {
        grant_id,
        item_kind: item_kind.to_string(),
        item_id: item_id.trim().to_string(),
        grantee_fp,
        granted_at: now,
        revoked: false,
    })
}

/// Canonical login share payload (grantor builds from the live item —
/// never from logs, never with history/attachments).
pub fn login_share_payload(title: &str, username: &str, password: &str, urls: &[String]) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(VaultError::Security("refusing to share an empty password".into()));
    }
    let v = serde_json::json!({
        "v": SHARE_VERSION,
        "kind": SUPPORTED_KIND,
        "title": title,
        "username": username,
        "password": password,
        "urls": urls,
    });
    serde_json::to_vec(&v).map_err(|_| VaultError::Security("share payload encode failed".into()))
}

// ---------------------------------------------------------------------------
// Envelope: item payload sealed for the grantee key. Seal refuses revoked
// or mismatched grants; open is offline and fails closed.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireShareEnvelope {
    v: u32,
    grant_id: String,
    kem_ct_b64: String,
    nonce_b64: String,
    sealed_b64: String,
}

#[derive(Debug, Clone)]
pub struct ShareEnvelope {
    pub grant_id: String,
    pub kem_ct: Vec<u8>,
    pub nonce: [u8; 24],
    pub sealed: Vec<u8>,
}

fn share_key(shared: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; 32];
    hk.expand(SHARE_INFO, &mut okm)
        .map_err(|_| VaultError::Crypto("share HKDF expansion failed".into()))?;
    Ok(okm)
}

pub fn seal_item_envelope(
    grant: &SharedGrant,
    grantee_pub: &[u8],
    item_json: &[u8],
) -> Result<ShareEnvelope> {
    if grant.revoked {
        return Err(VaultError::Security("grant is revoked — rotate the item secret".into()));
    }
    if grantee_pub.len() != EK_LEN {
        return Err(VaultError::Security("bad grantee PQ key length".into()));
    }
    if item_json.is_empty() || item_json.len() > MAX_ENVELOPE_BYTES {
        return Err(VaultError::Security("share payload invalid".into()));
    }
    // Bind the envelope to the recorded fingerprint — a swapped key fails.
    if grantee_fingerprint(grantee_pub)? != grant.grantee_fp {
        return Err(VaultError::Security("grantee key does not match the grant".into()));
    }
    let (ct, ss) = PqHybridEngine::encapsulate(grantee_pub)?;
    let mut key = share_key(ss.expose())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let sealed = cipher
        .encrypt(&nonce, item_json)
        .map_err(|_| VaultError::Crypto("share seal failed".into()))?;
    key.zeroize();
    let mut nonce_arr = [0u8; 24];
    nonce_arr.copy_from_slice(nonce.as_slice());
    Ok(ShareEnvelope {
        grant_id: grant.grant_id.clone(),
        kem_ct: ct,
        nonce: nonce_arr,
        sealed,
    })
}

/// Grantee side: open with the decapsulation key. Wrong key / tampered
/// envelope fails closed. Returns the raw item JSON for the grantee to
/// parse (never auto-imported — paste it or save it by hand).
pub fn open_item_envelope(env: &ShareEnvelope, decapsulation_key: &[u8]) -> Result<Vec<u8>> {
    let ss = PqHybridEngine::decapsulate(decapsulation_key, &env.kem_ct)?;
    let mut key = share_key(ss.expose())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = chacha20poly1305::XNonce::from_slice(&env.nonce);
    let plain = cipher
        .decrypt(nonce, env.sealed.as_slice())
        .map_err(|_| VaultError::Crypto("share open failed".into()))?;
    key.zeroize();
    if plain.is_empty() || plain.len() > MAX_ENVELOPE_BYTES {
        return Err(VaultError::Security("share payload corrupt".into()));
    }
    Ok(plain)
}

impl ShareEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let w = WireShareEnvelope {
            v: SHARE_VERSION,
            grant_id: self.grant_id.clone(),
            kem_ct_b64: b64e(&self.kem_ct),
            nonce_b64: b64e(&self.nonce),
            sealed_b64: b64e(&self.sealed),
        };
        serde_json::to_vec(&w).map_err(|_| VaultError::Security("envelope encode failed".into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(VaultError::Security("envelope object too large".into()));
        }
        let w: WireShareEnvelope = serde_json::from_slice(bytes)
            .map_err(|_| VaultError::Security("envelope object corrupt".into()))?;
        if w.v != SHARE_VERSION {
            return Err(VaultError::Security("unsupported envelope version".into()));
        }
        if w.grant_id.len() != 64 || !w.grant_id.chars().all(|c| c.is_ascii_hexdigit()) {
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
            grant_id: w.grant_id.to_lowercase(),
            kem_ct,
            nonce,
            sealed,
        })
    }
}

/// One-line grant ledger for status text (metadata only — no secrets).
pub fn ledger(grants: &[SharedGrant]) -> String {
    if grants.is_empty() {
        return "No sharing grants.".to_string();
    }
    let mut s = format!("{} grant(s):", grants.len());
    for g in grants {
        s.push_str(&format!(
            "\n• {} [{}:{}] {} {}",
            g.grant_id,
            g.item_kind,
            g.item_id,
            if g.revoked { "REVOKED" } else { "active" },
            &g.grantee_fp[..12]
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::pq_hybrid::PqHybridEngine;
    use crate::models::Vault;

    #[test]
    fn grant_lifecycle_basics() {
        let kp = PqHybridEngine::generate_keypair();
        let fp = grantee_fingerprint(&kp.encapsulation).unwrap();
        assert_eq!(fp.len(), 64);
        let g = create_grant("login", "item-1", &kp.encapsulation, 1_000).unwrap();
        assert_eq!(g.grantee_fp, fp);
        assert!(!g.revoked);
        // Non-login kinds and empty ids refuse loud.
        assert!(create_grant("card", "item-1", &kp.encapsulation, 1_000).is_err());
        assert!(create_grant("login", "  ", &kp.encapsulation, 1_000).is_err());
        assert!(create_grant("login", "item-1", &kp.encapsulation[..100], 1_000).is_err());
        // Same inputs + same time = same id (deterministic binding).
        let g2 = create_grant("login", "item-1", &kp.encapsulation, 1_000).unwrap();
        assert_eq!(g.grant_id, g2.grant_id);
    }

    #[test]
    fn envelope_roundtrip_and_fail_closed() {
        let kp = PqHybridEngine::generate_keypair();
        let kp2 = PqHybridEngine::generate_keypair();
        let g = create_grant("login", "item-1", &kp.encapsulation, 1_000).unwrap();
        let payload = login_share_payload("Example", "neo", "s3cret!", &["https://example.com".into()]).unwrap();
        let env = seal_item_envelope(&g, &kp.encapsulation, &payload).unwrap();
        let bytes = env.encode().unwrap();
        let back = ShareEnvelope::decode(&bytes).unwrap();
        let opened = open_item_envelope(&back, kp.decapsulation.expose()).unwrap();
        assert_eq!(opened, payload);
        // Wrong recipient fails closed.
        assert!(open_item_envelope(&back, kp2.decapsulation.expose()).is_err());
        // Swapped grantee key fails at seal (fingerprint binding).
        assert!(seal_item_envelope(&g, &kp2.encapsulation, &payload).is_err());
        // Revoked grant never seals.
        let mut revoked = g.clone();
        revoked.revoked = true;
        assert!(seal_item_envelope(&revoked, &kp.encapsulation, &payload).is_err());
        // Empty password never becomes a payload.
        assert!(login_share_payload("t", "u", "", &[]).is_err());
        // Corrupt / oversized decodes fail.
        assert!(ShareEnvelope::decode(b"nope").is_err());
        assert!(ShareEnvelope::decode(&vec![0u8; MAX_ENVELOPE_BYTES + 1]).is_err());
    }

    #[test]
    fn grants_persist_with_vault_json() {
        let kp = PqHybridEngine::generate_keypair();
        let mut v = Vault::new();
        v.shared_grants.push(create_grant("login", "item-9", &kp.encapsulation, 5_000).unwrap());
        let json = serde_json::to_vec(&v).unwrap();
        let back: Vault = serde_json::from_value(serde_json::from_slice::<serde_json::Value>(&json).unwrap()).unwrap();
        assert_eq!(back.shared_grants.len(), 1);
        assert_eq!(back.shared_grants[0].item_id, "item-9");
        // Pre-sharing JSON (field absent) still loads with empty grants.
        let mut old = serde_json::to_value(&v).unwrap();
        old.as_object_mut().unwrap().remove("shared_grants");
        let back2: Vault = serde_json::from_value(old).unwrap();
        assert!(back2.shared_grants.is_empty());
    }
}
