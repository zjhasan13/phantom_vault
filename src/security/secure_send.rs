//! Phase 9 — Secure send: expiring, single-view sealed notes.
//!
//! Sender: note → fresh random 32B key + XChaCha seal → relay object
//! `send/<id>.json` (ciphertext + expiry metadata only). The LINK-CODE is
//! just the base64 key (the id is sha256 of the key — no separate id to
//! lose). Reader: fetch → expiry check → decrypt → DELETE the relay object
//! (one-time view; two readers racing can both fetch before either delete
//! lands — documented race, second read fails loud because the object is
//! gone). Copy-paste transport shares the same encode/decode (offline).
//! No server ever sees plaintext; the relay sees ciphertext + expiry only.

use crate::error::{Result, VaultError};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const SEND_VERSION: u32 = 1;
/// Notes are short secrets, not files — anything bigger is hostile.
pub const MAX_NOTE_BYTES: usize = 16 * 1024;
/// TTL floor 5min (shorter is a chat message, not a send) .. cap 30d.
pub const MIN_TTL_SECS: u64 = 300;
pub const MAX_TTL_SECS: u64 = 30 * 86_400;
/// Relay objects for sends (strict stems only — see `send_path`).
const SEND_PREFIX: &str = "send/";
/// Canonical HKDF info — both sides must agree bit-for-bit.
const SEND_INFO: &[u8] = b"phantom_vault_secure_send_v1";

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
        .map_err(|_| VaultError::Security("send field is not base64".into()))
}

/// Packet id = sha256 hex of the key. Binds packet ↔ key with zero extra
/// identifiers to manage or leak.
pub fn packet_id(key: &[u8; 32]) -> String {
    hex(&Sha256::digest(key))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WirePacket {
    v: u32,
    id: String,
    expires_at: u64,
    nonce_b64: String,
    sealed_b64: String,
}

#[derive(Debug, Clone)]
pub struct SendPacket {
    pub id: String,
    pub expires_at: u64,
    pub nonce: [u8; 24],
    pub sealed: Vec<u8>,
}

/// Sender side: seal `note` for `ttl_secs`. Returns (packet bytes,
/// link-code, id). The key lives ONLY in the link-code — lose it and the
/// note is unrecoverable (by design, even for us).
pub fn create_send(note: &str, ttl_secs: u64, now: u64) -> Result<(Vec<u8>, String, String)> {
    if note.trim().is_empty() {
        return Err(VaultError::Security("refusing to send an empty note".into()));
    }
    if note.len() > MAX_NOTE_BYTES {
        return Err(VaultError::Security("note too large (16KB cap)".into()));
    }
    if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl_secs) {
        return Err(VaultError::Security("TTL out of range (5min..30d)".into()));
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let id = packet_id(&key);
    // The link-code leaves this function exactly once (in the Ok tuple) —
    // after this point the key exists only inside the HKDF transcript.
    let code = b64e(&key);
    let hk = hkdf::Hkdf::<Sha256>::new(None, &key);
    let mut okm = [0u8; 32];
    hk.expand(SEND_INFO, &mut okm)
        .map_err(|_| VaultError::Crypto("send HKDF expansion failed".into()))?;
    key.zeroize();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&okm));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let sealed = cipher
        .encrypt(&nonce, note.as_bytes())
        .map_err(|_| VaultError::Crypto("send seal failed".into()))?;
    okm.zeroize();
    let mut nonce_arr = [0u8; 24];
    nonce_arr.copy_from_slice(nonce.as_slice());
    let pkt = SendPacket {
        id: id.clone(),
        expires_at: now.saturating_add(ttl_secs),
        nonce: nonce_arr,
        sealed,
    };
    let bytes = pkt.encode()?;
    Ok((bytes, code, id))
}

/// Reader side: open packet bytes with the link-code key at `now`.
/// Expiry is enforced BEFORE decrypt (expired notes never decrypt).
pub fn open_send(packet_bytes: &[u8], key_b64: &str, now: u64) -> Result<String> {
    let key_raw = b64d(key_b64)?;
    if key_raw.len() != 32 {
        return Err(VaultError::Security("bad link-code (not a 32B key)".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_raw);
    let pkt = SendPacket::decode(packet_bytes)?;
    if pkt.id != packet_id(&key) {
        key.zeroize();
        return Err(VaultError::Security("link-code does not match this packet".into()));
    }
    if now > pkt.expires_at {
        key.zeroize();
        return Err(VaultError::Security("note expired — destroyed unread".into()));
    }
    let hk = hkdf::Hkdf::<Sha256>::new(None, &key);
    let mut okm = [0u8; 32];
    hk.expand(SEND_INFO, &mut okm)
        .map_err(|_| VaultError::Crypto("send HKDF expansion failed".into()))?;
    key.zeroize();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&okm));
    let nonce = chacha20poly1305::XNonce::from_slice(&pkt.nonce);
    let plain = cipher
        .decrypt(nonce, pkt.sealed.as_slice())
        .map_err(|_| VaultError::Crypto("send open failed".into()))?;
    okm.zeroize();
    String::from_utf8(plain).map_err(|_| VaultError::Security("note is not text".into()))
}

impl SendPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let w = WirePacket {
            v: SEND_VERSION,
            id: self.id.clone(),
            expires_at: self.expires_at,
            nonce_b64: b64e(&self.nonce),
            sealed_b64: b64e(&self.sealed),
        };
        serde_json::to_vec(&w).map_err(|_| VaultError::Security("packet encode failed".into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_NOTE_BYTES + 2048 {
            return Err(VaultError::Security("packet too large".into()));
        }
        let w: WirePacket = serde_json::from_slice(bytes)
            .map_err(|_| VaultError::Security("packet corrupt".into()))?;
        if w.v != SEND_VERSION {
            return Err(VaultError::Security("unsupported packet version".into()));
        }
        if w.id.len() != 64 || !w.id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VaultError::Security("bad packet id".into()));
        }
        let nonce_raw = b64d(&w.nonce_b64)?;
        let sealed = b64d(&w.sealed_b64)?;
        if nonce_raw.len() != 24 || sealed.is_empty() {
            return Err(VaultError::Security("packet field length mismatch".into()));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_raw);
        Ok(Self {
            id: w.id.to_lowercase(),
            expires_at: w.expires_at,
            nonce,
            sealed,
        })
    }
}

/// Strict relay stem: `send/<64-hex>.json`. Anything else is refused.
pub fn send_path(id: &str) -> Result<String> {
    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VaultError::Security("bad packet id".into()));
    }
    Ok(format!("{SEND_PREFIX}{}.json", id.to_lowercase()))
}

// ---------------------------------------------------------------------------
// Relay transport: fetch + DELETE (one-time view). Delete failure after a
// successful read still returns the note but says so LOUD (sender must
// delete manually) — never a silent multi-view.
// ---------------------------------------------------------------------------

/// Fetch packet bytes for `id`. None = already read (deleted) or never sent.
pub async fn send_fetch(owner: &str, repo: &str, token: &str, id: &str) -> Result<Option<(Vec<u8>, String)>> {
    use base64::Engine as _;
    let octo = crate::sync::github_sync::client(token)?;
    let path = send_path(id)?;
    let items = match octo.repos(owner, repo).get_content().path(&path).send().await {
        Ok(items) => items,
        Err(e) => {
            if crate::sync::github_sync::is_not_found(&e) {
                return Ok(None);
            }
            return Err(VaultError::Sync(format!("send fetch failed: {e}")));
        }
    };
    let first = items
        .items
        .first()
        .ok_or_else(|| VaultError::Sync("send object missing".into()))?;
    let sha = first.sha.clone();
    let decoded = first
        .decoded_content()
        .ok_or_else(|| VaultError::Sync("send object unreadable".into()))?;
    if decoded.len() > MAX_NOTE_BYTES + 2048 {
        return Err(VaultError::Sync("send object suspiciously large".into()));
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(decoded.trim())
        .map_err(|e| VaultError::Sync(format!("send object corrupt: {e}")))?;
    Ok(Some((raw, sha)))
}

/// Delete a relay object by path+sha (one-time-view enforcement + sender
/// manual cleanup). Same fixed generic commit message as all sync traffic.
pub async fn send_delete(owner: &str, repo: &str, token: &str, id: &str, sha: &str) -> Result<()> {
    let octo = crate::sync::github_sync::client(token)?;
    let path = send_path(id)?;
    octo.repos(owner, repo)
        .delete_file(&path, crate::sync::github_sync::COMMIT_MESSAGE, sha)
        .branch("main")
        .send()
        .await
        .map_err(|e| VaultError::Sync(format!("send delete failed: {e}")))?;
    Ok(())
}

/// Publish one packet. Returns the relay path (ids are content-bound, so
/// create-vs-update races are harmless — same bytes win either way).
pub async fn send_publish(owner: &str, repo: &str, token: &str, packet: &[u8], id: &str) -> Result<()> {
    use base64::Engine as _;
    if packet.is_empty() || packet.len() > MAX_NOTE_BYTES + 2048 {
        return Err(VaultError::Sync("send payload invalid".into()));
    }
    let octo = crate::sync::github_sync::client(token)?;
    let path = send_path(id)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(packet);
    // Fetch-first: update when re-publishing the same id, create otherwise.
    let existing: Option<String> = match octo.repos(owner, repo).get_content().path(&path).send().await {
        Ok(items) => items.items.first().map(|f| f.sha.clone()),
        Err(e) => {
            if crate::sync::github_sync::is_not_found(&e) {
                None
            } else {
                return Err(VaultError::Sync(format!("send publish check failed: {e}")));
            }
        }
    };
    if let Some(head) = existing {
        octo.repos(owner, repo)
            .update_file(&path, crate::sync::github_sync::COMMIT_MESSAGE, b64, head)
            .branch("main")
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("send publish failed: {e}")))?;
    } else {
        octo.repos(owner, repo)
            .create_file(&path, crate::sync::github_sync::COMMIT_MESSAGE, b64)
            .branch("main")
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("send publish failed: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_note() -> (Vec<u8>, String, String) {
        // Test-only helper: seal via the real path but return the key.
        // (Production `create_send` returns the link-code directly.)
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let id = packet_id(&key);
        let hk = hkdf::Hkdf::<Sha256>::new(None, &key);
        let mut okm = [0u8; 32];
        hk.expand(SEND_INFO, &mut okm).unwrap();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&okm));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let sealed = cipher.encrypt(&nonce, b"the launch codes".as_slice()).unwrap();
        okm.zeroize();
        let mut nonce_arr = [0u8; 24];
        nonce_arr.copy_from_slice(nonce.as_slice());
        let pkt = SendPacket { id: id.clone(), expires_at: 9_999_999, nonce: nonce_arr, sealed };
        let code = b64e(&key);
        key.zeroize();
        (pkt.encode().unwrap(), code, id)
    }

    #[test]
    fn roundtrip_and_expiry_enforced_before_decrypt() {
        let (bytes, code, _id) = make_note();
        assert_eq!(open_send(&bytes, &code, 1_000).unwrap(), "the launch codes");
        // Expired → refused even with the right key (never decrypts).
        assert!(open_send(&bytes, &code, 10_000_000).is_err());
    }

    #[test]
    fn wrong_key_and_tampering_fail_closed() {
        let (bytes, code, _id) = make_note();
        let mut other = [0u8; 32];
        OsRng.fill_bytes(&mut other);
        let wrong = b64e(&other);
        // Wrong key → id binding fails, never plaintext.
        assert!(open_send(&bytes, &wrong, 1_000).is_err());
        // Tampered ciphertext → AEAD fails, never plaintext.
        let mut pkt = SendPacket::decode(&bytes).unwrap();
        let last = pkt.sealed.len() - 1;
        pkt.sealed[last] ^= 0x01;
        let evil = pkt.encode().unwrap();
        assert!(open_send(&evil, &code, 1_000).is_err());
        // Untouched packet still opens (tamper was contained to the copy).
        assert_eq!(open_send(&bytes, &code, 1_000).unwrap(), "the launch codes");
    }

    #[test]
    fn create_validates_inputs() {
        assert!(create_send("", 3_600, 1_000).is_err());
        assert!(create_send("  ", 3_600, 1_000).is_err());
        assert!(create_send("hi", 60, 1_000).is_err());
        assert!(create_send("hi", MAX_TTL_SECS + 1, 1_000).is_err());
        assert!(create_send(&"x".repeat(MAX_NOTE_BYTES + 1), 3_600, 1_000).is_err());
        let (bytes, code, id) = create_send("hello", 3_600, 1_000).unwrap();
        assert_eq!(id.len(), 64);
        // Link-code opens its own packet before expiry.
        assert_eq!(open_send(&bytes, &code, 2_000).unwrap(), "hello");
        assert!(open_send(&bytes, &code, 1_000 + 3_601).is_err());
    }

    #[test]
    fn corrupt_packets_and_paths_refused() {
        assert!(SendPacket::decode(b"nope").is_err());
        assert!(SendPacket::decode(&vec![0u8; MAX_NOTE_BYTES + 2049]).is_err());
        assert!(send_path("short").is_err());
        assert!(send_path(&format!("{}!", "a".repeat(63))).is_err());
        assert!(send_path(&"b".repeat(64)).is_ok());
        assert!(open_send(b"nope", &b64e(&[0u8; 32]), 1_000).is_err());
    }
}
