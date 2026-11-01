//! A20 slice 1: transport-agnostic encrypted share bundles.
//!
//! A share is a random 256-bit key + an XChaCha20-Poly1305 blob. The key is
//! meant to travel in a URL **fragment** (`pvshare://<id>#k=<base64url>`), which
//! browsers/proxies never send to a server; the blob can travel over P2P, a
//! GitHub release, or a file. This module only owns the crypto/format — the
//! UI and transport are slice 2. Nothing calls it from production yet.
//!
//! Honest limits (see `docs/A20_SEND.md`): expiry is enforced by the opener's
//! clock; "one view" is enforced by the *transport* (P2P relay), never by the
//! recipient; a recipient can always copy what they can read.

#![allow(dead_code)] // slice 1: wired into UI/transport in slice 2

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const BUNDLE_MAGIC: &[u8; 5] = b"PVSH1";
pub const LINK_SCHEME: &str = "pvshare://";
/// Pad the plaintext to a 4 KiB bucket so container size does not reveal how
/// many/large the shared fields are.
const PAD_BUCKET: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareItem {
    pub kind: String,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    /// Raw base32 TOTP secret (empty = none).
    #[serde(default)]
    pub totp: String,
    #[serde(default)]
    pub custom_fields: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharePayload {
    pub version: u32,
    pub created: u64,
    pub expires_at: u64,
    /// `0` = unlimited; `1` = one view (enforced by the transport).
    pub max_views: u32,
    pub items: Vec<ShareItem>,
}

pub struct CreatedShare {
    /// `PVSH1 | nonce | ciphertext+tag` — safe to store/upload.
    pub bundle: Vec<u8>,
    pub id: String,
    /// The only secret in the share; keep it out of logs and out of the blob.
    pub key: SecretString,
    pub expires_at: u64,
}

impl CreatedShare {
    /// Key travels in the fragment; the blob never contains it.
    pub fn link(&self) -> String {
        format!("{LINK_SCHEME}{}#k={}", self.id, self.key.expose_secret())
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pad(mut bytes: Vec<u8>) -> Vec<u8> {
    let target = bytes.len().div_ceil(PAD_BUCKET).max(1) * PAD_BUCKET;
    bytes.resize(target, b' ');
    bytes
}

/// Create a share for `items`. `ttl_secs` must be > 0; `max_views` 0 means
/// unlimited. The returned key is the only way to open the bundle.
pub fn create(
    items: Vec<ShareItem>,
    ttl_secs: u64,
    max_views: u32,
) -> Result<CreatedShare, String> {
    if ttl_secs == 0 {
        return Err("share expiry must be at least 1 second".to_string());
    }
    if items.is_empty() {
        return Err("nothing to share".to_string());
    }
    let created = now_secs();
    let expires_at = created.saturating_add(ttl_secs);
    let payload = SharePayload {
        version: 1,
        created,
        expires_at,
        max_views,
        items,
    };
    let json = serde_json::to_vec(&payload).map_err(|e| format!("share encode: {e}"))?;
    let mut padded = pad(json);
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut id_raw = [0u8; 8];
    OsRng.fill_bytes(&mut id_raw);

    let sealed = crate::crypto::seal_with_raw_key(&key, &padded);
    padded.zeroize();
    let sealed = sealed?;

    let mut bundle = Vec::with_capacity(BUNDLE_MAGIC.len() + sealed.len());
    bundle.extend_from_slice(BUNDLE_MAGIC);
    bundle.extend_from_slice(&sealed);
    let key_b64 = URL_SAFE_NO_PAD.encode(key);
    key.zeroize();
    Ok(CreatedShare {
        bundle,
        id: hex(&id_raw),
        key: SecretString::new(key_b64),
        expires_at,
    })
}

/// Open a bundle with the fragment key. Expiry is checked against the local
/// clock; max_views is returned for the transport to enforce.
pub fn open(bundle: &[u8], key_b64: &str) -> Result<SharePayload, String> {
    if bundle.len() < BUNDLE_MAGIC.len() + 24 + 16 {
        return Err("share bundle is truncated".to_string());
    }
    if &bundle[..BUNDLE_MAGIC.len()] != BUNDLE_MAGIC {
        return Err("not a PhantomVault share bundle".to_string());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(key_b64.trim())
        .map_err(|_| "share key is not valid base64url".to_string())?;
    if decoded.len() != 32 {
        return Err("share key has the wrong length".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    let _decoded_guard = Zeroizing::new(decoded);
    let opened = crate::crypto::open_with_raw_key(&key, &bundle[BUNDLE_MAGIC.len()..]);
    key.zeroize();
    let mut plain = opened.map_err(|_| "share cannot be opened: wrong key or corrupt bundle".to_string())?;
    let payload: Result<SharePayload, String> =
        serde_json::from_slice(&plain).map_err(|_| "share payload is corrupt".to_string());
    plain.zeroize();
    let payload = payload?;
    if payload.version != 1 {
        return Err("unsupported share version".to_string());
    }
    if payload.expires_at <= now_secs() {
        return Err("share has expired".to_string());
    }
    Ok(payload)
}

/// Parse `pvshare://<id>#k=<key>`. The key must never be sent to a server.
pub fn parse_link(link: &str) -> Option<(String, String)> {
    let rest = link.strip_prefix(LINK_SCHEME)?;
    let (id, key) = rest.split_once("#k=")?;
    if id.is_empty() || key.is_empty() {
        return None;
    }
    Some((id.to_string(), key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(title: &str, password: &str) -> ShareItem {
        ShareItem {
            kind: "login".into(),
            title: title.into(),
            username: "u@example.com".into(),
            password: password.into(),
            url: "https://example.com".into(),
            notes: "note".into(),
            totp: "JBSWY3DPEHPK3PXP".into(),
            custom_fields: vec![("PIN".into(), "9999".into())],
        }
    }

    #[test]
    fn share_roundtrips_and_the_key_is_separate() {
        let created = create(vec![item("Gmail", "s3cret!")], 3600, 1).unwrap();
        let link = created.link();
        let (id, key) = parse_link(&link).unwrap();
        assert_eq!(id, created.id);
        assert_eq!(key.as_str(), created.key.expose_secret().as_str());
        // The key never lives inside the blob.
        assert!(!created
            .bundle
            .windows(key.len())
            .any(|w| w == key.as_bytes()));
        let opened = open(&created.bundle, &key).unwrap();
        assert_eq!(opened.items.len(), 1);
        assert_eq!(opened.items[0].title, "Gmail");
        assert_eq!(opened.items[0].password, "s3cret!");
        assert_eq!(opened.max_views, 1);
    }

    #[test]
    fn wrong_key_tamper_and_expiry_fail_closed() {
        let created = create(vec![item("Gmail", "pw")], 3600, 0).unwrap();
        assert!(open(&created.bundle, &"A".repeat(43)).is_err());
        let mut bad = created.bundle.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open(&bad, created.key.expose_secret()).is_err());
        assert!(open(&created.bundle[..10], created.key.expose_secret()).is_err());

        // TTL 0 is refused; an already-expired payload is refused on open.
        assert!(create(vec![item("x", "y")], 0, 1).is_err());
        let payload = SharePayload {
            version: 1,
            created: now_secs() - 10,
            expires_at: now_secs() - 1,
            max_views: 1,
            items: vec![item("old", "pw")],
        };
        let json = serde_json::to_vec(&payload).unwrap();
        let key = [7u8; 32];
        let sealed = crate::crypto::seal_with_raw_key(&key, &json).unwrap();
        let mut bundle = Vec::from(*BUNDLE_MAGIC);
        bundle.extend_from_slice(&sealed);
        let k = URL_SAFE_NO_PAD.encode(key);
        assert!(open(&bundle, &k).unwrap_err().contains("expired"));
    }

    #[test]
    fn padding_hides_payload_size() {
        let small = create(vec![item("a", "1")], 60, 1).unwrap();
        let large = create(
            vec![item("a", &"x".repeat(3000))],
            60,
            1,
        )
        .unwrap();
        assert_eq!(small.bundle.len(), large.bundle.len());
        assert_eq!(small.bundle.len() % PAD_BUCKET, BUNDLE_MAGIC.len() + 24 + 16);
    }

    #[test]
    fn link_parser_rejects_missing_fragment() {
        assert!(parse_link("pvshare://abc").is_none());
        assert!(parse_link("https://x#k=y").is_none());
        assert!(parse_link("pvshare://#k=abc").is_none());
        assert_eq!(
            parse_link("pvshare://id1#k=key1"),
            Some(("id1".to_string(), "key1".to_string()))
        );
    }
}
