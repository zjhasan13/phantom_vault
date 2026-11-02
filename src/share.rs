//! A20 slice 1: transport-agnostic encrypted share bundles.
//!
//! A share is a random 256-bit key + an XChaCha20-Poly1305 blob. The key is
//! meant to travel in a URL **fragment** (`pvshare://<id>#k=<base64url>`), which
//! browsers/proxies never send to a server; the blob can travel over P2P, a
//! GitHub release, or a file.
//!
//! A20a adds an optional recipient passphrase: `PVSH2` wraps the same random
//! key with `Argon2id(passphrase)` and the link carries only `#p=1`, so the
//! link alone is not enough to open the bundle. `PVSH1` remains readable.
//!
//! Honest limits (see `docs/A20_SEND.md`): expiry is enforced by the opener's
//! clock; "one view" is enforced by the *transport* (P2P relay), never by the
//! recipient; a recipient can always copy what they can read, and a weak
//! passphrase can be guessed offline.

#![allow(dead_code)] // slice 1: wired into UI/transport in slice 2

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const BUNDLE_MAGIC: &[u8; 5] = b"PVSH1";
/// A20a: passphrase-protected bundles.
pub const BUNDLE_MAGIC_V2: &[u8; 5] = b"PVSH2";
const FLAG_PASSPHRASE: u8 = 1;
const SALT_LEN: usize = 16;
const WRAP_NONCE_LEN: usize = 24;
const WRAPPED_KEY_LEN: usize = 32 + 16;
const V2_MIN: usize = 5 + 1 + SALT_LEN + WRAP_NONCE_LEN + WRAPPED_KEY_LEN + 24 + 16;
pub const LINK_SCHEME: &str = "pvshare://";
/// Reserved link host for the A20b async gist transport.
pub const GIST_HOST: &str = "gist";
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

impl ShareItem {
    /// Map a vault login to the share shape (linked custom fields are skipped).
    pub fn from_credential(c: &crate::models::Credential) -> Self {
        Self {
            kind: "login".to_string(),
            title: c.title.clone(),
            username: c.username.clone(),
            password: c.password.clone(),
            url: c.urls.first().map(|u| u.url().to_string()).unwrap_or_default(),
            notes: c.notes.clone(),
            totp: c.totp_secret.clone(),
            custom_fields: c
                .custom_fields
                .iter()
                .filter(|f| !matches!(f.field_type, crate::models::CustomFieldType::Linked))
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect(),
        }
    }
}

/// Import shared logins into a vault, skipping title+username duplicates.
/// Returns the number added. Non-login kinds are ignored.
pub fn add_items_to_vault(vault: &mut crate::models::Vault, items: &[ShareItem]) -> usize {
    let mut added = 0;
    for item in items {
        if item.kind != "login" {
            continue;
        }
        let exists = vault.credentials.iter().any(|c| {
            c.deleted_at.is_none()
                && c.title.eq_ignore_ascii_case(&item.title)
                && c.username.eq_ignore_ascii_case(&item.username)
        });
        if exists {
            continue;
        }
        vault.credentials.push(crate::models::Credential {
            id: format!("share-{}-{}", crate::models::current_timestamp(), added),
            title: item.title.clone(),
            username: item.username.clone(),
            password: item.password.clone(),
            totp_secret: item.totp.clone(),
            urls: if item.url.is_empty() {
                Vec::new()
            } else {
                vec![crate::models::LoginUrl::Plain(item.url.clone())]
            },
            apps: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: item
                .custom_fields
                .iter()
                .map(|(k, v)| crate::models::CustomField {
                    name: k.clone(),
                    value: v.clone(),
                    field_type: crate::models::CustomFieldType::Text,
                })
                .collect(),
            notes: item.notes.clone(),
            folder: String::new(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: crate::models::current_timestamp(),
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        });
        added += 1;
    }
    added
}

pub struct CreatedShare {
    /// `PVSH1 | nonce | ct` or `PVSH2 | …` — safe to store/upload.
    pub bundle: Vec<u8>,
    pub id: String,
    /// The only secret in the share; empty when a recipient passphrase wraps it.
    pub key: SecretString,
    pub expires_at: u64,
    pub max_views: u32,
    /// A20a: the recipient must enter a passphrase; the link has no key.
    pub passphrase: bool,
}

impl CreatedShare {
    /// Key travels in the fragment; the blob never contains it. With a
    /// passphrase the fragment only says `p=1` — the key is wrapped in the blob.
    fn fragment(&self) -> String {
        if self.passphrase {
            "#p=1".to_string()
        } else {
            format!("#k={}", self.key.expose_secret())
        }
    }

    pub fn link(&self) -> String {
        format!("{LINK_SCHEME}{}{}", self.id, self.fragment())
    }

    /// Link that names the sender's reachable address (`pvshare://host:port/id#…`).
    pub fn link_via(&self, host_port: &str) -> String {
        format!(
            "{LINK_SCHEME}{host_port}/{}{}",
            self.id,
            self.fragment()
        )
    }

    /// A20b: async link (`pvshare://gist/<owner>/<gist_id>#…`). The owner is
    /// needed for the tokenless raw fetch; the gist id replaces the local id.
    pub fn link_via_gist(&self, owner: &str, gist_id: &str) -> String {
        format!(
            "{LINK_SCHEME}{GIST_HOST}/{owner}/{gist_id}{}",
            self.fragment()
        )
    }
}

impl ShareLink {
    /// True for `pvshare://gist/...` (A20b relay links).
    pub fn is_gist(&self) -> bool {
        self.host.as_deref() == Some(GIST_HOST)
    }
}

/// GitHub gist ids are hex; accept the observed 32-char form plus slack.
pub fn is_gist_id(id: &str) -> bool {
    (20..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// GitHub logins: 1–39 chars, alphanumeric or `-`, no leading/trailing `-`.
pub fn is_gist_owner(owner: &str) -> bool {
    let b = owner.as_bytes();
    (1..=39).contains(&b.len())
        && !owner.starts_with('-')
        && !owner.ends_with('-')
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// Parsed share link. `host` is `None` for a file-transport link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareLink {
    pub host: Option<String>,
    /// GitHub login for `pvshare://gist/<owner>/<id>` links.
    pub gist_owner: Option<String>,
    pub id: String,
    /// `None` when the bundle is passphrase-protected (`#p=1`).
    pub key: Option<String>,
    pub needs_passphrase: bool,
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

/// Create a share without a recipient passphrase (PVSH1).
pub fn create(
    items: Vec<ShareItem>,
    ttl_secs: u64,
    max_views: u32,
) -> Result<CreatedShare, String> {
    create_with_passphrase(items, ttl_secs, max_views, None)
}

/// A20a: create a share, optionally wrapping its key with Argon2id(passphrase).
/// With a passphrase the link is `pvshare://<id>#p=1` and the key stays wrapped
/// inside the bundle; without one the behaviour is the original PVSH1.
pub fn create_with_passphrase(
    items: Vec<ShareItem>,
    ttl_secs: u64,
    max_views: u32,
    passphrase: Option<&SecretString>,
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
    let mut id_raw = [0u8; 16];
    OsRng.fill_bytes(&mut id_raw);

    let sealed = crate::crypto::seal_with_raw_key(&key, &padded);
    padded.zeroize();
    let sealed = match sealed {
        Ok(s) => s,
        Err(e) => {
            key.zeroize();
            return Err(e);
        }
    };

    let (bundle, key_out, protected) = match passphrase {
        None => {
            let mut bundle = Vec::with_capacity(BUNDLE_MAGIC.len() + sealed.len());
            bundle.extend_from_slice(BUNDLE_MAGIC);
            bundle.extend_from_slice(&sealed);
            let key_b64 = URL_SAFE_NO_PAD.encode(key);
            (bundle, SecretString::new(key_b64), false)
        }
        Some(pass) if pass.expose_secret().trim().is_empty() => {
            key.zeroize();
            return Err("share passphrase cannot be empty".to_string());
        }
        Some(pass) => {
            let mut salt = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut salt);
            // Normalise like every entry point does (CLI/UI trim), so a
            // passphrase entered with stray spaces still opens.
            let normalized = SecretString::new(pass.expose_secret().trim().to_string());
            let mut kek = match crate::crypto::derive_key_secret(&normalized, &salt) {
                Ok(k) => k,
                Err(e) => {
                    key.zeroize();
                    return Err(e);
                }
            };
            let wrapped = crate::crypto::seal_with_raw_key(&kek, &key);
            kek.zeroize();
            let wrapped = match wrapped {
                Ok(w) => w,
                Err(e) => {
                    key.zeroize();
                    return Err(e);
                }
            };
            if wrapped.len() != WRAP_NONCE_LEN + WRAPPED_KEY_LEN {
                key.zeroize();
                return Err("wrapped share key has an unexpected length".to_string());
            }
            let mut bundle =
                Vec::with_capacity(BUNDLE_MAGIC_V2.len() + 1 + SALT_LEN + wrapped.len() + sealed.len());
            bundle.extend_from_slice(BUNDLE_MAGIC_V2);
            bundle.push(FLAG_PASSPHRASE);
            bundle.extend_from_slice(&salt);
            bundle.extend_from_slice(&wrapped);
            bundle.extend_from_slice(&sealed);
            (bundle, SecretString::new(String::new()), true)
        }
    };
    key.zeroize();
    Ok(CreatedShare {
        bundle,
        id: hex(&id_raw),
        key: key_out,
        expires_at,
        max_views,
        passphrase: protected,
    })
}

fn decode_key(key_b64: Option<&str>) -> Result<[u8; 32], String> {
    let text = key_b64.ok_or_else(|| "this share needs its link key".to_string())?;
    let mut decoded = URL_SAFE_NO_PAD
        .decode(text.trim())
        .map_err(|_| "share key is not valid base64url".to_string())?;
    if decoded.len() != 32 {
        decoded.zeroize();
        return Err("share key has the wrong length".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(key)
}

fn open_payload(key: &[u8; 32], payload: &[u8], err: &str) -> Result<SharePayload, String> {
    let opened = crate::crypto::open_with_raw_key(key, payload).map_err(|_| err.to_string())?;
    let mut plain = opened;
    let parsed: Result<SharePayload, String> =
        serde_json::from_slice(&plain).map_err(|_| "share payload is corrupt".to_string());
    plain.zeroize();
    let payload = parsed?;
    if payload.version != 1 {
        return Err("unsupported share version".to_string());
    }
    if payload.expires_at <= now_secs() {
        return Err("share has expired".to_string());
    }
    Ok(payload)
}

/// Open a bundle. `key` is the fragment key (PVSH1 / no-passphrase); with
/// `PVSH2` a passphrase is required and the key is unwrapped from the bundle.
/// Expiry is checked against the local clock; max_views is returned for the
/// transport to enforce.
pub fn open(
    bundle: &[u8],
    key: Option<&str>,
    passphrase: Option<&str>,
) -> Result<SharePayload, String> {
    if bundle.len() >= BUNDLE_MAGIC_V2.len() && &bundle[..5] == BUNDLE_MAGIC_V2 {
        if bundle.len() < V2_MIN {
            return Err("share bundle is truncated".to_string());
        }
        let flags = bundle[5];
        if flags != FLAG_PASSPHRASE {
            return Err("unsupported share flags".to_string());
        }
        let salt = &bundle[6..6 + SALT_LEN];
        let wrap_nonce = &bundle[6 + SALT_LEN..6 + SALT_LEN + WRAP_NONCE_LEN];
        let wrapped_off = 6 + SALT_LEN + WRAP_NONCE_LEN;
        let wrapped = &bundle[wrapped_off..wrapped_off + WRAPPED_KEY_LEN];
        let payload_off = wrapped_off + WRAPPED_KEY_LEN;
        let pass = passphrase
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| "this share requires a recipient passphrase".to_string())?;
        let secret = SecretString::new(pass.to_string());
        let mut kek = crate::crypto::derive_key_secret(&secret, salt)?;
        let mut wrap_input = Vec::with_capacity(WRAP_NONCE_LEN + WRAPPED_KEY_LEN);
        wrap_input.extend_from_slice(wrap_nonce);
        wrap_input.extend_from_slice(wrapped);
        let unwrapped = crate::crypto::open_with_raw_key(&kek, &wrap_input);
        kek.zeroize();
        let mut key = unwrapped
            .map_err(|_| "wrong passphrase or corrupt bundle".to_string())?;
        if key.len() != 32 {
            key.zeroize();
            return Err("wrapped share key has an unexpected length".to_string());
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key);
        key.zeroize();
        let out = open_payload(
            &key_arr,
            &bundle[payload_off..],
            "wrong passphrase or corrupt bundle",
        );
        key_arr.zeroize();
        return out;
    }
    if bundle.len() < BUNDLE_MAGIC.len() + 24 + 16 || &bundle[..5] != BUNDLE_MAGIC {
        return Err("not a PhantomVault share bundle".to_string());
    }
    let mut key = decode_key(key)?;
    let out = open_payload(&key, &bundle[BUNDLE_MAGIC.len()..], "wrong key or corrupt bundle");
    key.zeroize();
    out
}

/// Parse `pvshare://<id>#k=<key>` / `#p=1` (file transport),
/// `pvshare://<host>:<port>/<id>#…` (LAN transport) or
/// `pvshare://gist/<owner>/<gist_id>#…` (A20b relay; `gist` is a reserved
/// host). The key must never be sent to a server.
pub fn parse_link(link: &str) -> Option<ShareLink> {
    let rest = link.strip_prefix(LINK_SCHEME)?;
    let (rest, fragment) = rest.split_once('#')?;
    let (kind, value) = fragment.split_once('=')?;
    let (key, needs_passphrase) = match kind {
        "k" if !value.is_empty() => (Some(value.to_string()), false),
        "p" if value == "1" => (None, true),
        _ => return None,
    };
    // A20b: gist links carry the owner (needed for a tokenless raw fetch).
    if let Some(path) = rest
        .strip_prefix(GIST_HOST)
        .and_then(|p| p.strip_prefix('/'))
    {
        if let Some((owner, id)) = path.split_once('/') {
            if !is_gist_owner(owner) || !is_gist_id(id) {
                return None;
            }
            return Some(ShareLink {
                host: Some(GIST_HOST.to_string()),
                gist_owner: Some(owner.to_string()),
                id: id.to_string(),
                key,
                needs_passphrase,
            });
        }
        // `pvshare://gist/<id>` (legacy, no owner) falls through below.
    }
    let (host, id) = match rest.split_once('/') {
        Some((host, id)) if !host.is_empty() && !id.trim_matches('/').is_empty() => (
            Some(host.to_string()),
            id.trim_matches('/').to_string(),
        ),
        Some(_) => return None,
        None => (None, rest.to_string()),
    };
    if id.is_empty() || id.contains('/') {
        return None;
    }
    // A legacy `pvshare://gist/<gist_id>` (no owner) still parses and can be
    // fetched through the API path.
    if host.as_deref() == Some(GIST_HOST) && !is_gist_id(&id) {
        return None;
    }
    Some(ShareLink {
        host,
        gist_owner: None,
        id,
        key,
        needs_passphrase,
    })
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
        let parsed = parse_link(&link).unwrap();
        assert_eq!(parsed.id, created.id);
        assert!(parsed.host.is_none());
        assert_eq!(
            parsed.key.as_deref(),
            Some(created.key.expose_secret().as_str())
        );
        assert!(!parsed.needs_passphrase);
        let key = parsed.key.unwrap();
        // The key never lives inside the blob.
        assert!(!created
            .bundle
            .windows(key.len())
            .any(|w| w == key.as_bytes()));
        let opened = open(&created.bundle, Some(&key), None).unwrap();
        assert_eq!(opened.items.len(), 1);
        assert_eq!(opened.items[0].title, "Gmail");
        assert_eq!(opened.items[0].password, "s3cret!");
        assert_eq!(opened.max_views, 1);
    }

    #[test]
    fn passphrase_share_roundtrips_and_requires_the_passphrase() {
        // Entry points trim; wrap the passphrase in spaces to prove create/open
        // normalise the same way.
        let pass = SecretString::new("  correct horse battery  ".to_string());
        let created =
            create_with_passphrase(vec![item("Gmail", "s3cret!")], 3600, 1, Some(&pass)).unwrap();
        assert!(created.passphrase);
        assert!(created.key.expose_secret().is_empty(), "key stays in the blob");
        let link = created.link();
        assert!(link.ends_with("#p=1"), "unexpected link: {link}");
        assert!(link.len() < 200, "link must fit a QR code: {link}");
        let lan = created.link_via("192.168.1.5:52123");
        assert_eq!(lan, format!("pvshare://192.168.1.5:52123/{}#p=1", created.id));
        assert!(!lan.contains("#k="));
        let relay = created.link_via_gist("zjhasan13", "0123456789abcdef0123456789abcdef");
        assert_eq!(
            relay,
            "pvshare://gist/zjhasan13/0123456789abcdef0123456789abcdef#p=1"
        );
        let parsed_relay = parse_link(&relay).unwrap();
        assert!(parsed_relay.is_gist());
        assert_eq!(parsed_relay.gist_owner.as_deref(), Some("zjhasan13"));
        let parsed = parse_link(&link).unwrap();
        assert!(parsed.needs_passphrase);
        assert!(parsed.key.is_none());

        // Correct passphrase opens; missing/wrong fail closed.
        let opened = open(&created.bundle, None, Some("correct horse battery")).unwrap();
        assert_eq!(opened.items[0].password, "s3cret!");
        assert!(open(&created.bundle, None, None)
            .unwrap_err()
            .contains("requires a recipient passphrase"));
        assert!(open(&created.bundle, None, Some("wrong passphrase"))
            .unwrap_err()
            .contains("wrong passphrase"));
        // A fragment key must not bypass the passphrase.
        let fake_key = URL_SAFE_NO_PAD.encode([9u8; 32]);
        assert!(open(&created.bundle, Some(&fake_key), None).is_err());
        // The raw key is not in the bundle.
        assert!(!created
            .bundle
            .windows(8)
            .any(|w| w == b"correct "));
    }

    #[test]
    fn wrong_key_tamper_and_expiry_fail_closed() {
        let created = create(vec![item("Gmail", "pw")], 3600, 0).unwrap();
        let bad_key = "A".repeat(43);
        assert!(open(&created.bundle, Some(&bad_key), None).is_err());
        let mut bad = created.bundle.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open(&bad, Some(created.key.expose_secret()), None).is_err());
        assert!(open(&created.bundle[..10], Some(created.key.expose_secret()), None).is_err());

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
        assert!(open(&bundle, Some(&k), None).unwrap_err().contains("expired"));
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
    fn link_parser_handles_file_and_lan_forms() {
        assert!(parse_link("pvshare://abc").is_none());
        assert!(parse_link("https://x#k=y").is_none());
        assert!(parse_link("pvshare://#k=abc").is_none());
        assert_eq!(
            parse_link("pvshare://id1#k=key1"),
            Some(ShareLink {
                host: None,
                gist_owner: None,
                id: "id1".to_string(),
                key: Some("key1".to_string()),
                needs_passphrase: false,
            })
        );
        assert_eq!(
            parse_link("pvshare://192.168.1.5:52199/id2#k=key2"),
            Some(ShareLink {
                host: Some("192.168.1.5:52199".to_string()),
                gist_owner: None,
                id: "id2".to_string(),
                key: Some("key2".to_string()),
                needs_passphrase: false,
            })
        );
        assert_eq!(
            parse_link("pvshare://id3#p=1"),
            Some(ShareLink {
                host: None,
                gist_owner: None,
                id: "id3".to_string(),
                key: None,
                needs_passphrase: true,
            })
        );
        let gist = parse_link("pvshare://gist/0123456789abcdef0123456789abcdef#k=key4")
            .unwrap();
        assert!(gist.is_gist());
        assert_eq!(gist.id, "0123456789abcdef0123456789abcdef");
        assert!(gist.gist_owner.is_none());
        let gist = parse_link(
            "pvshare://gist/zjhasan13/0123456789abcdef0123456789abcdef#k=key4",
        )
        .unwrap();
        assert_eq!(gist.gist_owner.as_deref(), Some("zjhasan13"));
        assert_eq!(gist.id, "0123456789abcdef0123456789abcdef");
        assert!(parse_link("pvshare://gist/zjhasan13/nothex#k=key4").is_none());
        assert!(parse_link("pvshare://host:1/#k=k").is_none());
    }

    #[test]
    fn add_items_to_vault_dedupes_and_skips_non_logins() {
        let mut vault = crate::models::Vault::new();
        let mut login = item("Gmail", "pw");
        login.kind = "login".to_string();
        let mut note = item("Note", "");
        note.kind = "note".to_string();
        assert_eq!(add_items_to_vault(&mut vault, &[login.clone(), note]), 1);
        assert_eq!(add_items_to_vault(&mut vault, &[login]), 0, "duplicate");
        assert_eq!(vault.credentials.len(), 1);
    }
}
