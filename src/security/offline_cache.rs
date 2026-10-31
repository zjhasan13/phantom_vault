//! A11: opt-in, read-only offline cache for the browser extension.
//!
//! The desktop app builds a **logins-only** snapshot at unlock and seals it
//! with a fresh 32-byte key. The key is DPAPI-sealed (current user) in
//! `vault_cache_key.dpapi`; the snapshot is XChaCha20-Poly1305 in
//! `vault_cache.enc`. The native host serves it only after a **Windows Hello**
//! prompt, so closed-app reads still require user presence.
//!
//! Deliberate boundaries:
//! - read-only: the host never accepts mutations against the cache;
//! - 15-minute extension session TTL (decrypted data stays in service-worker
//!   memory, never `storage`);
//! - `clear()` on decoy unlock, disable, nuke and (for freshness) after rekey;
//! - no master password is stored — only the cache key, and only DPAPI-wrapped.
//!
//! P1 (closed-app serving of the live vault) is unchanged: this file is a
//! separate, explicitly opt-in path.

use crate::models::Vault;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

pub const CACHE_FILE: &str = "vault_cache.enc";
pub const KEY_FILE: &str = "vault_cache_key.dpapi";
pub const CACHE_MAGIC: &[u8; 5] = b"PVOC1";
/// How long the extension may hold the decrypted snapshot in memory.
pub const SESSION_TTL_SECS: u64 = 15 * 60;
/// Bound the cache so a giant vault cannot turn into a giant DPAPI blob.
pub const MAX_ITEMS: usize = 1000;

type CacheResult<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CachedLogin {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub folder: String,
    pub reprompt: bool,
    pub last_changed: u64,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub created_at: u64,
    pub items: Vec<CachedLogin>,
}

/// Build the read-only snapshot: live logins only, no Trash, capped.
pub fn build_snapshot(vault: &Vault, now: u64) -> Snapshot {
    let items = vault
        .credentials
        .iter()
        .filter(|c| c.deleted_at.is_none())
        .take(MAX_ITEMS)
        .map(|c| CachedLogin {
            id: c.id.clone(),
            title: c.title.clone(),
            username: c.username.clone(),
            password: c.password.clone(),
            urls: c.urls.iter().map(|u| u.url().to_string()).collect(),
            folder: c.folder.clone(),
            reprompt: c.reprompt,
            last_changed: c.last_changed,
            verified: vault.is_verified(&c.id),
        })
        .collect();
    Snapshot {
        version: 1,
        created_at: now,
        items,
    }
}

/// Pure encode/decode, unit-tested without touching DPAPI or disk.
pub fn encode_snapshot(key: &[u8; 32], snapshot: &Snapshot) -> CacheResult<Vec<u8>> {
    let plain = serde_json::to_vec(snapshot).map_err(|e| format!("cache encode failed: {e}"))?;
    let sealed = crate::crypto::seal_with_raw_key(key, &plain)?;
    let mut out = Vec::with_capacity(CACHE_MAGIC.len() + sealed.len());
    out.extend_from_slice(CACHE_MAGIC);
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn decode_snapshot(key: &[u8; 32], blob: &[u8]) -> CacheResult<Snapshot> {
    let body = blob
        .strip_prefix(CACHE_MAGIC.as_slice())
        .ok_or_else(|| "cache file has the wrong magic".to_string())?;
    let plain = crate::crypto::open_with_raw_key(key, body)
        .map_err(|_| "cache decrypt failed (wrong key or tampered file)".to_string())?;
    serde_json::from_slice(&plain).map_err(|e| format!("cache decode failed: {e}"))
}

/// True only when both halves exist; a half-written pair is treated as off.
pub fn enabled() -> bool {
    enabled_at(Path::new("."))
}

pub fn enabled_at(base: &Path) -> bool {
    base.join(CACHE_FILE).is_file() && base.join(KEY_FILE).is_file()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> CacheResult<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", path.display())
    })
}

/// Rebuild the cache from a live vault. Generates a fresh key every time, so a
/// stale cache file cannot be paired with a newer key.
pub fn refresh(vault: &Vault) -> CacheResult<usize> {
    refresh_at(Path::new("."), vault)
}

pub fn refresh_at(base: &Path, vault: &Vault) -> CacheResult<usize> {
    use rand_core::RngCore;
    let snapshot = build_snapshot(vault, crate::models::current_timestamp());
    let mut key = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut key);
    let sealed_key = crate::core::memory::DpapiGuard::protect(&key)
        .map_err(|e| format!("cache key seal failed: {e}"))?;
    let blob = encode_snapshot(&key, &snapshot)?;
    key.zeroize();
    // Key first: if the cache write fails, `enabled()` stays false because the
    // pair is incomplete (and the next refresh overwrites both).
    write_atomic(&base.join(KEY_FILE), &sealed_key)?;
    write_atomic(&base.join(CACHE_FILE), &blob)?;
    Ok(snapshot.items.len())
}

/// Refresh only when the user enabled the cache; returns None when disabled.
pub fn refresh_if_enabled(vault: &Vault) -> Option<CacheResult<usize>> {
    if enabled() {
        Some(refresh(vault))
    } else {
        None
    }
}

/// Remove both halves. Returns true when something existed.
pub fn clear() -> bool {
    clear_at(Path::new("."))
}

pub fn clear_at(base: &Path) -> bool {
    let a = std::fs::remove_file(base.join(CACHE_FILE)).is_ok();
    let b = std::fs::remove_file(base.join(KEY_FILE)).is_ok();
    let _ = std::fs::remove_file(base.join(Path::new(CACHE_FILE).with_extension("tmp")));
    let _ = std::fs::remove_file(base.join(Path::new(KEY_FILE).with_extension("tmp")));
    a || b
}

fn unseal_key_at(base: &Path) -> CacheResult<[u8; 32]> {
    let path = base.join(KEY_FILE);
    let blob = std::fs::read(&path).map_err(|e| format!("cache key missing: {e}"))?;
    let secret = crate::core::memory::DpapiGuard::unprotect(&blob)
        .map_err(|_| "cache key unseal failed (different Windows user?)".to_string())?;
    if secret.expose().len() != 32 {
        return Err("cache key has the wrong length".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(secret.expose());
    Ok(key)
}

fn entry_json(item: &CachedLogin) -> serde_json::Value {
    // Same shape the popup already consumes from `query`; fields that need a
    // live vault (TOTP/health) are neutrally empty/unknown.
    serde_json::json!({
        "id": item.id,
        "title": item.title,
        "username": item.username,
        "password": item.password,
        "totp": "",
        "urls": item.urls,
        "folder": item.folder,
        "reprompt": item.reprompt,
        "last_changed": item.last_changed,
        "verified": item.verified,
        "health": "unknown",
        "last_filled": 0,
    })
}

/// Native-host `cache_get`: Hello prompt, then unseal + decrypt.
/// Only this function may serve while the desktop app is closed.
pub fn handle_cache_get() -> CacheResult<serde_json::Value> {
    if !enabled() {
        return Err("offline cache is not enabled".to_string());
    }
    let verified = crate::windows_native::hello::WindowsHello::authenticate_blocking(
        "Unlock PhantomVault offline cache",
    )
    .map_err(|e| format!("Hello unavailable: {e}"))?;
    if !verified {
        return Err("Hello verification canceled".to_string());
    }
    let mut key = unseal_key_at(Path::new("."))?;
    let blob = std::fs::read(Path::new(".").join(CACHE_FILE))
        .map_err(|e| format!("cache file missing: {e}"))?;
    let snapshot = decode_snapshot(&key, &blob);
    key.zeroize();
    let snapshot = snapshot?;
    crate::security::access_log::log_event("offline-cache", "read");
    Ok(serde_json::json!({
        "ok": true,
        "cached": true,
        "created_at": snapshot.created_at,
        "ttl_secs": SESSION_TTL_SECS,
        "entries": snapshot.items.iter().map(entry_json).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Vault};

    fn login(id: &str, title: &str) -> Credential {
        Credential {
            id: id.to_string(),
            title: title.to_string(),
            username: "user".to_string(),
            password: "secret".to_string(),
            totp_secret: String::new(),
            urls: Vec::new(),
            apps: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
            folder: String::new(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: 0,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        }
    }

    #[test]
    fn snapshot_skips_trash_and_caps() {
        let mut v = Vault::new();
        v.credentials.push(login("a", "Alpha"));
        let mut gone = login("b", "Gone");
        gone.deleted_at = Some(1);
        v.credentials.push(gone);
        let snap = build_snapshot(&v, 123);
        assert_eq!(snap.created_at, 123);
        assert_eq!(snap.items.len(), 1);
        assert_eq!(snap.items[0].id, "a");
        assert_eq!(snap.items[0].password, "secret");
    }

    #[test]
    fn encode_decode_roundtrip_and_wrong_key() {
        let key = [9u8; 32];
        let snap = build_snapshot(&Vault::new(), 1);
        let blob = encode_snapshot(&key, &snap).unwrap();
        assert_eq!(&blob[..5], CACHE_MAGIC);
        let back = decode_snapshot(&key, &blob).unwrap();
        assert_eq!(back.version, 1);
        assert_eq!(back.items.len(), 0);
        assert!(decode_snapshot(&[8u8; 32], &blob).is_err());
        // A flipped tag byte must fail, not silently serve.
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(decode_snapshot(&key, &tampered).is_err());
        assert!(decode_snapshot(&key, b"PVOC1short").is_err());
    }

    #[test]
    fn refresh_at_roundtrips_on_disk_and_clear_removes_both() {
        let dir = std::env::temp_dir().join(format!("pv-offline-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut v = Vault::new();
        v.credentials.push(login("disk1", "Disk Site"));
        assert_eq!(refresh_at(&dir, &v).unwrap(), 1);
        assert!(enabled_at(&dir));
        let key = unseal_key_at(&dir).unwrap();
        let blob = std::fs::read(dir.join(CACHE_FILE)).unwrap();
        let snap = decode_snapshot(&key, &blob).unwrap();
        assert_eq!(snap.items[0].title, "Disk Site");
        assert!(clear_at(&dir));
        assert!(!enabled_at(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_item_roundtrips_every_field() {
        let key = [3u8; 32];
        let mut v = Vault::new();
        let mut c = login("id1", "GitHub");
        c.urls = vec![crate::models::LoginUrl::Plain("https://github.com".into())];
        c.folder = "Work".into();
        c.reprompt = true;
        c.last_changed = 77;
        v.credentials.push(c);
        let snap = build_snapshot(&v, 5);
        let back = decode_snapshot(&key, &encode_snapshot(&key, &snap).unwrap()).unwrap();
        let i = &back.items[0];
        assert_eq!(i.title, "GitHub");
        assert_eq!(i.urls, vec!["https://github.com".to_string()]);
        assert_eq!(i.folder, "Work");
        assert!(i.reprompt);
        assert_eq!(i.last_changed, 77);
    }
}
