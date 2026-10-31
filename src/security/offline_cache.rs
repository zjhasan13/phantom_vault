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
/// Presence = the user explicitly allowed the PIN fallback for the cache.
/// Removed by disabling the cache, removing/replacing the PIN, or decoy.
pub const PIN_ALLOWED_FILE: &str = "offline_cache_pin.pref";
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

/// True when the user explicitly allowed PIN unlock for the cache.
pub fn pin_allowed_at(base: &Path) -> bool {
    base.join(PIN_ALLOWED_FILE).is_file()
}

/// Toggle the PIN fallback. Callers must also ensure the cache and a PIN are
/// present before enabling; this is just the consent marker.
pub fn set_pin_allowed_at(base: &Path, on: bool) -> CacheResult<()> {
    let path = base.join(PIN_ALLOWED_FILE);
    if on {
        std::fs::write(&path, b"1").map_err(|e| format!("cannot write {}: {e}", path.display()))
    } else {
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}

pub fn set_pin_allowed(on: bool) -> CacheResult<()> {
    set_pin_allowed_at(Path::new("."), on)
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
    let _ = std::fs::remove_file(base.join(PIN_ALLOWED_FILE));
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

/// Native-host `cache_status`: does a cache exist, and is a PIN enrolled?
/// Never prompts and returns no secrets, so the popup can offer the right
/// unlock methods while the desktop is closed.
pub fn cache_status_at(base: &Path) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "enabled": enabled_at(base),
        "pin_set": crate::security::ext_pin::is_set(base),
        "pin_allowed": pin_allowed_at(base) && crate::security::ext_pin::is_set(base),
    })
}

pub fn cache_status() -> serde_json::Value {
    cache_status_at(Path::new("."))
}

fn read_snapshot_at(base: &Path) -> CacheResult<Snapshot> {
    let mut key = unseal_key_at(base)?;
    let blob = std::fs::read(base.join(CACHE_FILE))
        .map_err(|e| format!("cache file missing: {e}"))?;
    let snapshot = decode_snapshot(&key, &blob);
    key.zeroize();
    snapshot
}

/// Native-host `cache_get`: unlock with Windows Hello (default) or the
/// extension PIN, then unseal + decrypt. Only this path may serve while the
/// desktop app is closed. Both gates are read-only and share the same cache.
pub fn handle_cache_get_at(
    base: &Path,
    method: &str,
    pin: Option<&str>,
) -> CacheResult<serde_json::Value> {
    if !enabled_at(base) {
        return Err("offline cache is not enabled".to_string());
    }
    match method {
        "hello" => {
            let verified = crate::windows_native::hello::WindowsHello::authenticate_blocking(
                "Unlock PhantomVault offline cache",
            )
            .map_err(|e| format!("Hello unavailable: {e}"))?;
            if !verified {
                return Err("Hello verification canceled".to_string());
            }
        }
        "pin" => {
            if !crate::security::ext_pin::is_set(base) {
                return Err("no extension PIN set".to_string());
            }
            if !pin_allowed_at(base) {
                return Err("PIN unlock is disabled for the offline cache".to_string());
            }
            match crate::security::ext_pin::verify(base, pin.unwrap_or("")) {
                Ok(crate::security::ext_pin::PinCheck::Valid) => {}
                Ok(crate::security::ext_pin::PinCheck::Invalid) => {
                    return Err("wrong PIN".to_string());
                }
                Ok(crate::security::ext_pin::PinCheck::Locked(secs)) => {
                    return Err(format!("too many attempts; retry in {secs}s"));
                }
                Err(e) => return Err(e),
            }
        }
        _ => return Err("unknown offline cache unlock method".to_string()),
    }
    let snapshot = read_snapshot_at(base)?;
    crate::security::access_log::log_event(
        "offline-cache",
        if method == "pin" { "read-pin" } else { "read-hello" },
    );
    Ok(serde_json::json!({
        "ok": true,
        "cached": true,
        "method": method,
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
    fn pin_gate_reads_the_same_snapshot_and_rejects_wrong_pin() {
        let dir = std::env::temp_dir().join(format!("pv-offline-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut v = Vault::new();
        v.credentials.push(login("pin1", "PIN Site"));
        refresh_at(&dir, &v).unwrap();
        crate::security::ext_pin::set(&dir, "1234").unwrap();
        // A11b: PIN fallback is opt-in; without the consent marker it refuses.
        assert!(handle_cache_get_at(&dir, "pin", Some("1234")).is_err());
        set_pin_allowed_at(&dir, true).unwrap();

        let status = cache_status_at(&dir);
        assert_eq!(status["enabled"], true);
        assert_eq!(status["pin_set"], true);
        assert_eq!(status["pin_allowed"], true);

        let ok = handle_cache_get_at(&dir, "pin", Some("1234")).unwrap();
        assert_eq!(ok["ok"], true);
        assert_eq!(ok["method"], "pin");
        assert_eq!(ok["entries"][0]["title"], "PIN Site");
        assert!(handle_cache_get_at(&dir, "pin", Some("9999")).is_err());
        assert!(handle_cache_get_at(&dir, "nope", None).is_err());

        crate::security::ext_pin::clear(&dir);
        let err = handle_cache_get_at(&dir, "pin", Some("1234")).unwrap_err();
        assert!(err.contains("no extension PIN"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
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
