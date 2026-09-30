//! Extension PIN store — managed ONLY from the desktop app.
//!
//! Why here and not in the extension: the popup's `chrome.storage` held the
//! hash next to the code that verifies it, and every lock-screen bug stranded
//! users. Now the desktop owns set/remove, seals the hash with DPAPI
//! (user+machine bound), and serves it over the already-trusted native bridge.
//! The extension keeps zero PIN state and enforces against the served hash.
//!
//! Threat honesty: a 4–8 digit PIN is shoulder-surfing protection, not vault
//! crypto. DPAPI binding means the file alone is useless off-machine; the
//! desktop vault itself is never touched by this flow.

use std::path::{Path, PathBuf};

pub const EXT_PIN_FILE: &str = "ext_pin.dpapi";

fn pin_path(base: &Path) -> PathBuf {
    base.join(EXT_PIN_FILE)
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit())
}

/// True when an extension PIN is enrolled on this machine.
pub fn is_set(base: &Path) -> bool {
    pin_path(base).is_file()
}

/// Store a SHA-256 hex hash (computed by the caller — the raw PIN never
/// reaches this layer). Rejects malformed hashes loudly.
pub fn set(base: &Path, hash_hex: &str) -> Result<(), String> {
    let h = hash_hex.trim().to_lowercase();
    if !valid_hash(&h) {
        return Err("PIN hash must be 64 hex chars (SHA-256).".to_string());
    }
    let blob = crate::core::memory::DpapiGuard::protect(h.as_bytes())
        .map_err(|e| format!("seal failed: {e:?}"))?;
    let tmp = base.join("ext_pin.dpapi.tmp");
    std::fs::write(&tmp, &blob).map_err(|e| format!("write: {e}"))?;
    std::fs::rename(&tmp, pin_path(base)).map_err(|e| format!("swap: {e}"))?;
    Ok(())
}

/// Read back the sealed hash for serving over the bridge. None when unset
/// or undecodable (fail-closed: callers treat as locked, never as open).
pub fn read_hash(base: &Path) -> Option<String> {
    let blob = std::fs::read(pin_path(base)).ok()?;
    let secret = crate::core::memory::DpapiGuard::unprotect(&blob).ok()?;
    let s = String::from_utf8_lossy(secret.expose()).trim().to_string();
    if valid_hash(&s) {
        Some(s)
    } else {
        None
    }
}

/// Remove the enrollment. Idempotent.
pub fn clear(base: &Path) {
    let _ = std::fs::remove_file(pin_path(base));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pv-extpin-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const HASH: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[test]
    fn set_read_clear_roundtrip() {
        let d = dir("roundtrip");
        assert!(!is_set(&d));
        assert!(read_hash(&d).is_none());
        set(&d, HASH).unwrap();
        assert!(is_set(&d));
        assert_eq!(read_hash(&d).as_deref(), Some(HASH));
        // Uppercase accepted, stored lowercase.
        set(&d, &HASH.to_uppercase()).unwrap();
        assert_eq!(read_hash(&d).as_deref(), Some(HASH));
        clear(&d);
        assert!(!is_set(&d));
        assert!(read_hash(&d).is_none());
        clear(&d); // idempotent
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn malformed_hashes_rejected() {
        let d = dir("malformed");
        assert!(set(&d, "").is_err());
        assert!(set(&d, "abc123").is_err());
        assert!(set(&d, &"zz".repeat(32)).is_err());
        assert!(!is_set(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn corrupt_blob_fails_closed() {
        let d = dir("corrupt");
        set(&d, HASH).unwrap();
        std::fs::write(pin_path(&d), b"definitely-not-dpapi").unwrap();
        assert!(read_hash(&d).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
