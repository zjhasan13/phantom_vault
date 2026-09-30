//! Brute-force backoff (rules Cat 8).
//!
//! Wrong master passwords cost attacker time, not just KDF time: after each
//! failed unlock the worker sleeps `delay(fails)` BEFORE burning Argon2id,
//! with fails persisted in a plaintext counter beside the vault (counts are
//! not secrets). Success deletes the counter. Pure logic — unit tested.

use std::path::Path;

// H7: DPAPI-sealed counter (not CWD plaintext) + atomic tmp+rename writes.
// Deletion still resets — documented limit without a server — but casual
// `echo x >` corruption no longer resets, and concurrent writers don't tear.
const COUNTER_FILE: &str = "unlock_backoff.dpapi";
/// Growth cap: 1,2,4,8,16,30,30… seconds. Never locks the owner out.
const MAX_DELAY_SECS: u64 = 30;

/// Delay for a 1-based consecutive-failure count: 1,2,4,8,16,30,30…
/// Saturates at the cap — the owner is never locked out.
pub fn delay_for_failures(fails: u32) -> u64 {
    if fails == 0 {
        return 0;
    }
    (1u64 << fails.saturating_sub(1).min(5)).min(MAX_DELAY_SECS)
}

/// Read the persisted failure count (missing/corrupt file = 0, fail open
/// for the owner; DPAPI seal means attacker-written garbage also reads 0
/// but cannot plant a large value to lock the owner out).
pub fn read_failures(path: &Path) -> u32 {
    let blob = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            // Legacy plaintext counter (pre-H7): honor it once, then migrate.
            return std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(0);
        }
    };
    crate::core::memory::DpapiGuard::unprotect(&blob)
        .ok()
        .and_then(|s| {
            String::from_utf8_lossy(s.expose()).trim().parse::<u32>().ok()
        })
        .unwrap_or(0)
}

/// Bump the counter after a failed attempt. Atomic tmp+rename; best effort.
pub fn record_failure(path: &Path) {
    let next = read_failures(path).saturating_add(1);
    if let Ok(blob) = crate::core::memory::DpapiGuard::protect(next.to_string().as_bytes()) {
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, &blob).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// Clear the counter after a successful unlock.
pub fn record_success(path: &Path) {
    let _ = std::fs::remove_file(path);
}

pub fn default_path() -> std::path::PathBuf {
    std::path::PathBuf::from(COUNTER_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_grows_then_caps() {
        assert_eq!(delay_for_failures(0), 0);
        assert_eq!(delay_for_failures(1), 1);
        assert_eq!(delay_for_failures(2), 2);
        assert_eq!(delay_for_failures(3), 4);
        assert_eq!(delay_for_failures(5), 16);
        assert_eq!(delay_for_failures(6), 30);
        assert_eq!(delay_for_failures(100), 30);
        assert_eq!(delay_for_failures(u32::MAX), 30);
    }

    #[test]
    fn counter_roundtrip_and_corrupt_is_zero() {
        let path = std::env::temp_dir().join(format!("pv-backoff-{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_failures(&path), 0);
        record_failure(&path);
        record_failure(&path);
        assert_eq!(read_failures(&path), 2);
        std::fs::write(&path, "garbage!!").unwrap();
        assert_eq!(read_failures(&path), 0);
        record_success(&path);
        assert!(!path.exists());
    }
}
