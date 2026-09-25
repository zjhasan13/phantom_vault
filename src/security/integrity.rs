//! Startup executable self-integrity (rules Cat 8).
//!
//! First run DPAPI-seals the SHA-256 of `current_exe()` to
//! `exe_integrity.dpapi`. Later runs compare: a mismatch (or a present but
//! unsealable seal — DPAPI itself refuses foreign machines) reports
//! `Tampered`, and the lock screen shows a blocking warning banner.
//! Fail-OPEN only when the exe itself can't be read; a corrupt seal fails
//! CLOSED (warn), since silent re-sealing would bless tampering.
//! Note: every recompile changes the hash by design — developers will see
//! the banner until they delete the seal; that IS the tripwire working.

use crate::core::memory::DpapiGuard;
use std::path::Path;

const SEAL_FILE: &str = "exe_integrity.dpapi";
/// Refuse to hash absurd images (would-DoS startup on a swapped binary).
const MAX_EXE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Integrity {
    FirstSeal,
    Ok,
    Tampered,
    Unknown,
}

fn sha256_file(path: &Path) -> Result<Vec<u8>, String> {
    use sha2::Digest;
    let meta = std::fs::metadata(path).map_err(|e| format!("exe stat failed: {e}"))?;
    if meta.len() == 0 || meta.len() > MAX_EXE_BYTES {
        return Err("exe size implausible".to_string());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("exe read failed: {e}"))?;
    Ok(sha2::Sha256::digest(&bytes).to_vec())
}

pub fn check_at(seal_path: &Path, exe_path: &Path) -> Integrity {
    let hash = match sha256_file(exe_path) {
        Ok(h) => h,
        Err(_) => return Integrity::Unknown,
    };
    let blob = match std::fs::read(seal_path) {
        Err(_) => {
            // First run: seal the baseline silently.
            if let Ok(sealed) = DpapiGuard::protect(&hash) {
                let _ = std::fs::write(seal_path, sealed);
            }
            return Integrity::FirstSeal;
        }
        Ok(b) => b,
    };
    match DpapiGuard::unprotect(&blob) {
        Ok(secret) => {
            let same = secret.expose() == hash.as_slice();
            drop(secret);
            if same {
                Integrity::Ok
            } else {
                Integrity::Tampered
            }
        }
        // Sealed for another machine/user, or corrupted: warn, never re-seal.
        Err(_) => Integrity::Tampered,
    }
}

/// Default paths: `exe_integrity.dpapi` beside the vault, live executable.
pub fn check() -> Integrity {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return Integrity::Unknown,
    };
    check_at(Path::new(SEAL_FILE), &exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("pv-int-{name}-{}.dpapi", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn fixture(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("pv-int-{name}-{}.bin", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn seal_then_ok_then_tamper() {
        let seal = tmp("sot");
        let exe = fixture("exe-a", b"fake-exe-bytes-v1");
        assert_eq!(check_at(&seal, &exe), Integrity::FirstSeal);
        assert!(seal.exists());
        assert_eq!(check_at(&seal, &exe), Integrity::Ok);
        // Rebuilt binary → mismatch warns.
        let exe2 = fixture("exe-b", b"fake-exe-bytes-v2!!!");
        assert_eq!(check_at(&seal, &exe2), Integrity::Tampered);
        // Corrupt seal → warn, never silently re-seal.
        std::fs::write(&seal, b"garbage").unwrap();
        assert_eq!(check_at(&seal, &exe), Integrity::Tampered);
        let _ = std::fs::remove_file(&seal);
        let _ = std::fs::remove_file(&exe);
        let _ = std::fs::remove_file(&exe2);
    }

    #[test]
    fn unreadable_exe_is_unknown_not_tampered() {
        let seal = tmp("unk");
        let missing = std::env::temp_dir().join("pv-int-no-such-file.bin");
        assert_eq!(check_at(&seal, &missing), Integrity::Unknown);
        assert!(!seal.exists(), "must not seal a baseline it cannot read");
    }
}
