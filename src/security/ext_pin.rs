//! Extension PIN store — managed ONLY from the desktop app.
//!
//! Why here and not in the extension: the popup's `chrome.storage` held the
//! hash next to the code that verifies it, and every lock-screen bug stranded
//! users. The desktop owns set/remove and seals the record with DPAPI
//! (user+machine bound). The bridge verifies the PIN — the raw verifier is
//! never served to the extension.
//!
//! A14: the old record was a bare SHA-256 of a 4–8 digit PIN, which is
//! reversible in seconds. The current format is Argon2id(salt, 32 MiB, t=3,
//! p=4) with a persistent attempt lockout. A legacy SHA-256 record is refused
//! (the user re-sets the PIN once); it cannot silently gate anything.
//!
//! Threat honesty: a 4–8 digit PIN is shoulder-surfing protection, not vault
//! crypto. Argon2id + lockout make guessing expensive, not impossible; the
//! desktop vault itself is never touched by this flow.

use std::path::{Path, PathBuf};

pub const EXT_PIN_FILE: &str = "ext_pin.dpapi";
pub const EXT_PIN_BACKOFF_FILE: &str = "ext_pin_backoff";
const MAGIC: &str = "PVPIN2";
const PIN_MIN: usize = 4;
const PIN_MAX: usize = 8;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
// 32 MiB keeps the popup responsive; the parameters are stored in the record
// so a future bump can still verify old PINs.
const M_COST_KIB: u32 = 32 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCheck {
    /// PIN matched.
    Valid,
    /// Wrong PIN; the next attempt may already be rate-limited.
    Invalid,
    /// Too many failures: do not derive, tell the caller how long to wait.
    Locked(u64),
}

fn pin_path(base: &Path) -> PathBuf {
    base.join(EXT_PIN_FILE)
}

fn backoff_path(base: &Path) -> PathBuf {
    base.join(EXT_PIN_BACKOFF_FILE)
}

fn valid_pin(pin: &str) -> bool {
    pin.len() >= PIN_MIN && pin.len() <= PIN_MAX && pin.bytes().all(|c| c.is_ascii_digit())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) || !b.iter().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        out.push(u8::from_str_radix(std::str::from_utf8(&b[i..i + 2]).ok()?, 16).ok()?);
    }
    Some(out)
}

fn derive(salt: &[u8], pin: &str, m: u32, t: u32, p: u32) -> Result<[u8; HASH_LEN], String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m, t, p, Some(HASH_LEN))
        .map_err(|e| format!("PIN KDF params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; HASH_LEN];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut out)
        .map_err(|e| format!("PIN KDF: {e}"))?;
    Ok(out)
}

/// Store (or replace) the PIN. The raw PIN is never persisted.
pub fn set(base: &Path, pin: &str) -> Result<(), String> {
    if !valid_pin(pin) {
        return Err("PIN must be 4–8 digits.".to_string());
    }
    use rand_core::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);
    let mut hash = derive(&salt, pin, M_COST_KIB, T_COST, P_COST)?;
    let record = format!(
        "{MAGIC}|{}|{M_COST_KIB}|{T_COST}|{P_COST}|{}",
        hex(&salt),
        hex(&hash)
    );
    hash.iter_mut().for_each(|b| *b = 0);
    let blob = crate::core::memory::DpapiGuard::protect(record.as_bytes())
        .map_err(|e| format!("seal failed: {e:?}"))?;
    let tmp = base.join("ext_pin.dpapi.tmp");
    std::fs::write(&tmp, &blob).map_err(|e| format!("write: {e}"))?;
    std::fs::rename(&tmp, pin_path(base)).map_err(|e| format!("swap: {e}"))?;
    // A fresh PIN starts a fresh attempt budget.
    crate::security::backoff::record_success(&backoff_path(base));
    Ok(())
}

/// True when an extension PIN is enrolled on this machine.
pub fn is_set(base: &Path) -> bool {
    pin_path(base).is_file()
}

struct PinRecord {
    salt: Vec<u8>,
    m: u32,
    t: u32,
    p: u32,
    hash: [u8; HASH_LEN],
}

/// Parse the sealed record. `Err` for a legacy SHA-256 record or corruption —
/// callers must fail closed and ask the user to re-set the PIN.
fn read_record(base: &Path) -> Result<PinRecord, String> {
    let blob = std::fs::read(pin_path(base)).map_err(|_| "no extension PIN set".to_string())?;
    let secret = crate::core::memory::DpapiGuard::unprotect(&blob)
        .map_err(|_| "extension PIN record cannot be unsealed".to_string())?;
    let text = String::from_utf8_lossy(secret.expose()).trim().to_string();
    if text.len() == 64 && text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("legacy SHA-256 PIN record — re-set the PIN in Settings".to_string());
    }
    let parts: Vec<&str> = text.split('|').collect();
    if parts.len() != 6 || parts[0] != MAGIC {
        return Err("extension PIN record is malformed".to_string());
    }
    let salt = unhex(parts[1]).ok_or_else(|| "PIN salt is malformed".to_string())?;
    if salt.len() != SALT_LEN {
        return Err("PIN salt has the wrong length".to_string());
    }
    let m = parts[2].parse::<u32>().map_err(|_| "PIN KDF params".to_string())?;
    let t = parts[3].parse::<u32>().map_err(|_| "PIN KDF params".to_string())?;
    let p = parts[4].parse::<u32>().map_err(|_| "PIN KDF params".to_string())?;
    let hash = unhex(parts[5]).ok_or_else(|| "PIN hash is malformed".to_string())?;
    if hash.len() != HASH_LEN {
        return Err("PIN hash has the wrong length".to_string());
    }
    let mut stored = [0u8; HASH_LEN];
    stored.copy_from_slice(&hash);
    Ok(PinRecord {
        salt,
        m,
        t,
        p,
        hash: stored,
    })
}

/// Attempt lockout schedule (seconds). Deliberately harsher than the master
/// backoff: 4 digits = 10k guesses, so the budget must be tiny.
pub fn delay_for_failures(fails: u32) -> u64 {
    match fails {
        0..=4 => 0,
        5 => 30,
        6 => 60,
        7 => 120,
        _ => 300,
    }
}

/// Verify a PIN with a persistent attempt lockout. The counter lives beside the
/// record and survives host/app restarts.
pub fn verify(base: &Path, pin: &str) -> Result<PinCheck, String> {
    use subtle::ConstantTimeEq;
    let bp = backoff_path(base);
    let fails = crate::security::backoff::read_failures(&bp);
    let wait = delay_for_failures(fails);
    if wait > 0 {
        return Ok(PinCheck::Locked(wait));
    }
    if !valid_pin(pin) {
        crate::security::backoff::record_failure(&bp);
        return Ok(PinCheck::Invalid);
    }
    let rec = read_record(base)?;
    let mut got = derive(&rec.salt, pin, rec.m, rec.t, rec.p)?;
    let ok = got.as_slice().ct_eq(rec.hash.as_slice()).into();
    got.iter_mut().for_each(|b| *b = 0);
    if ok {
        crate::security::backoff::record_success(&bp);
        Ok(PinCheck::Valid)
    } else {
        crate::security::backoff::record_failure(&bp);
        Ok(PinCheck::Invalid)
    }
}

/// Remove the enrollment and the attempt counter. Idempotent.
pub fn clear(base: &Path) {
    let _ = std::fs::remove_file(pin_path(base));
    let _ = std::fs::remove_file(backoff_path(base));
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

    #[test]
    fn set_verify_clear_roundtrip() {
        let d = dir("roundtrip");
        assert!(!is_set(&d));
        set(&d, "1234").unwrap();
        assert!(is_set(&d));
        assert_eq!(verify(&d, "1234").unwrap(), PinCheck::Valid);
        assert_eq!(verify(&d, "9999").unwrap(), PinCheck::Invalid);
        // A success clears the failure counter.
        assert_eq!(verify(&d, "1234").unwrap(), PinCheck::Valid);
        clear(&d);
        assert!(!is_set(&d));
        assert!(verify(&d, "1234").is_err());
        clear(&d); // idempotent
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_non_digit_and_bad_length() {
        let d = dir("valid");
        assert!(set(&d, "12a4").is_err());
        assert!(set(&d, "123").is_err());
        assert!(set(&d, "123456789").is_err());
        assert!(!is_set(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn legacy_sha256_record_fails_closed() {
        let d = dir("legacy");
        let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let blob = crate::core::memory::DpapiGuard::protect(hex.as_bytes()).unwrap();
        std::fs::write(pin_path(&d), blob).unwrap();
        let err = verify(&d, "1234").unwrap_err();
        assert!(err.contains("legacy"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn lockout_after_five_failures_persists() {
        let d = dir("lockout");
        set(&d, "1234").unwrap();
        for _ in 0..5 {
            assert_eq!(verify(&d, "0000").unwrap(), PinCheck::Invalid);
        }
        assert_eq!(verify(&d, "1234").unwrap(), PinCheck::Locked(30));
        // Same file-backed counter is read by a fresh call (host restart).
        assert_eq!(verify(&d, "1234").unwrap(), PinCheck::Locked(30));
        // Clear resets both the record and the budget.
        clear(&d);
        set(&d, "1234").unwrap();
        assert_eq!(verify(&d, "1234").unwrap(), PinCheck::Valid);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn corrupt_record_fails_closed() {
        let d = dir("corrupt");
        set(&d, "1234").unwrap();
        std::fs::write(pin_path(&d), b"definitely-not-dpapi").unwrap();
        assert!(verify(&d, "1234").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
