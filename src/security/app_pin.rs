//! App PIN quick-unlock (DPAPI-bound, device-local, never synced).
//!
//! Design (NOT "encrypt master with raw DPAPI"):
//! - Enroll: `pin_key = Argon2id(PIN, salt[16])`; the master password is
//!   sealed with DPAPI with `pin_key` as `optionalEntropy`:
//!   `pin.dpapi = salt[16] || DPAPI(master, entropy=pin_key)`.
//!   A stolen blob alone is useless: unsealing needs the live PIN *and* the
//!   machine DPAPI key. Same-user background malware is explicitly OUT of
//!   scope (it can keylog the PIN anyway) — this stops casual hands-on
//!   guessing, shoulder-surfers, and stolen-file offline attacks.
//! - Unlock: re-derive `pin_key`, unseal. Wrong PIN ⇒ OS-level DPAPI failure
//!   (no oracle beyond fail itself); the 5-strike counter decides wipe vs
//!   retry. All key buffers zeroize on drop.
//!
//! Files: `pin.dpapi` (sealed master), `pin_attempts.dpapi` (sealed counter,
//! same tmp+rename atomic pattern as the unlock backoff).

use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};
use rand_core::{OsRng, RngCore};

pub const PIN_FILE: &str = "pin.dpapi";
pub const PIN_ATTEMPTS_FILE: &str = "pin_attempts.dpapi";
/// Wrong guesses before the sealed master is shredded (owner re-enrolls
/// with the master password afterwards — never a lockout).
pub const MAX_PIN_ATTEMPTS: u32 = 5;
pub const PIN_MIN_LEN: usize = 4;
pub const PIN_MAX_LEN: usize = 8;
const SALT_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum PinError {
    /// No PIN enrolled on this machine.
    NoPin,
    /// PIN format rejected at setup (length/digits) — never written.
    BadFormat(String),
    /// Wrong PIN; `remaining` guesses left before the wipe.
    WrongPin { remaining: u32 },
    /// 5th strike: `pin.dpapi` shredded, counter reset. Re-enroll by master.
    Wiped,
    /// OS/crypto failure (DPAPI, KDF, IO).
    Crypto(String),
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::NoPin => write!(f, "No App PIN set on this machine."),
            PinError::BadFormat(s) => write!(f, "{s}"),
            PinError::WrongPin { remaining } => {
                write!(f, "Wrong PIN. {remaining} attempt(s) left before wipe.")
            }
            PinError::Wiped => write!(
                f,
                "Too many wrong PINs — PIN login wiped. Unlock with your master password to set a new PIN."
            ),
            PinError::Crypto(s) => write!(f, "{s}"),
        }
    }
}

fn pin_path(base: &Path) -> PathBuf {
    base.join(PIN_FILE)
}

fn attempts_path(base: &Path) -> PathBuf {
    base.join(PIN_ATTEMPTS_FILE)
}

fn check_format(pin: &str) -> Result<(), PinError> {
    if !(PIN_MIN_LEN..=PIN_MAX_LEN).contains(&pin.len()) {
        return Err(PinError::BadFormat(format!(
            "PIN must be {PIN_MIN_LEN}–{PIN_MAX_LEN} digits."
        )));
    }
    if !pin.bytes().all(|c| c.is_ascii_digit()) {
        return Err(PinError::BadFormat("PIN must be digits only.".into()));
    }
    Ok(())
}

/// Argon2id(PIN, salt) → 32-byte key, zeroized on drop. Same OWASP-grade
/// parameters as the vault KDF (a short PIN is onion-wrapped by DPAPI +
/// strike-wipe on top — KDF cost is the third layer, not the only one).
fn derive_pin_key(pin: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, PinError> {
    let mut out = Zeroizing::new([0u8; 32]);
    crate::crypto::derive_key_secret(&secrecy::SecretString::new(pin.to_string()), salt)
        .map(|k| {
            out.copy_from_slice(&k);
            // derive_key returns a plain array — wipe OUR copy source too.
            let mut k = k;
            k.zeroize();
        })
        .map_err(PinError::Crypto)?;
    Ok(out)
}

fn read_attempts(base: &Path) -> u32 {
    let p = attempts_path(base);
    let blob = match std::fs::read(&p) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    crate::core::memory::DpapiGuard::unprotect(&blob)
        .ok()
        .and_then(|s| String::from_utf8_lossy(s.expose()).trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn write_attempts(base: &Path, n: u32) {
    let p = attempts_path(base);
    if let Ok(blob) = crate::core::memory::DpapiGuard::protect(n.to_string().as_bytes()) {
        let tmp = base.join("pin_attempts.tmp");
        if std::fs::write(&tmp, &blob).is_ok() {
            let _ = std::fs::rename(&tmp, &p);
        }
    }
}

/// Enroll (or replace) the machine-local PIN, sealing the live master.
/// Requires the caller to hold the proven master (Settings, unlocked).
pub fn enroll(base: &Path, pin: &str, master: &str) -> Result<(), PinError> {
    check_format(pin)?;
    if master.is_empty() {
        return Err(PinError::Crypto("nothing to seal".into()));
    }
    let mut salt = [0u8; SALT_LEN];
    RngCore::fill_bytes(&mut OsRng, &mut salt);
    let key = derive_pin_key(pin, &salt)?;
    let blob = crate::core::memory::DpapiGuard::protect_with_entropy(master.as_bytes(), &key[..])
        .map_err(|e| PinError::Crypto(format!("seal failed: {e:?}")))?;
    drop(key);
    let mut file = salt.to_vec();
    file.extend_from_slice(&blob);
    // Atomic swap so a crash never leaves a torn half-PIN (tmp+rename).
    let tmp = base.join("pin.dpapi.tmp");
    std::fs::write(&tmp, &file).map_err(|e| PinError::Crypto(format!("write: {e}")))?;
    std::fs::rename(&tmp, pin_path(base)).map_err(|e| PinError::Crypto(format!("swap: {e}")))?;
    // Fresh enroll resets the strike counter.
    let _ = std::fs::remove_file(attempts_path(base));
    Ok(())
}

/// True when a PIN blob exists on this machine (lock-screen button gate).
pub fn is_enrolled(base: &Path) -> bool {
    pin_path(base).is_file()
}

/// Verify a PIN guess. Ok(master) on success (attempts reset). Wrong guesses
/// bump the sealed counter; the 5th strike shreds `pin.dpapi` and reports
/// `Wiped`. The returned master is a zeroizing `SecretString`.
pub fn verify_and_recover(
    base: &Path,
    pin: &str,
) -> Result<secrecy::SecretString, PinError> {
    let raw = match std::fs::read(pin_path(base)) {
        Ok(b) => b,
        Err(_) => return Err(PinError::NoPin),
    };
    if raw.len() <= SALT_LEN {
        return Err(PinError::Crypto("PIN blob truncated".into()));
    }
    let (salt, blob) = raw.split_at(SALT_LEN);
    // Malformed (non-digit/short) guesses still cost a strike — otherwise
    // format probing is free.
    let fmt_ok = (PIN_MIN_LEN..=PIN_MAX_LEN).contains(&pin.len()) && pin.bytes().all(|c| c.is_ascii_digit());
    let key = if fmt_ok {
        Some(derive_pin_key(pin, salt).map_err(|_| PinError::WrongPin {
            remaining: MAX_PIN_ATTEMPTS.saturating_sub(read_attempts(base) + 1),
        })?)
    } else {
        None
    };
    let recovered = key.as_ref().and_then(|k| {
        crate::core::memory::DpapiGuard::unprotect_with_entropy(blob, &k[..]).ok()
    });
    match recovered {
        Some(secret) => {
            let text = String::from_utf8_lossy(secret.expose()).into_owned();
            drop(secret);
            if text.is_empty() {
                return Err(PinError::Crypto("unsealed empty master".into()));
            }
            let _ = std::fs::remove_file(attempts_path(base));
            Ok(secrecy::SecretString::new(text))
        }
        None => {
            let fails = read_attempts(base).saturating_add(1);
            if fails >= MAX_PIN_ATTEMPTS {
                // 5th strike: shred the sealed master (DoD 3-pass) + reset.
                let _ = crate::security::shredder::shred_file(&pin_path(base));
                let _ = std::fs::remove_file(attempts_path(base));
                Err(PinError::Wiped)
            } else {
                write_attempts(base, fails);
                Err(PinError::WrongPin {
                    remaining: MAX_PIN_ATTEMPTS - fails,
                })
            }
        }
    }
}

/// Remove PIN login entirely (Settings → Remove; also used post-wipe).
/// Idempotent — missing files are fine.
pub fn disable(base: &Path) {
    let _ = std::fs::remove_file(pin_path(base));
    let _ = std::fs::remove_file(attempts_path(base));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        // Unique per test: the harness runs tests in parallel in one process.
        let d = std::env::temp_dir().join(format!("pv-pin-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn format_gate() {
        assert!(check_format("1234").is_ok());
        assert!(check_format("12345678").is_ok());
        assert!(matches!(check_format("123"), Err(PinError::BadFormat(_))));
        assert!(matches!(check_format("123456789"), Err(PinError::BadFormat(_))));
        assert!(matches!(check_format("12ab"), Err(PinError::BadFormat(_))));
        assert!(matches!(check_format(""), Err(PinError::BadFormat(_))));
    }

    #[test]
    fn roundtrip_and_wrong_pin_counts() {
        use secrecy::ExposeSecret;
        let d = dir("roundtrip");
        assert!(!is_enrolled(&d));
        enroll(&d, "246810", "correct-horse-master").unwrap();
        assert!(is_enrolled(&d));
        // Happy path recovers the exact master.
        let m = verify_and_recover(&d, "246810").unwrap();
        assert_eq!(m.expose_secret().as_str(), "correct-horse-master");
        // Wrong guesses count down, then wipe on the 5th.
        for want in [4, 3, 2, 1] {
            assert_eq!(
                verify_and_recover(&d, "000000").unwrap_err(),
                PinError::WrongPin { remaining: want }
            );
        }
        assert_eq!(
            verify_and_recover(&d, "000000").unwrap_err(),
            PinError::Wiped
        );
        assert!(!is_enrolled(&d));
        // Malformed guesses also cost strikes (fresh enroll first).
        enroll(&d, "1357", "m").unwrap();
        assert!(matches!(
            verify_and_recover(&d, "abc"),
            Err(PinError::WrongPin { .. })
        ));
        disable(&d);
        assert!(!is_enrolled(&d));
        assert_eq!(verify_and_recover(&d, "1357").unwrap_err(), PinError::NoPin);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_blob_fails_closed() {
        let d = dir("tamper");
        enroll(&d, "112233", "master-secret").unwrap();
        // Flip a byte in the DPAPI region (not the salt).
        let mut raw = std::fs::read(pin_path(&d)).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        std::fs::write(pin_path(&d), &raw).unwrap();
        // Correct PIN against a tampered blob must fail, never yield bytes.
        assert!(matches!(
            verify_and_recover(&d, "112233"),
            Err(PinError::WrongPin { .. })
        ));
        let _ = std::fs::remove_dir_all(&d);
    }
}
