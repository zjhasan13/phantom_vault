//! Manual 2FA clock offset — an offline, privacy-free correction for a PC
//! whose system clock disagrees with real time.
//!
//! WHY: TOTP windows are absolute UTC (RFC 6238), so a clock that runs 90s
//! fast emits codes no server will accept. Windows time sync normally fixes
//! that, but locked-down/corporate machines and some VMs cannot be corrected
//! (no elevation, time service disabled, permanently offline). This is the
//! escape hatch: a signed second count applied to 2FA generation only.
//!
//! WHY OFFLINE BY DESIGN: no NTP probe and no HTTP `Date` fetch. A networked
//! drift check would have to honour the global offline kill-switch on a brand
//! new egress path, and it would tell a third party exactly when this machine
//! runs an authenticator. Reading a local file has neither problem.
//!
//! Storage is `totp_offset.pref` — plain text integer seconds, clamped to
//! ±MAX_OFFSET_SECS. It is NOT a secret: it grants no access on its own and
//! is inert without the vault, so it needs no DPAPI seal and deliberately
//! stays OUT of the encrypted vault. That keeps the vault format, the sync
//! payload and every backup generation byte-identical — no migration.
//!
//! Sizing the clamp: Windows' own sync tolerance is ~±500 ms. ±300 s covers a
//! materially wrong machine while stopping a fat-fingered entry from shifting
//! every code by hours, where the failure would look like "the app is broken".

use std::sync::atomic::{AtomicI64, Ordering};

const PREF_FILE: &str = "totp_offset.pref";

/// Hard ceiling on |offset| in seconds (see module docs for the rationale).
pub const MAX_OFFSET_SECS: i64 = 300;

/// Sentinel meaning "not yet loaded from disk"; any real offset fits in i64.
const UNSET: i64 = i64::MIN;

/// Process-local cache. `now_secs()` runs once per account per 1s tick, so
/// the pref is read from RAM, never from disk on the hot path.
static CACHE: AtomicI64 = AtomicI64::new(UNSET);

/// Clamp a user-supplied offset into the supported band.
pub fn clamp(v: i64) -> i64 {
    v.clamp(-MAX_OFFSET_SECS, MAX_OFFSET_SECS)
}

/// Effective UTC epoch seconds for a raw system clock reading plus an offset.
///
/// Pure and separated from `SystemTime` so the arithmetic is unit-testable
/// without touching the real clock or the filesystem. Two failure modes are
/// handled explicitly:
/// - a negative raw+offset (impossible before 1970, but reachable with a
///   large negative offset) clamps to 0 instead of wrapping into a huge `u64`
///   and jumping the code to a far-future window;
/// - `saturating_add` avoids wraparound on the same input.
fn effective(raw_secs: i64, offset_secs: i64) -> u64 {
    raw_secs.saturating_add(offset_secs).max(0) as u64
}

/// Current manual offset in seconds (0 = system clock used as-is).
pub fn get() -> i64 {
    let cached = CACHE.load(Ordering::Relaxed);
    if cached != UNSET {
        return cached;
    }
    // A missing, empty, unparsable or absurd pref is not an error — it means
    // "no correction configured", which is the safe default for an
    // authenticator. Never fall back to a guess.
    let parsed = std::fs::read_to_string(PREF_FILE)
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .map(clamp)
        .unwrap_or(0);
    CACHE.store(parsed, Ordering::Relaxed);
    parsed
}

/// Persist a new offset (clamped) and return the value actually in effect.
/// Best-effort on failure: if the write fails the cache is left alone so the
/// live value can never disagree with the file the user just inspected.
pub fn set(v: i64) -> i64 {
    let v = clamp(v);
    if std::fs::write(PREF_FILE, v.to_string()).is_ok() {
        CACHE.store(v, Ordering::Relaxed);
        v
    } else {
        get()
    }
}

/// Drop the correction and go back to the raw system clock.
pub fn reset() -> i64 {
    set(0)
}

/// `"+90s"` / `"-45s"`, or `None` when the clock is used as-is (nothing to
/// show). Used for the honest "your codes are shifted" UI badge.
pub fn label_for(offset_secs: i64) -> Option<String> {
    match clamp(offset_secs) {
        0 => None,
        v => Some(format!("{v:+}s")),
    }
}

/// Live badge label for the current offset.
pub fn label() -> Option<String> {
    label_for(get())
}

/// The one clock read every 2FA code in the app is derived from.
pub fn now_secs() -> u64 {
    let raw = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    effective(raw, get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_bounds_both_directions() {
        assert_eq!(clamp(0), 0);
        assert_eq!(clamp(90), 90);
        assert_eq!(clamp(-90), -90);
        assert_eq!(clamp(MAX_OFFSET_SECS), MAX_OFFSET_SECS);
        assert_eq!(clamp(-MAX_OFFSET_SECS), -MAX_OFFSET_SECS);
        // Fat-finger / hostile input is truncated, never rejected.
        assert_eq!(clamp(999_999), MAX_OFFSET_SECS);
        assert_eq!(clamp(-999_999), -MAX_OFFSET_SECS);
        assert_eq!(clamp(i64::MAX), MAX_OFFSET_SECS);
        assert_eq!(clamp(i64::MIN), -MAX_OFFSET_SECS);
    }

    #[test]
    fn zero_offset_is_identity() {
        assert_eq!(effective(1_700_000_000, 0), 1_700_000_000);
    }

    #[test]
    fn offset_shifts_effective_clock() {
        assert_eq!(effective(1_000, 90), 1_090);
        assert_eq!(effective(1_000, -90), 910);
    }

    #[test]
    fn negative_result_clamps_to_zero_not_wraparound() {
        // The dangerous case: a naive `as u64` cast on a negative i64 yields a
        // ~1.8e19 timestamp, which would compute a garbage far-future window.
        assert_eq!(effective(10, -300), 0);
        assert_eq!(effective(0, -1), 0);
        assert_eq!(effective(0, -MAX_OFFSET_SECS), 0);
    }

    #[test]
    fn positive_overflow_saturates() {
        assert_eq!(effective(i64::MAX, MAX_OFFSET_SECS), i64::MAX as u64);
    }

    #[test]
    fn label_formats_sign_and_hides_zero() {
        assert_eq!(label_for(0), None);
        assert_eq!(label_for(90).as_deref(), Some("+90s"));
        assert_eq!(label_for(-45).as_deref(), Some("-45s"));
        // Out-of-band values are clamped before formatting, so the badge can
        // never advertise an offset the code path will not actually apply.
        assert_eq!(label_for(9_999).as_deref(), Some("+300s"));
    }

    #[test]
    fn live_clock_is_within_the_supported_band_of_raw() {
        // Hermetic bound check against the real clock: whatever the pref says,
        // the effective time must sit within the clamp band of the raw read.
        let raw = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let got = now_secs() as i64;
        // Precompute: an expression with a `-` inside `{...}` is not a valid
        // inline format arg, and silently mis-renders as a literal brace.
        let drift = got - raw;
        assert!(
            drift.abs() <= MAX_OFFSET_SECS,
            "effective clock drifted {drift}s from raw, outside ±{MAX_OFFSET_SECS}"
        );
    }
}
