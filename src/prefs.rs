//! Persisted, non-secret UI preferences (D-3).
//!
//! Auto-lock and the clipboard TTL used to live only in atomics, so every
//! restart silently reverted a 1-minute auto-lock to "Never" and the clipboard
//! timer back to 15 s. They are not secrets: a plain JSON file beside
//! `lang.pref` is enough. Saves go through tmp+rename so a crash never leaves a
//! half-written preference behind.

use serde::{Deserialize, Serialize};

pub const PREFS_FILE: &str = "ui.prefs.json";
/// 0 = Never. 15 minutes is the shipped default: a window hidden to the tray
/// must not stay unlocked forever just because Settings was never opened.
pub const DEFAULT_AUTOLOCK_MINS: u64 = 15;
pub const DEFAULT_CLIPBOARD_SECS: u64 = 15;
pub const MAX_AUTOLOCK_MINS: u64 = 120;
pub const MIN_CLIPBOARD_SECS: u64 = 5;
pub const MAX_CLIPBOARD_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiPrefs {
    pub auto_lock_mins: u64,
    pub clipboard_secs: u64,
}

impl Default for UiPrefs {
    fn default() -> Self {
        Self {
            auto_lock_mins: DEFAULT_AUTOLOCK_MINS,
            clipboard_secs: DEFAULT_CLIPBOARD_SECS,
        }
    }
}

impl UiPrefs {
    /// Keep a hand-edited or future-version file inside the ranges the UI can
    /// actually express. 0 minutes stays 0 (Never); everything else is capped.
    pub fn clamp(mut self) -> Self {
        self.auto_lock_mins = self.auto_lock_mins.min(MAX_AUTOLOCK_MINS);
        self.clipboard_secs = self
            .clipboard_secs
            .clamp(MIN_CLIPBOARD_SECS, MAX_CLIPBOARD_SECS);
        self
    }
}

/// Parse a pref document. Anything unreadable falls back to the defaults: a
/// corrupt pref must never brick the app, and must never mean "Never".
pub fn parse(text: &str) -> UiPrefs {
    serde_json::from_str::<UiPrefs>(text)
        .unwrap_or_default()
        .clamp()
}

/// Missing or unreadable file = shipped defaults (not "never lock").
pub fn load() -> UiPrefs {
    std::fs::read_to_string(PREFS_FILE)
        .map(|t| parse(&t))
        .unwrap_or_default()
}

pub fn save(p: &UiPrefs) -> Result<(), String> {
    let p = p.clamp();
    let json = serde_json::to_string_pretty(&p).map_err(|e| format!("prefs json: {e}"))?;
    let tmp = format!("{PREFS_FILE}.tmp");
    std::fs::write(&tmp, json).map_err(|e| format!("prefs write: {e}"))?;
    std::fs::rename(&tmp, PREFS_FILE).map_err(|e| format!("prefs rename: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let p = UiPrefs::default();
        assert_eq!(p.auto_lock_mins, 15);
        assert_eq!(p.clipboard_secs, 15);
    }

    #[test]
    fn corrupt_document_falls_back_to_defaults() {
        assert_eq!(parse("{not json"), UiPrefs::default());
        assert_eq!(parse(""), UiPrefs::default());
        assert_eq!(parse(r#"{"auto_lock_mins":"x"}"#), UiPrefs::default());
    }

    #[test]
    fn out_of_range_values_are_clamped() {
        let p = parse(r#"{"auto_lock_mins":9999,"clipboard_secs":1}"#);
        assert_eq!(p.auto_lock_mins, MAX_AUTOLOCK_MINS);
        assert_eq!(p.clipboard_secs, MIN_CLIPBOARD_SECS);
        let q = parse(r#"{"auto_lock_mins":15,"clipboard_secs":9999}"#);
        assert_eq!(q.clipboard_secs, MAX_CLIPBOARD_SECS);
    }

    #[test]
    fn roundtrip_keeps_the_user_choice() {
        let p = UiPrefs {
            auto_lock_mins: 1,
            clipboard_secs: 30,
        };
        let text = serde_json::to_string(&p).expect("serialize");
        assert_eq!(parse(&text), p);
    }
}
