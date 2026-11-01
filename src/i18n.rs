//! A26: tiny process-wide UI language switch for Rust-generated strings.
//!
//! Slint labels use the `ui_lang` property; this mirrors it so status strings
//! produced in Rust (import headlines, sync results, unlock status) can pick a
//! Bengali form without a gettext catalogue.

use std::sync::atomic::{AtomicBool, Ordering};

static UI_LANG_BN: AtomicBool = AtomicBool::new(false);

pub fn set_bn(on: bool) {
    UI_LANG_BN.store(on, Ordering::Relaxed);
}

pub fn is_bn() -> bool {
    UI_LANG_BN.load(Ordering::Relaxed)
}

/// Pick the Bengali or English form of a static string.
pub fn tr<'a>(en: &'a str, bn: &'a str) -> &'a str {
    if is_bn() {
        bn
    } else {
        en
    }
}
