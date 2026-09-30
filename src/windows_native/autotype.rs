//! Phase 13 — Global Auto-Type via Win32 `SendInput`.
//!
//! Security upgrades over the naive spec:
//! - Clipboard is never touched (immune to clipboard sniffers / Win+V history).
//! - Pastejacking guard: CR/LF stripped from fields; only the intentional
//!   final Enter is ever sent as a control key.
//! - Timing jitter (8–28 ms) between keystrokes resists keystroke-timing analysis.
//! - Unicode path (`KEYEVENTF_UNICODE`) types symbols/non-ASCII exactly,
//!   independent of the victim layout.
//! - Pre-type focus delay lets the OS settle on the target field after minimize.

use crate::error::{Result, VaultError};
use rand::Rng;
use rand_core::OsRng;
use std::time::Duration;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    VIRTUAL_KEY, VK_RETURN, VK_TAB,
};

const FOCUS_DELAY_MS: u64 = 600;
/// Phase 17 fix: DWM minimize-animation settle before the FIRST keystroke.
/// 800ms — slower machines drop the first chars at 400ms while focus is
/// still in transit to the target window.
const SETTLE_MS: u64 = 800;
/// Phase 17 fix: down→up hold window. Below ~8ms Windows may miss KeyUp and
/// the hardware repeat kicks in (the infamous 'tttttt').
const HOLD_MIN_MS: u64 = 8;
const HOLD_MAX_MS: u64 = 15;
/// Phase 17 fix: inter-character gap.
const GAP_MIN_MS: u64 = 10;
const GAP_MAX_MS: u64 = 20;
/// Phase 17 fix: Tab transition — app needs time to move field focus.
const TAB_PRE_MS: u64 = 100;
const TAB_POST_MS: u64 = 150;

/// Pastejacking guard: strip CR/LF, NUL, DEL, ANSI escape sequences
/// (`ESC[...letter`, `ESC(...)`, lone `ESC`), and all other C0/C1 control
/// codes (including Tab — it is the field separator, never payload).
/// Printable + Unicode pass through untouched. Pure — unit tested.
pub fn sanitize_field(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Consume ANSI escape sequence bodies so `ESC[31m` etc. vanish whole.
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    // Params/intermediates until the final command byte (@..~).
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some('(') | Some(')') | Some('#') => {
                    chars.next();
                    chars.next(); // single follow-up designator byte
                }
                _ => {} // lone ESC — dropped, body already consumed as ESC itself
            }
            continue;
        }
        if ch == '\u{7f}' || ch.is_control() {
            continue;
        }
        out.push(ch);
    }
    out
}

/// Push one Rust `char` as its true UTF-16 code units — direct, untranslated.
/// Surrogate pairs (non-BMP) emit both units in order; BMP chars emit one.
/// There is deliberately NO layout table, NO shift-state, NO scan mapping:
/// `wVk = 0` + `KEYEVENTF_UNICODE` + raw `wScan` unit, byte-exact.
fn push_char(seq: &mut Vec<u16>, ch: char) {
    let mut buf = [0u16; 2];
    let units = ch.encode_utf16(&mut buf);
    seq.extend_from_slice(units);
}

/// Collect the UTF-16 units of a sanitized field, char by char.
fn field_units(raw: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for ch in sanitize_field(raw).chars() {
        push_char(&mut out, ch);
    }
    out
}

/// Build the exact key sequence: user + Tab + pass + Enter.
/// Authoritative contract of the typing order; pinned by unit tests.
#[allow(dead_code)]
pub fn build_sequence(username: &str, password: &str) -> Vec<KeyStroke> {
    let mut seq = Vec::new();
    for unit in sanitize_field(username).encode_utf16() {
        seq.push(KeyStroke::Unicode(unit));
    }
    seq.push(KeyStroke::Vk(VK_TAB));
    for unit in sanitize_field(password).encode_utf16() {
        seq.push(KeyStroke::Unicode(unit));
    }
    seq.push(KeyStroke::Vk(VK_RETURN));
    seq
}

#[allow(dead_code)]
pub enum KeyStroke {
    Unicode(u16),
    Vk(VIRTUAL_KEY),
}

/// Build a Tab-chained sequence for N fields + optional Enter.
/// Contract: field{Tab}field{Tab}…[Enter]. Pinned by unit tests.
#[allow(dead_code)]
pub fn build_tabbed_sequence(fields: &[&str], press_enter: bool) -> Vec<KeyStroke> {
    let mut seq = Vec::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            seq.push(KeyStroke::Vk(VK_TAB));
        }
        for unit in sanitize_field(f).encode_utf16() {
            seq.push(KeyStroke::Unicode(unit));
        }
    }
    if press_enter {
        seq.push(KeyStroke::Vk(VK_RETURN));
    }
    seq
}

/// Type N fields joined by Tab into the focused control (worker thread).
/// C9: target is captured BEFORE the settle sleeps; any focus change during
/// the sleep aborts, and every field re-checks (per-char for secrets).
pub fn type_fields(fields: &[&str], press_enter: bool) -> Result<()> {
    if fields.iter().all(|f| sanitize_field(f).is_empty()) {
        return Err(VaultError::AutoType("nothing to type".into()));
    }
    let expected = foreground_token();
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    std::thread::sleep(Duration::from_millis(FOCUS_DELAY_MS));
    ensure_focus(expected)?;
    let mut rng = OsRng;
    let target = expected;
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            ensure_focus(target)?;
            std::thread::sleep(Duration::from_millis(TAB_PRE_MS));
            press_vk(VK_TAB, &mut rng)?;
            std::thread::sleep(Duration::from_millis(TAB_POST_MS));
            ensure_focus(target)?;
        }
        for unit in field_units(f) {
            ensure_focus(target)?;
            press_unicode(unit, &mut rng)?;
            sleep_range(&mut rng, GAP_MIN_MS, GAP_MAX_MS);
        }
    }
    if press_enter {
        ensure_focus(target)?;
        press_vk(VK_RETURN, &mut rng)?;
    }
    Ok(())
}

/// Payment-card checkout fill: number{TAB}MM/YY{TAB}CVV (no submit).
pub fn type_card(number: &str, exp_month: &str, exp_year: &str, cvv: &str) -> Result<()> {
    let exp = if exp_month.trim().is_empty() && exp_year.trim().is_empty() {
        String::new()
    } else {
        format!("{}/{}", exp_month.trim(), exp_year.trim())
    };
    type_fields(&[number, &exp, cvv], false)
}

/// Identity/address fill: name{TAB}email{TAB}phone{TAB}address (no submit).
pub fn type_identity(full_name: &str, email: &str, phone: &str, address: &str) -> Result<()> {
    type_fields(&[full_name, email, phone, address], false)
}

fn key_input(vk: VIRTUAL_KEY, scan: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(flags),
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send_one(input: &INPUT) -> Result<()> {
    // SAFETY: fully-initialized POD, single event per call so every KeyUp is
    // individually acknowledged by the OS (no batched down/up pairs).
    let sent = unsafe { SendInput(std::slice::from_ref(input), std::mem::size_of::<INPUT>() as i32) };
    if sent != 1 {
        return Err(VaultError::AutoType("SendInput was blocked".into()));
    }
    Ok(())
}

fn sleep_range(rng: &mut OsRng, lo: u64, hi: u64) {
    let ms: u64 = rng.gen_range(lo..=hi);
    std::thread::sleep(Duration::from_millis(ms));
}

/// One full press: KeyDown → hold → KeyUp. Never batched, never skipped.
fn press_unicode(unit: u16, rng: &mut OsRng) -> Result<()> {
    send_one(&key_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE.0))?;
    sleep_range(rng, HOLD_MIN_MS, HOLD_MAX_MS);
    send_one(&key_input(
        VIRTUAL_KEY(0),
        unit,
        (KEYEVENTF_UNICODE | KEYEVENTF_KEYUP).0,
    ))?;
    Ok(())
}

fn press_vk(vk: VIRTUAL_KEY, rng: &mut OsRng) -> Result<()> {
    send_one(&key_input(vk, 0, 0))?;
    sleep_range(rng, HOLD_MIN_MS, HOLD_MAX_MS);
    send_one(&key_input(vk, 0, KEYEVENTF_KEYUP.0))?;
    Ok(())
}

/// Foreground-window token for the focus guard below. Captured BEFORE the
/// settle sleeps, re-checked after and per character: if the user Alt+Tabbed
/// mid-type, we abort instead of spraying the password into a chat box.
/// HWND reuse errs to abort (safe).
fn foreground_token() -> isize {
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
    // SAFETY: no buffers; null handle = no foreground window.
    unsafe { GetForegroundWindow().0 as isize }
}

fn ensure_focus(target: isize) -> Result<()> {
    if foreground_token() != target {
        return Err(VaultError::AutoType(
            "focus moved mid-type — aborted for safety".into(),
        ));
    }
    Ok(())
}

/// Type arbitrary text (e.g. a live TOTP code) with the same per-key
/// down/hold/up discipline. Used by the 2FA auto-chain watcher.
/// C9: same focus guard as the main paths (was unguarded).
pub fn type_text_raw(text: &str, press_enter: bool) -> Result<()> {
    let target = foreground_token();
    let mut rng = OsRng;
    for unit in field_units(text) {
        ensure_focus(target)?;
        press_unicode(unit, &mut rng)?;
        sleep_range(&mut rng, GAP_MIN_MS, GAP_MAX_MS);
    }
    if press_enter {
        ensure_focus(target)?;
        press_vk(VK_RETURN, &mut rng)?;
    }
    Ok(())
}

/// Type `username{Tab}password{Enter}` into the currently focused field.
/// Blocks the calling (worker) thread. Timing budget:
/// settle 800ms → hide-delay 600ms → per-char down/hold/up + gap →
/// Tab guards (100ms pre / 150ms post).
pub fn type_sequence(username: &str, password: &str) -> Result<()> {
    if sanitize_field(password).is_empty() {
        return Err(VaultError::AutoType("nothing to type".into()));
    }
    // C9: capture BEFORE the unguarded sleeps; Alt+Tab during settle aborts.
    let target = foreground_token();
    // 1. DWM minimize-animation settle, then the original focus delay.
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    std::thread::sleep(Duration::from_millis(FOCUS_DELAY_MS));
    ensure_focus(target)?;
    let mut rng = OsRng;
    // 2. Username, char by char (verified UTF-16 units, no translation).
    for unit in field_units(username) {
        ensure_focus(target)?;
        press_unicode(unit, &mut rng)?;
        sleep_range(&mut rng, GAP_MIN_MS, GAP_MAX_MS);
    }
    // 3. Tab transition with guards on both sides (focus re-verified:
    // the password must never land in a newly-focused chat box).
    ensure_focus(target)?;
    std::thread::sleep(Duration::from_millis(TAB_PRE_MS));
    press_vk(VK_TAB, &mut rng)?;
    std::thread::sleep(Duration::from_millis(TAB_POST_MS));
    ensure_focus(target)?;
    // 4. Password, char by char with per-char re-check.
    for unit in field_units(password) {
        ensure_focus(target)?;
        press_unicode(unit, &mut rng)?;
        sleep_range(&mut rng, GAP_MIN_MS, GAP_MAX_MS);
    }
    ensure_focus(target)?;
    press_vk(VK_RETURN, &mut rng)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_control_chars() {
        assert_eq!(sanitize_field("ab\r\ncd\nef\rg"), "abcdefg");
        assert_eq!(sanitize_field("  user  "), "  user  ");
    }

    #[test]
    fn sanitize_strips_shell_traps_and_ansi() {
        // NUL + DEL vanish.
        assert_eq!(sanitize_field("ab\0cd\x7fef"), "abcdef");
        // Full ANSI color sequence vanishes whole (no stray "[31m").
        assert_eq!(sanitize_field("pw\x1b[31m;rm -rf ~"), "pw;rm -rf ~");
        // Lone ESC + charset designator vanish.
        assert_eq!(sanitize_field("a\x1bb"), "ab");
        // Tab is the field separator, never payload.
        assert_eq!(sanitize_field("a\tb"), "ab");
        // C1 control vanishes, real Unicode survives.
        assert_eq!(sanitize_field("pässwörd\u{85}!"), "pässwörd!");
    }

    #[test]
    fn sequence_layout_is_user_tab_pass_enter() {
        let seq = build_sequence("ab", "xy");
        // a,b + Tab + x,y + Enter = 6 strokes
        assert_eq!(seq.len(), 6);
        assert!(matches!(seq[2], KeyStroke::Vk(vk) if vk == VK_TAB));
        assert!(matches!(seq[5], KeyStroke::Vk(vk) if vk == VK_RETURN));
    }

    #[test]
    fn field_units_cover_ascii_and_surrogates() {
        // 'c' must be exactly one unit 0x63 — the reported 'o' (0x6F) can
        // never arise here; any target-side morph is outside this path.
        assert_eq!(field_units("c"), vec![0x63u16]);
        assert_eq!(field_units("com"), vec![0x63, 0x6F, 0x6D]);
        // Non-BMP char → correct surrogate pair, in order.
        assert_eq!(field_units("😀"), vec![0xD83D, 0xDE00]);
        // Control chars stripped before encoding.
        assert_eq!(field_units("a\nc"), vec![0x61, 0x63]);
    }

    #[test]
    fn sequence_sanitizes_embedded_newlines() {
        let seq = build_sequence("a\nb", "x\ry");
        // newline chars must never become keystrokes
        assert_eq!(seq.len(), 6);
    }

    #[test]
    fn tabbed_sequence_chains_fields_with_tabs() {
        // card: number{TAB}exp{TAB}cvv, no Enter → 4+1+5+1+3 = 14 strokes
        let seq = build_tabbed_sequence(&["4111", "01/30", "123"], false);
        assert_eq!(seq.len(), 14);
        assert!(matches!(seq[4], KeyStroke::Vk(vk) if vk == VK_TAB));
        assert!(matches!(seq[10], KeyStroke::Vk(vk) if vk == VK_TAB));
        // identity with Enter: 1+1+1+1 chars + 3 tabs + Enter = 8
        let seq = build_tabbed_sequence(&["a", "b", "c", "d"], true);
        assert_eq!(seq.len(), 8);
        assert!(matches!(seq[7], KeyStroke::Vk(vk) if vk == VK_RETURN));
        // empty field still advances (blind checkout forms).
        let seq = build_tabbed_sequence(&["", "x"], false);
        assert_eq!(seq.len(), 2);
        assert!(matches!(seq[0], KeyStroke::Vk(vk) if vk == VK_TAB));
    }

    /// Regression test for the "c typed as o" report: proves byte-for-byte
    /// that 'c' (U+0063) is placed untranslated into wScan with wVk=0 and
    /// KEYEVENTF_UNICODE (4) down / UNICODE|KEYUP (6) up. No layout table,
    /// no shift handling, no mapping exists anywhere on this path.
    #[test]
    fn c_encodes_byte_exact() {
        // SAFETY: reading our own fully-initialized POD struct.
        unsafe {
            let down = key_input(VIRTUAL_KEY(0), 0x63, KEYEVENTF_UNICODE.0);
            let up = key_input(VIRTUAL_KEY(0), 0x63, (KEYEVENTF_UNICODE | KEYEVENTF_KEYUP).0);
            assert_eq!(down.r#type, INPUT_KEYBOARD);
            assert_eq!(down.Anonymous.ki.wVk, VIRTUAL_KEY(0));
            assert_eq!(down.Anonymous.ki.wScan, 0x63);
            assert_eq!(down.Anonymous.ki.dwFlags.0, 4);
            assert_eq!(up.Anonymous.ki.wScan, 0x63);
            assert_eq!(up.Anonymous.ki.dwFlags.0, 6);
            // Full alphabet sweep: every ASCII unit round-trips identically.
            for unit in 0x20u16..0x7Fu16 {
                let d = key_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE.0);
                assert_eq!(d.Anonymous.ki.wScan, unit, "unit {unit:#X} mangled");
            }
        }
    }
}
