//! Phase 22 — Desktop in-line context inspector + Smart-Grab capture.
//!
//! Uses UI Automation to answer: "is a password field focused right now,
//! in which app, and is there a username next door?" Everything is
//! best-effort — any COM/UIA failure degrades to app-name + title only,
//! never a panic, never a crash. Runs on worker threads (COM MTA).

use crate::error::{Result, VaultError};
use windows::core::BSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationTreeWalker,
    IUIAutomationValuePattern, UIA_EditControlTypeId, UIA_ValuePatternId,
};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId};

#[derive(Debug, Default, Clone)]
pub struct DesktopContext {
    pub app_name: String,
    /// Raw executable stem (no `.exe`, e.g. `chrome`) for spoof checks.
    pub exe_name: String,
    pub window_title: String,
    pub detected_username: String,
    pub is_password_focused: bool,
}

struct ComGuard;

impl ComGuard {
    fn enter() -> Result<Self> {
        // SAFETY: balanced with CoUninitialize in Drop, same thread.
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(|e| VaultError::AutoType(format!("COM init failed: {e}")))?;
        }
        Ok(ComGuard)
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

fn automation() -> Result<IUIAutomation> {
    // SAFETY: standard COM activation; errors mapped, never unwrapped.
    unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| VaultError::AutoType(format!("UIA create failed: {e}")))
}

fn bstr_to_string(b: BSTR) -> String {
    String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(b.as_ptr(), b.len())
    })
    .trim()
    .to_string()
}

fn foreground_window() -> Option<HWND> {
    // SAFETY: no buffers; null means "no foreground window".
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.0.is_null() {
        None
    } else {
        Some(hwnd)
    }
}

fn window_title(hwnd: HWND) -> String {
    let mut buf = [0u16; 512];
    // SAFETY: bounded buffer, length-checked.
    let n = unsafe { GetWindowTextW(hwnd, &mut buf) };
    String::from_utf16_lossy(&buf[..n as usize]).trim().to_string()
}

fn process_exe_name(hwnd: HWND) -> String {
    // SAFETY: out-param pid + handle closed deterministically.
    unsafe {
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return String::new();
        }
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).unwrap_or_default();
        if handle.0.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 512];
        let n = GetProcessImageFileNameW(handle, &mut buf);
        let _ = windows::Win32::Foundation::CloseHandle(handle);
        if n == 0 {
            return String::new();
        }
        let full = String::from_utf16_lossy(&buf[..n as usize]);
        full.rsplit(['\\', '/'])
            .next()
            .unwrap_or("")
            .trim_end_matches(".exe")
            .to_string()
    }
}

/// Clean "Discord" / "Steam" style service name from exe + title.
pub fn pretty_service_name(exe: &str, title: &str) -> String {
    let base = if !exe.is_empty() {
        exe
    } else {
        // Fallback: first long token of the window title.
        title
            .split(['-', '|', '–', ':'])
            .map(str::trim)
            .find(|t| t.len() >= 3)
            .unwrap_or(title)
    };
    let mut chars = base.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn is_password(el: &IUIAutomationElement) -> bool {
    // SAFETY: read-only UIA property; any failure = "not a password field".
    unsafe { el.CurrentIsPassword().map(|b| b.as_bool()).unwrap_or(false) }
}

fn element_value(el: &IUIAutomationElement) -> String {
    // SAFETY: pattern query; missing pattern = empty string.
    unsafe {
        el.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
            .and_then(|p| p.CurrentValue())
            .map(bstr_to_string)
            .unwrap_or_default()
    }
}

fn is_edit(el: &IUIAutomationElement) -> bool {
    // SAFETY: read-only UIA property.
    unsafe {
        el.CurrentControlType()
            .map(|t| t == UIA_EditControlTypeId)
            .unwrap_or(false)
    }
}

/// Hunt a neighboring non-password Edit and read its value (the username).
fn hunt_username(auto: &IUIAutomation, focused: &IUIAutomationElement) -> String {
    // SAFETY: walker navigation; every step is fallible and degrades to "".
    unsafe {
        let walker: IUIAutomationTreeWalker = match auto.CreateTrueCondition().and_then(|cond| {
            auto.CreateTreeWalker(&cond)
        }) {
            Ok(w) => w,
            Err(_) => return String::new(),
        };
        let parent = match walker.GetParentElement(focused) {
            Ok(p) => p,
            Err(_) => return String::new(),
        };
        // Direct value on the focused control itself (some apps label it).
        if !is_password(focused) {
            let v = element_value(focused);
            if !v.is_empty() {
                return v;
            }
        }
        let mut child = match walker.GetFirstChildElement(&parent) {
            Ok(c) => c,
            Err(_) => return String::new(),
        };
        for _ in 0..24 {
            if is_edit(&child) && !is_password(&child) {
                let v = element_value(&child);
                if !v.is_empty() {
                    return v;
                }
                // Empty edit: remember name as a hint, keep scanning for value.
                let name: String = child
                    .CurrentName()
                    .map(bstr_to_string)
                    .unwrap_or_default();
                if !name.is_empty() && name.len() < 64 {
                    return name;
                }
            }
            child = match walker.GetNextSiblingElement(&child) {
                Ok(n) => n,
                Err(_) => break,
            };
        }
        String::new()
    }
}

/// Executable typosquat / leetspeak guard (desktop phishing parity).
/// Normalizes leet-speak (`0→o`, `1→l`, …), collapses doubled letters
/// (`diiscord→discord`), and flags non-ASCII homoglyph stems. Returns the
/// impersonated brand when the stem is NOT the genuine name itself.
/// Pure — unit tested. `Some` means "refuse autofill".
pub fn executable_spoof_brand(exe: &str) -> Option<&'static str> {
    const KNOWN: &[(&str, &str)] = &[
        ("chrome", "Chrome"), ("chromium", "Chromium"), ("firefox", "Firefox"),
        ("msedge", "Edge"), ("edge", "Edge"), ("brave", "Brave"), ("opera", "Opera"),
        ("vivaldi", "Vivaldi"), ("discord", "Discord"), ("steam", "Steam"),
        ("spotify", "Spotify"), ("telegram", "Telegram"), ("whatsapp", "WhatsApp"),
        ("slack", "Slack"), ("zoom", "Zoom"), ("teams", "Teams"), ("outlook", "Outlook"),
        ("code", "VS Code"), ("vscode", "VS Code"), ("bitwarden", "Bitwarden"),
        ("1password", "1Password"), ("keepass", "KeePass"), ("keepassxc", "KeePassXC"),
        ("protonvpn", "Proton VPN"), ("github", "GitHub Desktop"),
    ];
    fn leet(c: char, one_as_i: bool) -> char {
        match c {
            // '1' is ambiguous (l vs i): callers try both readings.
            '1' if one_as_i => 'i',
            '1' => 'l',
            '0' => 'o', '3' => 'e', '4' => 'a',
            '5' => 's', '7' => 't', '8' => 'b', '@' => 'a', '$' => 's',
            _ => c,
        }
    }
    fn normalize(raw: &str, one_as_i: bool) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut prev = '\0';
        for c in raw.chars().filter(|c| c.is_alphanumeric()) {
            let c = leet(c.to_ascii_lowercase(), one_as_i);
            if c != prev {
                out.push(c);
            }
            prev = c;
        }
        out
    }
    let raw = exe.trim().trim_end_matches(".exe").to_lowercase();
    if raw.is_empty() {
        return None;
    }
    let has_non_ascii = !raw.is_ascii();
    // Genuine check on the RAW ascii stem (no leet, no collapse): an exact
    // match is the real binary — or an exact-name collision, which is the
    // OS's problem, not ours.
    let ascii_raw: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    // Leet-normalized + doubles-collapsed attacker views (both '1' readings).
    let norms = [normalize(&raw, false), normalize(&raw, true)];
    // Homoglyph skeleton: non-ASCII lookalikes stripped (сhrome → hrome).
    let skeleton: String = norms[0].chars().filter(|c| c.is_ascii()).collect();
    fn is_subsequence(needle: &str, hay: &str) -> bool {
        let mut hn = hay.chars();
        needle.chars().all(|n| hn.any(|h| h == n))
    }
    for (stem, brand) in KNOWN {
        if ascii_raw == *stem && !has_non_ascii {
            return None;
        }
        if norms.iter().any(|n| n == stem) {
            return Some(brand);
        }
        // сhrome-style: non-ASCII present and the skeleton is the brand
        // minus ≤2 smuggled glyphs.
        if has_non_ascii
            && skeleton.len() + 2 >= stem.len()
            && is_subsequence(&skeleton, stem)
        {
            return Some(brand);
        }
    }
    None
}

/// OTP-screen matcher: names, labels, or automation IDs containing any of
/// these (case-insensitive) mark a 2FA/OTP input. Pure — unit tested.
pub fn otp_like(name: &str, automation_id: &str) -> bool {
    const KEYS: &[&str] = &[
        "2fa",
        "otp",
        "onetime",
        "one-time",
        "verification",
        "verify",
        "authenticator",
        "2-step",
        "twostep",
        "two-factor",
        "twofactor",
        "securitycode",
        "security-code",
        "mfacode",
    ];
    // Bare "code" only counts with an auth-ish neighbor word to avoid matching
    // "postal code", "promo code", "country code", "area code", etc.
    const CODE_NEIGHBORS: &[&str] = &[
        "auth", "verif", "2fa", "otp", "factor", "token", "login", "sign", "secur",
    ];
    let hay = format!("{name} {automation_id}").to_lowercase();
    if KEYS.iter().any(|k| hay.contains(k)) {
        return true;
    }
    if hay.contains("code") {
        let stripped = hay.replace("code", " ");
        if CODE_NEIGHBORS.iter().any(|n| stripped.contains(n)) {
            return true;
        }
        // "enter the 6-digit code" style prompts.
        if stripped.contains("digit") || stripped.contains("6") {
            return true;
        }
    }
    false
}

/// Scan the foreground window subtree (capped) for an OTP input.
/// Returns true on the first match. Best-effort; false = keep watching.
pub fn otp_screen_visible() -> bool {
    let Ok(_com) = ComGuard::enter() else {
        return false;
    };
    let auto = match automation() {
        Ok(a) => a,
        Err(_) => return false,
    };
    // SAFETY: every UIA step is fallible and degrades to false.
    unsafe {
        let hwnd = match foreground_window() {
            Some(h) => h,
            None => return false,
        };
        let root: IUIAutomationElement = match auto.ElementFromHandle(hwnd) {
            Ok(el) => el,
            Err(_) => return false,
        };
        let walker = match auto
            .CreateTrueCondition()
            .and_then(|c| auto.CreateTreeWalker(&c))
        {
            Ok(w) => w,
            Err(_) => return false,
        };
        // Iterative DFS with a hard cap (never hang the watcher thread).
        let mut stack = vec![root];
        let mut visited = 0usize;
        while let Some(el) = stack.pop() {
            visited += 1;
            if visited > 400 {
                break;
            }
            let name: String = el
                .CurrentName()
                .map(bstr_to_string)
                .unwrap_or_default();
            let aid: String = el
                .CurrentAutomationId()
                .map(bstr_to_string)
                .unwrap_or_default();
            if otp_like(&name, &aid) && (is_edit(&el) || is_password(&el)) {
                return true;
            }
            // Children via first/next sibling walk (bounded).
            let mut child = match walker.GetFirstChildElement(&el) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for _ in 0..32 {
                stack.push(child.clone());
                child = match walker.GetNextSiblingElement(&child) {
                    Ok(n) => n,
                    Err(_) => break,
                };
            }
        }
        false
    }
}
/// app name + title with empty username and `is_password_focused = false`.
pub fn inspect_active_context() -> Result<DesktopContext> {
    let _com = ComGuard::enter()?;
    let mut ctx = DesktopContext::default();
    let Some(hwnd) = foreground_window() else {
        return Err(VaultError::AutoType("no foreground window".into()));
    };
    let exe = process_exe_name(hwnd);
    let title = window_title(hwnd);
    // Never capture from ourselves (would offer to save our own fields).
    let me = exe.eq_ignore_ascii_case("phantom_vault");
    ctx.app_name = pretty_service_name(&exe, &title);
    ctx.exe_name = exe;
    ctx.window_title = title;
    if me {
        return Ok(ctx);
    }
    let auto = automation()?;
    // SAFETY: focused element query; failure = no password focus.
    let focused: IUIAutomationElement =
        unsafe { auto.GetFocusedElement().map_err(|_| VaultError::AutoType("no focused element".into()))? };
    ctx.is_password_focused = is_password(&focused);
    if !is_password(&focused) {
        // Focus may sit in the username box — still useful for capture.
        let v = element_value(&focused);
        if !v.is_empty() && v.len() < 128 {
            ctx.detected_username = v;
        }
    } else {
        ctx.detected_username = hunt_username(&auto, &focused);
    }
    // Scrub absurd lengths (binary dumps in value patterns).
    if ctx.detected_username.len() > 128 {
        ctx.detected_username.clear();
    }
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_names() {
        assert_eq!(pretty_service_name("discord", "Discord"), "Discord");
        assert_eq!(pretty_service_name("", "Steam Login | Steam"), "Steam Login");
        assert_eq!(pretty_service_name("spotify", ""), "Spotify");
        assert_eq!(pretty_service_name("", ""), "");
    }

    #[test]
    fn otp_matcher_hits() {
        assert!(otp_like("Enter verification code", ""));
        assert!(otp_like("", "otp-input"));
        assert!(otp_like("2FA Token", ""));
        assert!(otp_like("Authenticator app code", ""));
        assert!(otp_like("Security Code", ""));
        assert!(otp_like("6-digit passcode", ""));
        assert!(otp_like("One-time password", ""));
    }

    #[test]
    fn otp_matcher_rejects_lookalikes() {
        assert!(!otp_like("Postal code", ""));
        assert!(!otp_like("Promo code", ""));
        assert!(!otp_like("Username", ""));
        assert!(!otp_like("Password", ""));
        assert!(!otp_like("Country", ""));
        assert!(!otp_like("", ""));
    }

    #[test]
    fn spoof_guard_catches_typosquats() {
        assert_eq!(executable_spoof_brand("chr0me"), Some("Chrome"));
        assert_eq!(executable_spoof_brand("chr0me.exe"), Some("Chrome"));
        assert_eq!(executable_spoof_brand("g00gle"), None); // unknown brand, not our list
        assert_eq!(executable_spoof_brand("diiscord"), Some("Discord"));
        assert_eq!(executable_spoof_brand("steamm"), Some("Steam"));
        assert_eq!(executable_spoof_brand("d1scord"), Some("Discord"));
        assert_eq!(executable_spoof_brand("f1refox"), Some("Firefox"));
        // Cyrillic 'с' smuggled into chrome → homoglyph spoof.
        assert_eq!(executable_spoof_brand("сhrome"), Some("Chrome"));
    }

    #[test]
    fn spoof_guard_allows_genuine_and_unrelated() {
        assert_eq!(executable_spoof_brand("chrome"), None);
        assert_eq!(executable_spoof_brand("CHROME.EXE"), None);
        assert_eq!(executable_spoof_brand("discord"), None);
        assert_eq!(executable_spoof_brand("steam"), None);
        assert_eq!(executable_spoof_brand("notepad"), None);
        assert_eq!(executable_spoof_brand("myapp"), None);
        assert_eq!(executable_spoof_brand(""), None);
        // Helper processes that merely contain a brand are NOT flagged.
        assert_eq!(executable_spoof_brand("steamwebhelper"), None);
        assert_eq!(executable_spoof_brand("chrome_updater"), None);
    }
}
