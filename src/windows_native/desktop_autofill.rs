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

/// Pure policy gate for UIA `ValuePattern.SetValue` (unit tested): only an
/// enabled, writable Edit control qualifies. Password boxes usually report
/// read-only, so the caller falls back to SendInput typing.
fn uia_value_allowed(is_edit: bool, enabled: bool, read_only: bool) -> bool {
    is_edit && enabled && !read_only
}

/// P5: choose the username/password edit pair from an ordered (top-to-bottom)
/// list of `(is_password, is_focused)` descriptors. Focus disambiguates
/// multi-field forms; falls back to the first password and the nearest edit
/// above it. Pure — unit tested.
fn pick_login_pair(edits: &[(bool, bool)]) -> Option<(usize, usize)> {
    let focus = edits.iter().position(|e| e.1);
    // A focused password wins; otherwise the first password in tree order.
    let pass = focus
        .filter(|&f| edits[f].0)
        .or_else(|| edits.iter().position(|e| e.0))?;
    // Username = nearest non-password Edit ABOVE the password (tree order),
    // else the first Edit anywhere (password-above layouts).
    let user = (0..pass)
        .rev()
        .find(|&i| !edits[i].0)
        .or_else(|| edits.iter().position(|e| !e.0))?;
    if user == pass { None } else { Some((user, pass)) }
}

/// Walk the foreground window's UIA tree collecting visible Edit controls in
/// order, capped (depth 12 / 200 nodes) so a pathological tree can't stall.
fn collect_edits(
    auto: &IUIAutomation,
    walker: &IUIAutomationTreeWalker,
    root: &IUIAutomationElement,
    focused: Option<&IUIAutomationElement>,
) -> Vec<(IUIAutomationElement, bool, bool)> {
    fn walk(
        auto: &IUIAutomation,
        walker: &IUIAutomationTreeWalker,
        parent: &IUIAutomationElement,
        focused: Option<&IUIAutomationElement>,
        out: &mut Vec<(IUIAutomationElement, bool, bool)>,
        depth: u32,
    ) {
        if depth > 12 || out.len() >= 200 {
            return;
        }
        // SAFETY: walker navigation; every step is fallible and simply ends
        // that branch.
        let mut child = unsafe { walker.GetFirstChildElement(parent) };
        while let Ok(c) = child {
            // SAFETY: read-only UIA properties + element comparison.
            unsafe {
                let offscreen = c.CurrentIsOffscreen().map(|b| b.as_bool()).unwrap_or(false);
                if !offscreen && is_edit(&c) {
                    let is_focus = focused
                        .map(|f| auto.CompareElements(f, &c).map(|b| b.as_bool()).unwrap_or(false))
                        .unwrap_or(false);
                    out.push((c.clone(), is_password(&c), is_focus));
                }
            }
            walk(auto, walker, &c, focused, out, depth + 1);
            child = unsafe { walker.GetNextSiblingElement(&c) };
        }
    }
    let mut out = Vec::new();
    walk(auto, walker, root, focused, &mut out, 0);
    out
}

/// P5: pair-fill username + password in the foreground window via UIA, with no
/// Tab/focus dance (apps whose Tab order skips or wraps break keystroke fill).
/// Both targets must be enabled, writable Edits *before* any write; a partial
/// write is reverted so the keystroke fallback never duplicates. Returns true
/// only when both values landed.
pub fn fill_login_pair(username: &str, password: &str) -> bool {
    let user = crate::windows_native::autotype::sanitize_field(username);
    let pass = crate::windows_native::autotype::sanitize_field(password);
    if user.is_empty() || pass.is_empty() {
        return false;
    }
    let Ok(_com) = ComGuard::enter() else { return false; };
    let Ok(auto) = automation() else { return false; };
    let Some(hwnd) = foreground_window() else { return false; };
    // SAFETY: UIA activation/query only; failures degrade to `false`.
    let Ok(root) = (unsafe { auto.ElementFromHandle(hwnd) }) else { return false; };
    let Ok(walker) = (unsafe {
        auto.CreateTrueCondition()
            .and_then(|cond| auto.CreateTreeWalker(&cond))
    }) else {
        return false;
    };
    let focused = unsafe { auto.GetFocusedElement().ok() };
    let edits = collect_edits(&auto, &walker, &root, focused.as_ref());
    if edits.len() < 2 {
        return false;
    }
    let desc: Vec<(bool, bool)> = edits.iter().map(|(_, p, f)| (*p, *f)).collect();
    let Some((ui, pi)) = pick_login_pair(&desc) else { return false; };
    // Safety: if focus is inside an Edit, it must be one of the pair. This
    // keeps pairing from filling a chat/search box the user happened to be in.
    if let Some(f) = desc.iter().position(|e| e.1) {
        if f != ui && f != pi {
            return false;
        }
    }
    let (Some(up), Some(pp)) = (value_writable(&edits[ui].0), value_writable(&edits[pi].0))
    else {
        return false;
    };
    // SAFETY: both patterns were validated as writable above.
    unsafe {
        if up.SetValue(&BSTR::from(user.as_str())).is_err() {
            return false;
        }
        if pp.SetValue(&BSTR::from(pass.as_str())).is_err() {
            let _ = up.SetValue(&BSTR::from("")); // never leave a half-filled pair
            return false;
        }
    }
    true
}

fn value_writable(el: &IUIAutomationElement) -> Option<IUIAutomationValuePattern> {
    // SAFETY: read-only UIA property/pattern queries.
    unsafe {
        if !is_edit(el) || !el.CurrentIsEnabled().map(|b| b.as_bool()).unwrap_or(false) {
            return None;
        }
        let p = el
            .GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
            .ok()?;
        if p.CurrentIsReadOnly().map(|b| b.as_bool()).unwrap_or(true) {
            return None;
        }
        Some(p)
    }
}

/// UIA fast fill: write `value` into the currently focused Edit through
/// `ValuePattern.SetValue` — no keystrokes, no clipboard, no IME. Best-effort:
/// any missing pattern / read-only / non-edit control returns false and the
/// caller falls back to the verified Unicode SendInput path.
pub fn set_focused_value(value: &str) -> bool {
    let Ok(_com) = ComGuard::enter() else { return false; };
    let sanitized = crate::windows_native::autotype::sanitize_field(value);
    if sanitized.is_empty() {
        return false;
    }
    let Ok(auto) = automation() else { return false; };
    // SAFETY: read-only UIA queries + SetValue on the focused element; all
    // failures degrade to `false` (fallback), never panic.
    unsafe {
        let Ok(el) = auto.GetFocusedElement() else { return false; };
        let enabled = el.CurrentIsEnabled().map(|b| b.as_bool()).unwrap_or(false);
        let Ok(pattern) =
            el.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
        else {
            return false;
        };
        let read_only = pattern.CurrentIsReadOnly().map(|b| b.as_bool()).unwrap_or(true);
        if !uia_value_allowed(is_edit(&el), enabled, read_only) {
            return false;
        }
        pattern.SetValue(&BSTR::from(sanitized.as_str())).is_ok()
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
    fn uia_setvalue_policy_requires_enabled_writable_edit() {
        assert!(uia_value_allowed(true, true, false));
        assert!(!uia_value_allowed(true, true, true), "read-only password box");
        assert!(!uia_value_allowed(false, true, false), "button/link is not a field");
        assert!(!uia_value_allowed(true, false, false), "disabled control");
    }

    #[test]
    fn uia_login_pair_uses_focus_and_edit_order() {
        // Plain username above password, focus elsewhere.
        assert_eq!(pick_login_pair(&[(false, false), (true, false)]), Some((0, 1)));
        // Focus on the username / on the password.
        assert_eq!(pick_login_pair(&[(false, true), (true, false)]), Some((0, 1)));
        assert_eq!(pick_login_pair(&[(false, false), (true, true)]), Some((0, 1)));
        // Signup: email + two passwords, focus email -> first password.
        assert_eq!(
            pick_login_pair(&[(false, true), (true, false), (true, false)]),
            Some((0, 1))
        );
        // Unusual DOM order: password above, username below.
        assert_eq!(pick_login_pair(&[(true, true), (false, false)]), Some((1, 0)));
        // Incomplete forms never pair.
        assert_eq!(pick_login_pair(&[(false, false)]), None);
        assert_eq!(pick_login_pair(&[(true, false)]), None);
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
