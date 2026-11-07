//! Phase 22 — Desktop in-line context inspector + Smart-Grab capture.
//!
//! Uses UI Automation to answer: "is a password field focused right now,
//! in which app, and is there a username next door?" Everything is
//! best-effort — any COM/UIA failure degrades to app-name + title only,
//! never a panic, never a crash. Runs on worker threads (COM MTA).

use crate::error::{Result, VaultError};
use windows::core::BSTR;
use windows::Win32::Foundation::{HWND, RPC_E_CHANGED_MODE};
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

struct ComGuard {
    /// True only when this call initialized COM (so Drop must balance it).
    owned: bool,
}

impl ComGuard {
    fn enter() -> Result<Self> {
        // SAFETY: balanced with CoUninitialize in Drop on the same thread, and
        // only when this call actually initialized the apartment.
        unsafe {
            let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
            if hr == RPC_E_CHANGED_MODE {
                // A16: already initialized in another apartment (Slint's STA
                // UI thread). UIA works there; just don't uninitialize it.
                return Ok(ComGuard { owned: false });
            }
            hr.ok()
                .map_err(|e| VaultError::AutoType(format!("COM init failed: {e}")))?;
        }
        Ok(ComGuard { owned: true })
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.owned {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

fn automation() -> Result<IUIAutomation> {
    // SAFETY: standard COM activation; errors mapped, never unwrapped.
    unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| VaultError::AutoType(format!("UIA create failed: {e}")))
}

fn bstr_to_string_raw(b: BSTR) -> String {
    String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(b.as_ptr(), b.len())
    })
}

fn bstr_to_string(b: BSTR) -> String {
    bstr_to_string_raw(b).trim().to_string()
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
/// multi-field forms; the password is the nearest one at/after the focused
/// field (or the nearest one before it). Pure - unit tested.
///
/// A8: without an Edit focus we no longer guess from page order - that filled
/// the login form while the user was on a signup form. Pair-fill now requires
/// the focused control to be part of the pair.
fn pick_login_pair(edits: &[(bool, bool)]) -> Option<(usize, usize)> {
    let focus = edits.iter().position(|e| e.1)?;
    let pass = if edits[focus].0 {
        focus
    } else {
        (focus..edits.len())
            .find(|&i| edits[i].0)
            .or_else(|| (0..focus).rev().find(|&i| edits[i].0))?
    };
    // Username = nearest non-password Edit ABOVE the password (tree order),
    // else the next one below it (password-above layouts).
    let user = (0..pass)
        .rev()
        .find(|&i| !edits[i].0)
        .or_else(|| (pass + 1..edits.len()).find(|&i| !edits[i].0))?;
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
    // A7: preserve whatever the user already typed in the username box. A
    // failed password write used to blank it, destroying a typed email.
    // A5: read both previous values so an ignored write can be rolled back.
    let (prev_user, prev_pass) = unsafe {
        (
            up.CurrentValue().map(bstr_to_string_raw).unwrap_or_default(),
            pp.CurrentValue().map(bstr_to_string_raw).unwrap_or_default(),
        )
    };
    // SAFETY: both patterns were validated as writable above.
    let user_ok = unsafe { up.SetValue(&BSTR::from(user.as_str())).is_ok() };
    let pass_ok = user_ok && unsafe { pp.SetValue(&BSTR::from(pass.as_str())).is_ok() };
    if user_ok && pass_ok {
        // A5: controlled inputs can accept SetValue and discard it. Only
        // report success when the new value is actually readable back. A
        // read-only value pattern (common for password boxes) keeps the old
        // trust-on-write behaviour.
        let user_read = unsafe { up.CurrentValue().ok().map(bstr_to_string_raw) };
        let pass_read = unsafe { pp.CurrentValue().ok().map(bstr_to_string_raw) };
        if value_matches(user_read.as_deref(), &user) && value_matches(pass_read.as_deref(), &pass) {
            return true;
        }
    }
    // Never leave a half-filled pair, and never destroy the old values.
    unsafe {
        let _ = up.SetValue(&BSTR::from(prev_user.as_str()));
        let _ = pp.SetValue(&BSTR::from(prev_pass.as_str()));
    }
    false
}

/// A5: did the write land? `None` means the control does not expose its value;
/// in that case keep the historical trust-on-write behaviour rather than
/// double-typing a secret.
fn value_matches(observed: Option<&str>, expected: &str) -> bool {
    observed.map(|v| v == expected).unwrap_or(true)
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
        if pattern.SetValue(&BSTR::from(sanitized.as_str())).is_err() {
            return false;
        }
        // A5: React/Electron inputs can accept SetValue and discard it. Verify
        // the value and let the caller fall back to keystrokes when it did not
        // land. A pattern that cannot be read keeps the old behaviour.
        //
        // Password boxes are exempt: their value is masked or withheld, so a
        // mismatch there would re-type a secret that did land. They usually
        // reject SetValue as read-only anyway.
        if is_password(&el) {
            return true;
        }
        let observed = pattern.CurrentValue().ok().map(bstr_to_string_raw);
        value_matches(observed.as_deref(), &sanitized)
    }
}

/// A2: is the focused control a password box? Read-only; false on any UIA
/// failure so the caller can fall back to the old keystroke path.
pub fn focused_is_password() -> bool {
    let Ok(_com) = ComGuard::enter() else { return false; };
    let Ok(auto) = automation() else { return false; };
    // SAFETY: read-only focused-element query.
    unsafe {
        let Ok(el) = auto.GetFocusedElement() else { return false; };
        is_password(&el)
    }
}

/// A12: does a field label/id look like a password/secret input?
fn password_label_like(hay: &str) -> bool {
    hay.contains("pass")
        || hay.contains("secret")
        || hay.split(|c: char| !c.is_alphanumeric())
            .any(|w| w == "pin")
}

/// A12: post-Tab check before the password is written. Returns true when the
/// control reports IsPassword *or* its label/id says password/pin/secret. UIA
/// failure returns true (cannot tell -> keep the historical behaviour).
pub fn focused_looks_like_password() -> bool {
    let Ok(_com) = ComGuard::enter() else { return true; };
    let Ok(auto) = automation() else { return true; };
    // SAFETY: read-only focused-element query.
    unsafe {
        let Ok(el) = auto.GetFocusedElement() else { return true; };
        if is_password(&el) {
            return true;
        }
        let name = el.CurrentName().map(bstr_to_string).unwrap_or_default();
        let aid = el
            .CurrentAutomationId()
            .map(bstr_to_string)
            .unwrap_or_default();
        password_label_like(&format!("{name} {aid}").to_lowercase())
    }
}

/// A11: element-level focus guard for mid-type checks. Holds COM initialized
/// for its lifetime; `still_focused` compares the *control*, not just the
/// window, so focus moving to a "show password" button or a confirm field
/// aborts instead of typing the secret there.
pub struct FocusGuard {
    _com: ComGuard,
    auto: IUIAutomation,
    target: IUIAutomationElement,
}

impl FocusGuard {
    /// Capture the currently focused control. `None` means UIA is unavailable
    /// and the caller keeps the window-only guard.
    pub fn capture() -> Option<Self> {
        let com = ComGuard::enter().ok()?;
        let auto = automation().ok()?;
        // SAFETY: read-only focused-element query.
        let target = unsafe { auto.GetFocusedElement().ok()? };
        Some(Self {
            _com: com,
            auto,
            target,
        })
    }

    /// False only when a *different* control is focused. A UIA failure returns
    /// true (cannot tell -> do not abort).
    pub fn still_focused(&self) -> bool {
        // SAFETY: read-only comparison; failures degrade to "still focused".
        unsafe {
            self.auto
                .GetFocusedElement()
                .ok()
                .and_then(|cur| self.auto.CompareElements(&cur, &self.target).ok())
                .map(|b| b.as_bool())
                .unwrap_or(true)
        }
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
                // A15: an empty edit's *name* is a label or placeholder
                // ("Email address"), not a value. Keep scanning and return ""
                // rather than saving that as the username.
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
/// these (case-insensitive) mark a 2FA/OTP input. Pure - unit tested.
///
/// A9: card checkout fields ("Security code", CVV/CVC, expiry) are explicitly
/// rejected so a live TOTP can never be typed into a card form. An explicit
/// OTP/2FA/authenticator word still wins if both appear.
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
        "mfacode",
    ];
    // Bare "code" only counts with an auth-ish neighbor word to avoid matching
    // "postal code", "promo code", "country code", "area code", etc.
    const CODE_NEIGHBORS: &[&str] = &[
        "auth", "verif", "2fa", "otp", "factor", "token", "login", "sign",
    ];
    // A9: card-style labels. "security code" is a CVV synonym, not a TOTP.
    const CARD_TERMS: &[&str] = &[
        "cvv",
        "cvc",
        "card number",
        "card-number",
        "cardnumber",
        "expiry",
        "expiration",
        "security code",
        "security-code",
    ];
    // Unambiguous OTP wording: it outranks a card term when both are present.
    const STRONG_OTP: &[&str] = &[
        "otp",
        "2fa",
        "authenticator",
        "one-time",
        "onetime",
        "two-factor",
        "twofactor",
        "mfa",
    ];
    let hay = format!("{name} {automation_id}").to_lowercase();
    if STRONG_OTP.iter().any(|k| hay.contains(k)) {
        return true;
    }
    if CARD_TERMS.iter().any(|t| hay.contains(t)) {
        return false;
    }
    if KEYS.iter().any(|k| hay.contains(k)) {
        return true;
    }
    if hay.contains("code") {
        let stripped = hay.replace("code", " ");
        if CODE_NEIGHBORS.iter().any(|n| stripped.contains(n)) {
            return true;
        }
        // "enter the 6-digit code" style prompts. Only six digits qualify; a
        // 3-4 digit CVV prompt must not.
        if stripped.contains("6-digit") || stripped.contains("6 digit") {
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
        // A10: only type when the OTP control (or a child box of a composite
        // widget) actually has keyboard focus.
        let focused = auto.GetFocusedElement().ok();
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
            if otp_like(&name, &aid)
                && (is_edit(&el) || is_password(&el))
                && focus_within(&auto, &walker, focused.as_ref(), &el)
            {
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

/// A10: is `target` (or one of its ancestors, up to 4) the focused element?
/// Composite OTP widgets put focus on a child box; the labelled parent still
/// qualifies, so the guard does not require the label node itself to be focused.
fn focus_within(
    auto: &IUIAutomation,
    walker: &IUIAutomationTreeWalker,
    focused: Option<&IUIAutomationElement>,
    target: &IUIAutomationElement,
) -> bool {
    let Some(mut cur) = focused.cloned() else {
        return false;
    };
    for _ in 0..4 {
        // SAFETY: read-only comparison / parent walk; any failure = false.
        let same = unsafe { auto.CompareElements(&cur, target) }
            .map(|b| b.as_bool())
            .unwrap_or(false);
        if same {
            return true;
        }
        match unsafe { walker.GetParentElement(&cur) } {
            Ok(p) => cur = p,
            Err(_) => return false,
        }
    }
    false
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
        // A8: no Edit focus -> no pair (never guess between login/signup).
        assert_eq!(pick_login_pair(&[(false, false), (true, false)]), None);
        // Focus on the username / on the password.
        assert_eq!(pick_login_pair(&[(false, true), (true, false)]), Some((0, 1)));
        assert_eq!(pick_login_pair(&[(false, false), (true, true)]), Some((0, 1)));
        // Signup: email + two passwords, focus email -> the first password only.
        assert_eq!(
            pick_login_pair(&[(false, true), (true, false), (true, false)]),
            Some((0, 1))
        );
        // Signup: focus the second email block -> its own password below.
        assert_eq!(
            pick_login_pair(&[(false, false), (true, false), (false, true), (true, false)]),
            Some((2, 3))
        );
        // Unusual DOM order: password above, username below, focus password.
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
        assert!(otp_like("6-digit passcode", ""));
        assert!(otp_like("Enter the 6-digit code", ""));
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
    fn otp_matcher_rejects_card_checkout_fields() {
        // A9: a CVV box must never receive a live TOTP.
        assert!(!otp_like("Security code", ""));
        assert!(!otp_like("Card security code", "cvc"));
        assert!(!otp_like("3-digit security code", ""));
        assert!(!otp_like("CVV", "cvv-input"));
        assert!(!otp_like("Expiration date", "card-expiry"));
        // An explicit OTP word outranks the card word.
        assert!(otp_like("Security code OTP", ""));
        assert!(otp_like("Card verification code from your authenticator", ""));
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

    #[test]
    fn bstr_restore_keeps_the_typed_username_exact() {
        // A7: the rollback value must preserve whitespace the user typed,
        // while the display/compare helper still trims.
        let typed = BSTR::from("  user@example.com  ");
        assert_eq!(bstr_to_string_raw(typed.clone()), "  user@example.com  ");
        assert_eq!(bstr_to_string(typed), "user@example.com");
    }

    #[test]
    fn setvalue_readback_detects_an_ignored_write() {
        // A5: SetValue returning Ok is not proof that the value changed.
        assert!(value_matches(Some("pw"), "pw"));
        assert!(!value_matches(Some(""), "pw"));
        assert!(!value_matches(Some("old"), "pw"));
        // A pattern that does not expose its value keeps trust-on-write.
        assert!(value_matches(None, "pw"));
    }

    #[test]
    fn password_label_heuristic_rejects_shipping() {
        // A12: post-Tab check must not treat "shipping" as a PIN field.
        assert!(password_label_like("password"));
        assert!(password_label_like("confirm passcode"));
        assert!(password_label_like("user-pin"));
        assert!(password_label_like("secret answer"));
        assert!(!password_label_like("username"));
        assert!(!password_label_like("shipping address"));
        assert!(!password_label_like("email"));
        assert!(!password_label_like(""));
    }

    #[test]
    fn com_guard_can_reenter_on_the_same_thread() {
        // A16: the guard must not leak an unbalanced CoUninitialize when the
        // apartment is already initialized (RPC_E_CHANGED_MODE path).
        let first = ComGuard::enter();
        assert!(first.is_ok(), "COM init failed: {:?}", first.err().map(|e| e.to_string()));
        drop(first);
        let second = ComGuard::enter();
        assert!(second.is_ok());
    }
}
