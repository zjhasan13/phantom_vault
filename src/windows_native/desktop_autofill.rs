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

/// Inspect the active desktop context. Never fails hard: worst case returns
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
}
