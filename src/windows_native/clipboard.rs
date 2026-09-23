//! Phase 20 — Win+V / Cloud-clipboard exclusion + guarded auto-clear.
//!
//! Plain `CF_UNICODETEXT` lands in Windows 10/11 clipboard history AND cloud
//! sync. We additionally publish Microsoft's official opt-out formats so
//! history monitors and cloud upload skip our payload:
//!
//! - `ExcludeClipboardContentFromMonitorProcessing` (presence marker)
//! - `CanIncludeInClipboardHistory` = DWORD 0
//! - `CanUploadToCloudClipboard` = DWORD 0
//!
//! Auto-clear only wipes when the clipboard still holds EXACTLY our secret,
//! so a newer user copy is never destroyed.
//!
//! Implemented on `windows-sys` raw handles (no `Param` trait generics).

use crate::error::{Result, VaultError};
use std::sync::OnceLock;
use std::time::Duration;
use windows_sys::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use zeroize::Zeroize;

const CF_UNICODETEXT: u32 = 13;
const OPEN_RETRIES: usize = 30;
const OPEN_RETRY_MS: u64 = 10;

fn wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn register_format(name: &str) -> Result<u32> {
    let wide = wide_null(name);
    // SAFETY: NUL-terminated buffer outlives the call.
    let id = unsafe { RegisterClipboardFormatW(wide.as_ptr()) };
    if id == 0 {
        return Err(VaultError::AutoType(format!("register clipboard format: {name}")));
    }
    Ok(id)
}

fn format_exclude() -> Result<u32> {
    static FMT: OnceLock<u32> = OnceLock::new();
    if let Some(f) = FMT.get() {
        return Ok(*f);
    }
    let f = register_format("ExcludeClipboardContentFromMonitorProcessing")?;
    let _ = FMT.set(f);
    Ok(f)
}

fn format_can_history() -> Result<u32> {
    static FMT: OnceLock<u32> = OnceLock::new();
    if let Some(f) = FMT.get() {
        return Ok(*f);
    }
    let f = register_format("CanIncludeInClipboardHistory")?;
    let _ = FMT.set(f);
    Ok(f)
}

fn format_can_cloud() -> Result<u32> {
    static FMT: OnceLock<u32> = OnceLock::new();
    if let Some(f) = FMT.get() {
        return Ok(*f);
    }
    let f = register_format("CanUploadToCloudClipboard")?;
    let _ = FMT.set(f);
    Ok(f)
}

/// GlobalAlloc + fill a moveable block. On SetClipboardData success the OS
/// owns it; our failure paths free it via GlobalFree.
fn alloc_block(bytes: &[u8]) -> Result<HGLOBAL> {
    // SAFETY: plain byte buffer; freed below on any failure path.
    let h = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) };
    if h.is_null() {
        return Err(VaultError::AutoType("GlobalAlloc failed".into()));
    }
    unsafe {
        let ptr = GlobalLock(h) as *mut u8;
        if ptr.is_null() {
            GlobalFree(h);
            return Err(VaultError::AutoType("GlobalLock failed".into()));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        GlobalUnlock(h);
    }
    Ok(h)
}

fn open_guarded() -> Result<()> {
    for _ in 0..OPEN_RETRIES {
        // SAFETY: null HWND associates with the calling task; standard pattern.
        if unsafe { OpenClipboard(HWND::default()) } != 0 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(OPEN_RETRY_MS));
    }
    Err(VaultError::AutoType("clipboard busy".into()))
}

/// Read current CF_UNICODETEXT (if any) for the guarded-clear comparison.
fn read_text_locked() -> Option<String> {
    // SAFETY: read-only peek under an open clipboard owned by us in this fn.
    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
            return None;
        }
        let h = GetClipboardData(CF_UNICODETEXT);
        if h.is_null() {
            return None;
        }
        let ptr = GlobalLock(h as HGLOBAL) as *const u16;
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
            if len > 1024 * 1024 {
                break;
            }
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        let out = String::from_utf16_lossy(slice);
        GlobalUnlock(h as HGLOBAL);
        Some(out)
    }
}

/// Copy `text` with Win+V + cloud exclusion, then auto-clear after
/// `auto_clear_secs` — but ONLY if our secret is still on top.
/// `on_cleared` runs on the worker thread (route UI via invoke_from_event_loop).
pub fn copy_sensitive(
    text: &str,
    auto_clear_secs: u64,
    on_cleared: impl FnOnce() + Send + 'static,
) -> Result<()> {
    if text.is_empty() {
        return Err(VaultError::AutoType("nothing to copy".into()));
    }
    let exclude = format_exclude()?;
    let can_hist = format_can_history()?;
    let can_cloud = format_can_cloud()?;

    // UTF-16 + NUL terminator.
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    wide.push(0);
    let raw_bytes: Vec<u8> = wide.iter().flat_map(|u| u.to_le_bytes()).collect();
    let h_text = alloc_block(&raw_bytes)?;
    let h_hist = alloc_block(&0u32.to_le_bytes())?;
    let h_cloud = alloc_block(&0u32.to_le_bytes())?;
    // Scrub our stack copies ASAP; the clipboard owns the blocks on success.
    let mut raw_bytes = raw_bytes;
    raw_bytes.zeroize();
    for w in wide.iter_mut() {
        *w = 0;
    }
    drop(wide);

    open_guarded()?;
    // SAFETY: classic clipboard sequence; CloseClipboard runs in every path.
    // A null return from SetClipboardData keeps OUR ownership (we free it).
    let ok = unsafe {
        let mut ok = false;
        if EmptyClipboard() != 0
            && !SetClipboardData(CF_UNICODETEXT, h_text as HANDLE).is_null()
            // Presence marker: null handle tells monitors to ignore us.
            && !SetClipboardData(exclude, std::ptr::null_mut()).is_null()
            && !SetClipboardData(can_hist, h_hist as HANDLE).is_null()
            && !SetClipboardData(can_cloud, h_cloud as HANDLE).is_null()
        {
            ok = true;
        }
        CloseClipboard();
        ok
    };
    if !ok {
        // Ownership never transferred — free our blocks (best effort).
        unsafe {
            GlobalFree(h_text);
            GlobalFree(h_hist);
            GlobalFree(h_cloud);
        }
        return Err(VaultError::AutoType("SetClipboardData failed".into()));
    }

    // Guarded auto-clear on a worker thread (never blocks UI).
    let mut expect = text.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(auto_clear_secs));
        let matched = (|| {
            open_guarded().ok()?;
            let current = read_text_locked();
            let same = current.as_deref() == Some(expect.as_str());
            if same {
                unsafe {
                    EmptyClipboard();
                }
            }
            unsafe {
                CloseClipboard();
            }
            Some(same)
        })();
        expect.zeroize();
        if matched == Some(true) {
            on_cleared();
        }
    });
    Ok(())
}
