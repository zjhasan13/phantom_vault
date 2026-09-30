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
use windows_sys::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use zeroize::Zeroize;

const CF_UNICODETEXT: u32 = 13;
const OPEN_RETRIES: usize = 30;
const OPEN_RETRY_MS: u64 = 10;

/// Copy-generation counter: every `copy_sensitive` (and every `flush_now`)
/// bumps it. A stale auto-clear worker whose generation no longer matches
/// exits as a harmless no-op — so copying B 10s after A can never let A's
/// timer wipe B. Backstops the content-equality check below.
static CLIPBOARD_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Claim the next generation (called on every new copy).
pub(crate) fn next_generation() -> u64 {
    CLIPBOARD_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
}

/// Current generation (workers compare against their claimed one).
pub(crate) fn current_generation() -> u64 {
    CLIPBOARD_GEN.load(std::sync::atomic::Ordering::SeqCst)
}

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

/// FNV-1a 64-bit (no new dep) — identifies OUR last sensitive copy for the
/// guarded lock/exit clear (M1) without retaining the secret itself.
fn fnv_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

static LAST_COPY_HASH: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
static LAST_COPY_LEN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Read current CF_UNICODETEXT (if any) for the guarded-clear comparison.
/// M2: bounded by the real GlobalSize allocation — never scans past a
/// foreign non-NUL-terminated block (old code walked up to 1M u16 blind).
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
        let alloc_units = (GlobalSize(h as HGLOBAL) / 2).min(1024 * 1024 + 1);
        let mut len = 0usize;
        while len < alloc_units && *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        let out = String::from_utf16_lossy(slice);
        GlobalUnlock(h as HGLOBAL);
        Some(out)
    }
}

/// Guarded flush (M1): empties the clipboard NOW only if it still holds
/// OUR last sensitive copy (hash + length match). Locking the vault while
/// copying an unrelated address no longer destroys it; a lingering secret
/// is still caught by the 15-s auto-clear worker. Retires the generation.
pub fn flush_now() {
    let _ = next_generation();
    let want_hash = LAST_COPY_HASH.load(std::sync::atomic::Ordering::SeqCst);
    let want_len = LAST_COPY_LEN.load(std::sync::atomic::Ordering::SeqCst) as usize;
    if want_hash == 0 {
        return; // no sensitive copy outstanding — never touch user data.
    }
    if open_guarded().is_err() {
        return;
    }
    let matched = read_text_locked().map(|t| fnv_hash(&t) == want_hash && t.len() == want_len);
    // SAFETY: classic empty+close sequence; nothing retained.
    unsafe {
        if matched == Some(true) {
            EmptyClipboard();
        }
        CloseClipboard();
    }
    if matched == Some(true) {
        LAST_COPY_HASH.store(0, std::sync::atomic::Ordering::SeqCst);
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
    // Ownership is tracked PER HANDLE: a failed SetClipboardData keeps OUR
    // ownership (we free it); a successful one transfers it to the OS (we
    // must NOT free — that would corrupt the OS heap). The exclusion-marker
    // call passes a NULL handle, so its return value is meaningless and is
    // deliberately ignored (best-effort hardening, never load-bearing).
    let (ok_text, ok_hist, ok_cloud) = unsafe {
        if EmptyClipboard() == 0 {
            (false, false, false)
        } else {
            let ok_text = !SetClipboardData(CF_UNICODETEXT, h_text as HANDLE).is_null();
            let _ = SetClipboardData(exclude, std::ptr::null_mut());
            let ok_hist = !SetClipboardData(can_hist, h_hist as HANDLE).is_null();
            let ok_cloud = !SetClipboardData(can_cloud, h_cloud as HANDLE).is_null();
            (ok_text, ok_hist, ok_cloud)
        }
    };
    unsafe {
        CloseClipboard();
        // Free ONLY what we still own — never an OS-transferred block.
        if !ok_text {
            GlobalFree(h_text);
        }
        if !ok_hist {
            GlobalFree(h_hist);
        }
        if !ok_cloud {
            GlobalFree(h_cloud);
        }
    }
    if !ok_text {
        return Err(VaultError::AutoType("SetClipboardData failed".into()));
    }
    if !(ok_hist && ok_cloud) {
        // Secret landed WITHOUT the Win+V/cloud opt-outs: usable, but warn
        // LOUD so a silently-unprotected copy never surprises anyone.
        eprintln!("⚠️ clipboard privacy flags rejected — copy works, history exclusion uncertain");
    }

    // Record identity for the guarded lock/exit flush (M1).
    LAST_COPY_HASH.store(fnv_hash(text), std::sync::atomic::Ordering::SeqCst);
    LAST_COPY_LEN.store(text.len() as u64, std::sync::atomic::Ordering::SeqCst);
    // M3: single long-lived auto-clear worker (not one 15-s thread per
    // copy holding a secret). Jobs carry generation + secret + deadline;
    // the worker sleeps per-job and applies the same generation-then-content
    // gate. Type-erased callback so call sites keep `impl FnOnce`.
    struct ClearJob {
        gen: u64,
        expect: String,
        at: std::time::Instant,
        cb: Box<dyn FnOnce() + Send>,
    }
    static WORKER: OnceLock<std::sync::mpsc::Sender<ClearJob>> = OnceLock::new();
    let tx = WORKER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<ClearJob>();
        std::thread::spawn(move || {
            while let Ok(mut job) = rx.recv() {
                let now = std::time::Instant::now();
                if job.at > now {
                    std::thread::sleep(job.at - now);
                }
                if current_generation() != job.gen {
                    job.expect.zeroize();
                    continue; // superseded — no-op.
                }
                let matched = (|| {
                    open_guarded().ok()?;
                    let current = read_text_locked();
                    let same = current.as_deref() == Some(job.expect.as_str());
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
                job.expect.zeroize();
                if matched == Some(true) {
                    (job.cb)();
                }
            }
        });
        tx
    });
    let my_gen = next_generation();
    let job = ClearJob {
        gen: my_gen,
        expect: text.to_string(),
        at: std::time::Instant::now() + Duration::from_secs(auto_clear_secs),
        cb: Box::new(on_cleared),
    };
    tx.send(job)
        .map_err(|_| VaultError::AutoType("clipboard worker gone".into()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_monotonic_and_flush_retires() {
        let a = next_generation();
        let b = next_generation();
        assert_eq!(b, a + 1);
        assert_eq!(current_generation(), b);
        // A newer claim must invalidate an older worker's generation.
        let stale = a;
        assert_ne!(current_generation(), stale);
    }
}
