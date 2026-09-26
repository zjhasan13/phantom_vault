//! Phase Batch-1 — DWM anti-capture guard (WDA_MONITOR).
//!
//! `WDA_MONITOR` (1) forces DWM to paint an opaque surface for our windows,
//! defeating GDI BitBlt grabbers (ShareX, Snipping Tool, PrintScreen) AND
//! DirectComposition/WGC pipelines (OBS, Zoom, Discord) alike.
//! Applied ~250ms after window creation so DWM has fully adopted the HWND.
//! Best-effort everywhere: a failed guard never breaks the app.

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows_sys::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WDA_MONITOR};

/// Apply WDA_MONITOR to a Slint window. Returns true when the OS accepted it.
pub fn guard_window(window: &slint::Window) -> bool {
    set_affinity(window, WDA_MONITOR)
}

/// Clear the affinity back to WDA_NONE (0) so screenshots work again.
/// Returns true when the OS accepted it.
pub fn clear_window(window: &slint::Window) -> bool {
    set_affinity(window, 0)
}

fn set_affinity(window: &slint::Window, affinity: u32) -> bool {
    let handle_wrapper = window.window_handle();
    let Ok(handle) = handle_wrapper.window_handle() else {
        return false;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return false;
    };
    let hwnd = win32.hwnd.get() as *mut std::ffi::c_void;
    // SAFETY: HWND came from our own live window; constant affinity flag.
    unsafe { SetWindowDisplayAffinity(hwnd as _, affinity) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wda_monitor_value_is_one() {
        assert_eq!(WDA_MONITOR, 1);
    }
}
