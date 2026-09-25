//! Cloud-IME keystroke shield (rules Cat 8).
//!
//! Third-party and cloud-synchronized IMEs can observe (and upload) every
//! keystroke they compose — including master passwords and pasted secrets.
//! Detaching the input context (`ImmAssociateContext(hwnd, NULL)`) makes our
//! top-level windows IME-deaf: keystrokes flow straight to Slint with no
//! composition interceptor in the middle. Applied once per window at startup
//! (the association sticks for the window lifetime); `is_detached` readback
//! proves it. Restoring passes the previous context back verbatim.

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Input::Ime::{
    ImmAssociateContext, ImmGetContext, ImmReleaseContext,
};

/// Detach (`enabled=false`) or leave attached (`enabled=true` is a no-op
/// readback — Windows owns the default context, we never fabricate one).
/// Returns true when the window ends in the requested state.
pub fn set_ime_detached(hwnd: HWND, detached: bool) -> bool {
    if !detached {
        return !is_detached(hwnd);
    }
    // SAFETY: detaching with NULL is the documented opt-out; the previous
    // context handle is intentionally dropped (window-lifetime scope).
    unsafe {
        ImmAssociateContext(hwnd, std::ptr::null_mut());
    }
    is_detached(hwnd)
}

/// Raw HWND of a Slint window (null when not yet materialized by the OS).
/// Shared by the startup guard and the focus-blur probe.
pub fn hwnd_of(window: &slint::Window) -> HWND {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    window
        .window_handle()
        .window_handle()
        .ok()
        .and_then(|h| match h.as_raw() {
            RawWindowHandle::Win32(w) => Some(w.hwnd.get() as HWND),
            _ => None,
        })
        .unwrap_or(std::ptr::null_mut())
}

/// True when no input context is associated with the window.
pub fn is_detached(hwnd: HWND) -> bool {
    // SAFETY: read-only query; the returned context must be released.
    unsafe {
        let himc = ImmGetContext(hwnd);
        let detached = himc.is_null();
        if !detached {
            ImmReleaseContext(hwnd, himc);
        }
        detached
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, RegisterClassW, CW_USEDEFAULT, WNDCLASSW,
        WS_OVERLAPPEDWINDOW,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A real (never shown) top-level window owned by this test — proves the
    /// mechanism end-to-end with zero side effects on other windows.
    /// Previous context is always restored before destroy.
    struct TestWindow {
        hwnd: HWND,
        prev: *mut core::ffi::c_void,
    }
    impl TestWindow {
        fn new() -> Option<Self> {
            let cls = wide(&format!("PvImeGuardTest{}", std::process::id()));
            let wc = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(DefWindowProcW),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: std::ptr::null_mut(),
                hIcon: std::ptr::null_mut(),
                hCursor: std::ptr::null_mut(),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: cls.as_ptr(),
            };
            // SAFETY: fully specified class, valid for both calls below.
            unsafe {
                if RegisterClassW(&wc) == 0 {
                    return None;
                }
                let hwnd = CreateWindowExW(
                    0,
                    cls.as_ptr(),
                    cls.as_ptr(),
                    WS_OVERLAPPEDWINDOW,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    64,
                    64,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if hwnd.is_null() {
                    return None;
                }
                // Save + detach in one call (documented restore pattern).
                let prev = ImmAssociateContext(hwnd, std::ptr::null_mut());
                Some(Self { hwnd, prev })
            }
        }

        fn restore(&mut self) {
            // SAFETY: re-associating the exact handle we detached.
            unsafe {
                ImmAssociateContext(self.hwnd, self.prev);
                self.prev = std::ptr::null_mut();
            }
        }
    }
    impl Drop for TestWindow {
        fn drop(&mut self) {
            // SAFETY: window created by new(); best-effort teardown.
            unsafe {
                if !self.prev.is_null() {
                    ImmAssociateContext(self.hwnd, self.prev);
                }
                DestroyWindow(self.hwnd);
            }
        }
    }

    #[test]
    fn detach_verify_restore_roundtrip() {
        let mut win = TestWindow::new().expect("test window must exist");
        assert!(is_detached(win.hwnd), "freshly detached by ctor");
        win.restore();
        assert!(!is_detached(win.hwnd), "restored context must read back");
        // And the public helper agrees end-to-end (leaves detached; the
        // window is destroyed milliseconds later by Drop).
        assert!(set_ime_detached(win.hwnd, true));
        assert!(is_detached(win.hwnd));
    }
}
