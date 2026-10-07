//! System-tray integration (Windows Notification Area) + close-to-tray.
//!
//! Architecture: a dedicated worker thread owns a message-only window and
//! pumps `GetMessageW`. Single/double-click restores MainWindow; right-click
//! pops a 4-item menu (Open / QuickBar / Lock / Exit). Menu actions are
//! caller-supplied `Arc<dyn Fn()>` so this module never touches Slint types
//! (it only guarantees the callbacks run — main.rs routes them through
//! `slint::invoke_from_event_loop` itself).
//!
//! Close-to-tray (default ON, `tray_minimize.pref`): the X button minimizes
//! instead of closing — minimized windows keep the Slint loop alive, whereas
//! hiding the last window can tear it down. Working set is trimmed via
//! `EmptyWorkingSet` on minimize. Exit happens ONLY from the tray menu
//! (caller runs `panic_wipe()` first).

use std::sync::{Arc, Mutex, OnceLock};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

/// Close-to-tray preference file. Missing file = ON (spec default).
const TRAY_PREF_FILE: &str = "tray_minimize.pref";

pub fn load_tray_pref() -> bool {
    std::fs::read_to_string(TRAY_PREF_FILE)
        .map(|s| s.trim() != "0")
        .unwrap_or(true)
}

pub fn save_tray_pref(on: bool) {
    let _ = std::fs::write(TRAY_PREF_FILE, if on { "1" } else { "0" });
}

/// Trim the process working set (called after minimize-to-tray so RAM
/// drops to a few MB while the vault sits in the tray). Best-effort.
pub fn trim_working_set() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::ProcessStatus::EmptyWorkingSet;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        unsafe {
            EmptyWorkingSet(GetCurrentProcess());
        }
    }
}

/// Menu actions, supplied by main.rs (already event-loop-safe closures).
#[derive(Clone, Default)]
pub struct TrayActions {
    pub on_open: Option<Arc<dyn Fn() + Send + Sync>>,
    pub on_quickbar: Option<Arc<dyn Fn() + Send + Sync>>,
    pub on_lock: Option<Arc<dyn Fn() + Send + Sync>>,
    pub on_exit: Option<Arc<dyn Fn() + Send + Sync>>,
}

static ACTIONS: OnceLock<Arc<Mutex<TrayActions>>> = OnceLock::new();

fn actions() -> Arc<Mutex<TrayActions>> {
    ACTIONS.get_or_init(|| Arc::new(Mutex::new(TrayActions::default()))).clone()
}

pub fn set_actions(a: TrayActions) {
    if let Ok(mut g) = actions().lock() {
        *g = a;
    }
}

fn fire<F: Fn(&TrayActions) -> Option<Arc<dyn Fn() + Send + Sync>>>(pick: F) {
    if let Ok(g) = actions().lock() {
        if let Some(cb) = pick(&g) {
            cb();
        }
    }
}

/// Handle to a live tray icon (Send across threads for stop-from-anywhere).
/// Fields + `remove()` are the public teardown API — currently the process
/// exits via the tray menu (which clears the icon), full graceful-remove
/// lands with a future non-exit lock path.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct TrayHandle {
    hwnd_isize: isize,
    id: u32,
}

#[cfg(windows)]
mod win {
    use super::*;
    use windows_sys::Win32::Foundation::{
        GetLastError, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
        NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
        DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW, LoadImageW,
        PostMessageW, PostQuitMessage, RegisterClassW, SetForegroundWindow, TrackPopupMenu,
        TranslateMessage, HMENU, IDI_APPLICATION, IMAGE_ICON, LR_LOADFROMFILE,
        MF_SEPARATOR, MF_STRING, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_APP, WM_CLOSE,
        WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW,
        WS_OVERLAPPEDWINDOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::HWND_MESSAGE;

    const WM_TRAY: u32 = WM_APP + 0x7661;
    const CLASS: &[u16] = &[
        b'P' as u16, b'V' as u16, b'T' as u16, b'r' as u16, b'a' as u16, b'y' as u16, 0,
    ];
    const TIP: &str = "PhantomVault — Zero-Knowledge Native Vault";

    const M_OPEN: usize = 1;
    const M_QUICKBAR: usize = 2;
    const M_LOCK: usize = 3;
    const M_EXIT: usize = 4;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_TRAY {
            match lparam as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => {
                    fire(|a| a.on_open.clone());
                    return 0;
                }
                WM_RBUTTONUP => {
                    show_menu(hwnd);
                    return 0;
                }
                _ => {}
            }
        }
        match msg {
            WM_CLOSE => {
                DestroyWindow(hwnd);
                return 0;
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                return 0;
            }
            _ => {}
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    unsafe fn show_menu(hwnd: HWND) {
        let menu: HMENU = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let items: [(usize, &str); 4] = [
            (M_OPEN, "🔓 Open PhantomVault"),
            (M_QUICKBAR, "⚡ QuickBar (Alt+Space)"),
            (M_LOCK, "🔒 Lock Vault"),
            (M_EXIT, "❌ Exit Completely"),
        ];
        for (id, label) in items {
            AppendMenuW(menu, MF_STRING, id, wide(label).as_ptr());
        }
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd);
        let picked = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            0,
            hwnd,
            std::ptr::null(),
        );
        DestroyMenu(menu);
        // Re-arm foreground tracking (required menu-dismiss quirk).
        PostMessageW(hwnd, 0, 0, 0);
        match picked as usize {
            M_OPEN => fire(|a| a.on_open.clone()),
            M_QUICKBAR => fire(|a| a.on_quickbar.clone()),
            M_LOCK => fire(|a| a.on_lock.clone()),
            M_EXIT => fire(|a| a.on_exit.clone()),
            _ => {}
        }
    }

    unsafe fn load_icon() -> windows_sys::Win32::UI::WindowsAndMessaging::HICON {
        let path = wide("assets\\app.ico");
        let h = LoadImageW(
            std::ptr::null_mut(),
            path.as_ptr(),
            IMAGE_ICON,
            16,
            16,
            LR_LOADFROMFILE,
        );
        if !h.is_null() {
            return h as _;
        }
        LoadIconW(std::ptr::null_mut(), IDI_APPLICATION as _)
    }

    pub(super) fn spawn(actions: TrayActions) -> Result<TrayHandle, String> {
        set_actions(actions);
        let (tx, rx) = std::sync::mpsc::channel::<Result<(isize, u32), String>>();
        std::thread::spawn(move || unsafe {
            let hinstance: HINSTANCE = GetModuleHandleW(std::ptr::null());
            let wc = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinstance,
                lpszClassName: CLASS.as_ptr(),
                ..std::mem::zeroed()
            };
            if RegisterClassW(&wc) == 0 && GetLastError() != 0 {
                // ERROR_CLASS_ALREADY_EXISTS (1410) is fine — reuse it.
                if GetLastError() != 1410 {
                    let _ = tx.send(Err("tray RegisterClass failed".into()));
                    return;
                }
            }
            let hwnd = CreateWindowExW(
                0,
                CLASS.as_ptr(),
                std::ptr::null(),
                WS_OVERLAPPEDWINDOW,
                0, 0, 0, 0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                hinstance,
                std::ptr::null(),
            );
            if hwnd.is_null() {
                let _ = tx.send(Err("tray window failed".into()));
                return;
            }
            let icon = load_icon();
            let mut tip = [0u16; 128];
            for (i, c) in TIP.encode_utf16().take(127).enumerate() {
                tip[i] = c;
            }
            let nid = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: 1,
                uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
                uCallbackMessage: WM_TRAY,
                hIcon: icon,
                szTip: tip,
                ..std::mem::zeroed()
            };
            if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
                let _ = tx.send(Err("tray Shell_NotifyIcon failed".into()));
                DestroyWindow(hwnd);
                return;
            }
            let _ = tx.send(Ok((hwnd as isize, 1)));
            let mut msg = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            let nid = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: 1,
                ..std::mem::zeroed()
            };
            Shell_NotifyIconW(NIM_DELETE, &nid);
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|_| "tray thread startup timeout".to_string())?
            .map(|(hwnd_isize, id)| TrayHandle { hwnd_isize, id })
    }

    pub(super) fn remove(handle: TrayHandle) {
        unsafe {
            let nid = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: handle.hwnd_isize as HWND,
                uID: handle.id,
                ..std::mem::zeroed()
            };
            Shell_NotifyIconW(NIM_DELETE, &nid);
            PostMessageW(handle.hwnd_isize as HWND, WM_CLOSE, 0, 0);
        }
    }
}

/// Start the tray icon + message pump. Non-Windows: no-op handle.
pub fn start(actions: TrayActions) -> Result<TrayHandle, String> {
    #[cfg(windows)]
    {
        win::spawn(actions)
    }
    #[cfg(not(windows))]
    {
        let _ = actions;
        Err("tray unsupported on this platform".into())
    }
}

/// Remove the icon + stop the pump.
#[allow(dead_code)]
pub fn remove(handle: TrayHandle) {
    #[cfg(windows)]
    {
        win::remove(handle);
    }
    #[cfg(not(windows))]
    {
        let _ = handle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both action tests below mutate the process-global ACTIONS static, so
    // they must never run concurrently (parallel harness flaked ~1/8 runs:
    // fire_without_handlers reset the table between dispatch's set and fire).
    static ACTION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn tray_pref_roundtrips_without_clobbering() {
        // Preserve whatever the developer's real pref is (tests run with
        // CWD = crate root, so this file is live, not a fixture).
        let original = std::fs::read_to_string(TRAY_PREF_FILE).ok();
        save_tray_pref(false);
        assert!(!load_tray_pref());
        save_tray_pref(true);
        assert!(load_tray_pref());
        match original {
            Some(c) => {
                let _ = std::fs::write(TRAY_PREF_FILE, c);
            }
            None => {
                let _ = std::fs::remove_file(TRAY_PREF_FILE);
            }
        }
    }

    #[test]
    fn tray_actions_fire_without_handlers() {
        let _guard = ACTION_TEST_LOCK.lock().unwrap();
        // No handlers registered → fire() is a silent no-op, never panics.
        set_actions(TrayActions::default());
        fire(|a| a.on_open.clone());
        fire(|a| a.on_exit.clone());
    }

    #[test]
    fn tray_actions_dispatch() {
        let _guard = ACTION_TEST_LOCK.lock().unwrap();
        let hit = Arc::new(AtomicBool::new(false));
        let hit2 = hit.clone();
        set_actions(TrayActions {
            on_open: Some(Arc::new(move || hit2.store(true, Ordering::SeqCst))),
            ..Default::default()
        });
        fire(|a| a.on_open.clone());
        assert!(hit.load(Ordering::SeqCst));
        set_actions(TrayActions::default());
    }
}
