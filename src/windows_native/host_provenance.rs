//! A27 L1 — which image spawned the native host?
//!
//! `native_host::serve_cli` authenticates the caller's `argv[1]` origin string,
//! but that string is public: it is written to `native-host-*.json` on disk. So
//! any same-user process can spawn the host with it. This module answers the
//! second question — which executable started us — so the host can audit (step
//! 1, current) and later refuse (step 2) a spawn that did not come from a
//! browser.
//!
//! Scope: parent PID + image name only. Authenticode publisher verification is
//! the next step (`docs/A27_HOST_PAIRING.md` §3 L1); until it lands, a renamed
//! copy of `chrome.exe` still passes. Treat this as a speed bump, not a wall,
//! and never as a replacement for the Hello/PIN/reprompt gates.

/// Browsers whose native-messaging host spawn is expected. Matched on the image
/// file name only — the signature check that would make that meaningful is the
/// documented follow-up.
const BROWSER_IMAGES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "firefox.exe",
    "chromium.exe",
    "vivaldi.exe",
    "opera.exe",
];

/// Lower-case the file name and match it against the allow-list.
///
/// Pure so the matching rule is testable without a browser on the machine.
pub fn browser_from_image_path(path: &str) -> Option<&'static str> {
    let name = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .trim()
        .to_ascii_lowercase();
    BROWSER_IMAGES.iter().copied().find(|b| *b == name)
}

/// What the probe could establish about our parent process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentVerdict {
    /// Parent image is a known browser (carries the allow-list entry).
    Browser(&'static str),
    /// Parent image is something else; the path is kept for the audit log.
    NotABrowser(String),
}

/// Classify a resolved parent image path. Pure.
pub fn classify_parent_image(path: &str) -> ParentVerdict {
    match browser_from_image_path(path) {
        Some(name) => ParentVerdict::Browser(name),
        None => ParentVerdict::NotABrowser(path.to_string()),
    }
}

/// One audit-log line for the current parent. Never fails: a probe error is a
/// log line, not an error return, because step 1 must not change behaviour.
pub fn audit_line() -> String {
    match parent_image_path() {
        Ok(path) => match classify_parent_image(&path) {
            ParentVerdict::Browser(name) => format!("parent ok: {name}"),
            ParentVerdict::NotABrowser(p) => format!("WARN parent not a known browser: {p}"),
        },
        Err(e) => format!("WARN parent probe failed: {e}"),
    }
}

/// Resolve the full image path of the process that spawned us.
#[cfg(windows)]
pub fn parent_image_path() -> Result<String, String> {
    let pid = parent_pid().ok_or_else(|| "no parent pid".to_string())?;
    image_path_for_pid(pid)
}

#[cfg(not(windows))]
pub fn parent_image_path() -> Result<String, String> {
    Err("not windows".into())
}

/// Parent PID via a Toolhelp process snapshot.
#[cfg(windows)]
fn parent_pid() -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    let me = std::process::id();
    // SAFETY: snapshot handle is closed on every path below; PROCESSENTRY32W is
    // a plain out-struct with dwSize set as the API requires.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut ok = Process32FirstW(snap, &mut entry);
        while ok != 0 {
            if entry.th32ProcessID == me {
                found = Some(entry.th32ParentProcessID);
                break;
            }
            ok = Process32NextW(snap, &mut entry);
        }
        CloseHandle(snap);
        found.filter(|p| *p != 0 && *p != me)
    }
}

/// `QueryFullProcessImageNameW` for one PID.
#[cfg(windows)]
fn image_path_for_pid(pid: u32) -> Result<String, String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    const MAX_PATH_W: usize = 32768;
    // SAFETY: handle closed below; the buffer is sized for the API's documented
    // maximum and the length in/out is initialised to its capacity in WCHARs.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return Err(format!("OpenProcess({pid}) denied"));
        }
        let mut buf = vec![0u16; MAX_PATH_W];
        let mut len = MAX_PATH_W as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return Err(format!("QueryFullProcessImageNameW({pid}) failed"));
        }
        buf.truncate(len as usize);
        Ok(String::from_utf16_lossy(&buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_match_is_case_insensitive_and_strips_dirs() {
        assert_eq!(
            browser_from_image_path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Some("chrome.exe")
        );
        assert_eq!(browser_from_image_path("FIREFOX.EXE"), Some("firefox.exe"));
        assert_eq!(
            browser_from_image_path(r"D:\edge\msedge.exe"),
            Some("msedge.exe")
        );
    }

    #[test]
    fn non_browser_images_are_rejected() {
        assert_eq!(browser_from_image_path(r"C:\Windows\System32\cmd.exe"), None);
        assert_eq!(browser_from_image_path("powershell.exe"), None);
        // A directory named like a browser must not match by substring.
        assert_eq!(browser_from_image_path(r"C:\chrome.exe\evil.exe"), None);
        assert_eq!(browser_from_image_path("chrome.exe.bak"), None);
        assert_eq!(browser_from_image_path(""), None);
    }

    #[test]
    fn classify_keeps_the_path_for_the_audit_log() {
        assert_eq!(
            classify_parent_image(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
            ParentVerdict::Browser("firefox.exe")
        );
        assert_eq!(
            classify_parent_image(r"C:\Windows\System32\cmd.exe"),
            ParentVerdict::NotABrowser(r"C:\Windows\System32\cmd.exe".into())
        );
    }

    #[test]
    fn audit_line_never_panics() {
        // Whatever the parent is on this machine, the line is non-empty and
        // carries no secret — it is only a path or an error string.
        let line = audit_line();
        assert!(!line.is_empty());
    }
}
