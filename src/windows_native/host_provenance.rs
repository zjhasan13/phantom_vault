//! A27 L1 — which image spawned the native host, and is it really a browser?
//!
//! `native_host::serve_cli` authenticates the caller's `argv[1]` origin string,
//! but that string is public: it is written to `native-host-*.json` on disk. So
//! any same-user process can spawn the host with it. This module answers the
//! second question — which executable started us, and is that executable a
//! browser signed by its vendor — so the host can audit (step 1) and refuse
//! (step 2, release builds) a spawn that did not come from a browser.
//!
//! Scope: parent PID + image name + Authenticode signer
//! (`authenticode::check_file`). A copy of `chrome.exe` renamed to `chrome.exe`
//! in another folder still passes if the signature is intact and by Google —
//! that is the documented limit, not a bug: this layer stops *spawn and talk*,
//! it does not stop injection into a real browser. Never treat it as a
//! replacement for the Hello/PIN/reprompt gates.

/// Browsers whose native-messaging host spawn is expected. Matched on the image
/// file name; the signature check below makes the name meaningful.
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

/// Vendor tokens a browser image's signer must contain.
///
/// Token matching, not an exact certificate subject: the display names drift
/// (`Google LLC`, `Microsoft Corporation`, `Mozilla Corporation`,
/// `Brave Software, Inc.`, `Opera Norway AS`, …). A signed file whose signer
/// carries none of these is refused and logged with the name it did carry, so a
/// new vendor is one line here, not a bug report.
fn vendor_tokens(image: &str) -> &'static [&'static str] {
    match image {
        "chrome.exe" => &["google"],
        "msedge.exe" => &["microsoft"],
        "brave.exe" => &["brave"],
        "firefox.exe" => &["mozilla"],
        "chromium.exe" => &["google", "chromium"],
        "vivaldi.exe" => &["vivaldi"],
        "opera.exe" => &["opera"],
        _ => &[],
    }
}

/// True when `publisher` looks like the vendor that ships `image`.
///
/// Pure: the whole rule is a lower-case token test, so it is unit-tested against
/// the real certificate names without needing those browsers installed.
pub fn publisher_matches_image(image: &str, publisher: &str) -> bool {
    let name = publisher.to_ascii_lowercase();
    if name.trim().is_empty() {
        return false;
    }
    vendor_tokens(image).iter().any(|token| name.contains(token))
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

/// The full L1 answer: name, signature and vendor must all agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnVerdict {
    /// Browser image, Authenticode-trusted, signed by the expected vendor.
    Trusted {
        browser: &'static str,
        publisher: String,
    },
    /// The parent image is not a browser at all.
    NotABrowser(String),
    /// Right image name, but the file has no usable signature.
    Unsigned { browser: &'static str },
    /// A signature is present but the chain does not validate.
    Untrusted { browser: &'static str, status: i32 },
    /// Trusted signature, wrong vendor for this image.
    WrongPublisher {
        browser: &'static str,
        publisher: String,
    },
    /// The probe itself failed (no parent, access denied, non-Windows).
    Unknown(String),
}

/// Inspect the process that spawned us. Never panics; every failure is a
/// verdict the caller can log or refuse.
pub fn inspect_parent() -> SpawnVerdict {
    let path = match parent_image_path() {
        Ok(path) => path,
        Err(e) => return SpawnVerdict::Unknown(e),
    };
    match classify_parent_image(&path) {
        ParentVerdict::NotABrowser(path) => SpawnVerdict::NotABrowser(path),
        ParentVerdict::Browser(browser) => match crate::windows_native::authenticode::check_file(&path) {
            crate::windows_native::authenticode::Signature::Trusted { publisher } => {
                if publisher_matches_image(browser, &publisher) {
                    SpawnVerdict::Trusted { browser, publisher }
                } else {
                    SpawnVerdict::WrongPublisher { browser, publisher }
                }
            }
            crate::windows_native::authenticode::Signature::Unsigned => SpawnVerdict::Unsigned { browser },
            crate::windows_native::authenticode::Signature::Untrusted { status } => {
                SpawnVerdict::Untrusted { browser, status }
            }
        },
    }
}

/// One audit-log line for a verdict. Never carries vault data: a path, an image
/// name, a publisher name or an error string.
pub fn describe(verdict: &SpawnVerdict) -> String {
    match verdict {
        SpawnVerdict::Trusted { browser, publisher } => {
            format!("parent ok: {browser} signed by {publisher}")
        }
        SpawnVerdict::NotABrowser(path) => format!("WARN parent not a known browser: {path}"),
        SpawnVerdict::Unsigned { browser } => {
            format!("WARN parent {browser} has no Authenticode signature")
        }
        SpawnVerdict::Untrusted { browser, status } => {
            format!("WARN parent {browser} signature untrusted (0x{status:08x})")
        }
        SpawnVerdict::WrongPublisher { browser, publisher } => {
            format!("WARN parent {browser} signed by unexpected publisher: {publisher}")
        }
        SpawnVerdict::Unknown(why) => format!("WARN parent probe failed: {why}"),
    }
}

/// Decide whether the host must refuse this spawn.
///
/// `allow_unsigned` is the documented `PV_ALLOW_UNSIGNED_BROWSER=1` escape hatch
/// for unsigned browser forks (LibreWolf, ungoogled Chromium). It only covers a
/// *missing* signature — a wrong publisher stays refused — and it weakens this
/// layer, so the host audit-logs that it was used. A same-user process that
/// spawns the host can set the variable itself, which is exactly why L2 (the
/// pairing secret) exists.
pub fn spawn_refusal(verdict: &SpawnVerdict, allow_unsigned: bool) -> Option<String> {
    let open_from = "open the extension from Chrome, Edge, Firefox, Brave, Vivaldi or Opera";
    match verdict {
        SpawnVerdict::Trusted { .. } => None,
        SpawnVerdict::NotABrowser(_) => Some(format!(
            "native host refused: it was not started by a browser — {open_from}"
        )),
        SpawnVerdict::Unknown(_) => Some(format!(
            "native host refused: could not identify the process that started it — {open_from}"
        )),
        SpawnVerdict::Unsigned { .. } if allow_unsigned => None,
        SpawnVerdict::Unsigned { browser } => Some(format!(
            "native host refused: {browser} is not code-signed. Set PV_ALLOW_UNSIGNED_BROWSER=1 only if you built or trust this browser."
        )),
        SpawnVerdict::Untrusted { browser, .. } => Some(format!(
            "native host refused: {browser} failed the signature check — reinstall it from the official source"
        )),
        SpawnVerdict::WrongPublisher { browser, .. } => Some(format!(
            "native host refused: {browser} is signed by an unexpected publisher — reinstall it from the official source"
        )),
    }
}

/// One audit-log line for the current parent. Never fails: a probe error is a
/// log line, not an error return.
#[cfg(test)]
pub fn audit_line() -> String {
    describe(&inspect_parent())
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

    #[test]
    fn publisher_must_match_the_browser_vendor() {
        // Real certificate display names, as WinTrust reports them.
        assert!(publisher_matches_image("chrome.exe", "Google LLC"));
        assert!(publisher_matches_image("chrome.exe", "GOOGLE LLC"));
        assert!(publisher_matches_image("msedge.exe", "Microsoft Corporation"));
        assert!(publisher_matches_image("firefox.exe", "Mozilla Corporation"));
        assert!(publisher_matches_image("brave.exe", "Brave Software, Inc."));
        assert!(publisher_matches_image("vivaldi.exe", "Vivaldi Technologies AS"));
        assert!(publisher_matches_image("opera.exe", "Opera Norway AS"));
        assert!(publisher_matches_image("chromium.exe", "The Chromium Authors"));
        // A signed file is not enough: the vendor has to match the image.
        assert!(!publisher_matches_image("chrome.exe", "Microsoft Corporation"));
        assert!(!publisher_matches_image("firefox.exe", "Google LLC"));
        assert!(!publisher_matches_image("chrome.exe", ""));
        assert!(!publisher_matches_image("chrome.exe", "   "));
        assert!(!publisher_matches_image("unknown.exe", "Google LLC"));
    }

    #[test]
    fn only_a_signed_vendor_browser_is_served() {
        let trusted = SpawnVerdict::Trusted {
            browser: "chrome.exe",
            publisher: "Google LLC".into(),
        };
        assert_eq!(spawn_refusal(&trusted, false), None, "happy path serves");

        let not_browser = SpawnVerdict::NotABrowser(r"C:\tools\evil.exe".into());
        let msg = spawn_refusal(&not_browser, false).expect("refused");
        assert!(msg.contains("not started by a browser"), "{msg}");
        assert!(msg.contains("open the extension from Chrome"), "{msg}");
        // The escape hatch is for unsigned browsers only, not for any parent.
        assert!(spawn_refusal(&not_browser, true).is_some());

        let unsigned = SpawnVerdict::Unsigned {
            browser: "firefox.exe",
        };
        assert!(spawn_refusal(&unsigned, false).unwrap().contains("not code-signed"));
        assert_eq!(
            spawn_refusal(&unsigned, true),
            None,
            "PV_ALLOW_UNSIGNED_BROWSER covers a missing signature"
        );

        let untrusted = SpawnVerdict::Untrusted {
            browser: "chrome.exe",
            status: -2146762496,
        };
        assert!(spawn_refusal(&untrusted, false).unwrap().contains("signature check"));
        assert!(
            spawn_refusal(&untrusted, true).is_some(),
            "a broken chain is never allowed through"
        );

        let wrong = SpawnVerdict::WrongPublisher {
            browser: "chrome.exe",
            publisher: "Contoso Ltd".into(),
        };
        assert!(spawn_refusal(&wrong, false).unwrap().contains("unexpected publisher"));
        assert!(spawn_refusal(&wrong, true).is_some());

        let unknown = SpawnVerdict::Unknown("no parent pid".into());
        assert!(spawn_refusal(&unknown, false).unwrap().contains("could not identify"));
        assert!(spawn_refusal(&unknown, true).is_some(), "fail closed");
    }

    #[test]
    fn describe_names_the_problem_without_vault_data() {
        assert!(
            describe(&SpawnVerdict::Trusted {
                browser: "msedge.exe",
                publisher: "Microsoft Corporation".into()
            })
            .contains("signed by Microsoft")
        );
        assert!(
            describe(&SpawnVerdict::Untrusted {
                browser: "chrome.exe",
                status: -2146762496
            })
            .contains("0x800b0100")
        );
        assert!(
            describe(&SpawnVerdict::WrongPublisher {
                browser: "chrome.exe",
                publisher: "Contoso Ltd".into()
            })
            .contains("Contoso Ltd")
        );
        assert!(describe(&SpawnVerdict::Unknown("denied".into())).contains("denied"));
    }
}
