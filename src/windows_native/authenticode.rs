//! A27 L1 step 2 — is the image that spawned us Authenticode-signed?
//!
//! `host_provenance` answers *which* image started the native host (name only,
//! which a renamed copy defeats). This module answers *who signed it*, using the
//! two Win32 calls every Authenticode verifier needs:
//!
//! 1. `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` — does the
//!    embedded signature chain to a trusted root?
//! 2. `CryptQueryObject` → `CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)` →
//!    `CertFindCertificateInStore` → `CertGetNameStringW` — who is the signer?
//!
//! Revocation is deliberately **not** checked (`WTD_REVOKE_NONE`) and URL
//! retrieval is disabled (`WTD_CACHE_ONLY_URL_RETRIEVAL`): the host starts in a
//! Chrome-spawned child process, must not block on the network, and the vault is
//! local-first. The chain still has to reach a trusted root in the local store.
//! A revoked-but-cached certificate therefore passes; say so in `SECURITY.md`.
//!
//! This is a speed bump on the L1 path, not a sandbox: a same-user process can
//! still inject into a real browser or read the pairing secret. See
//! `docs/A27_HOST_PAIRING.md` §3.

/// What the Authenticode check established about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// `WinVerifyTrust` returned S_OK. `publisher` is the signer's simple
    /// display name, empty when it could not be read (still trusted).
    Trusted { publisher: String },
    /// A signature is present but the chain did not validate (tampered,
    /// self-signed, untrusted root). `status` is the raw `WinVerifyTrust` code
    /// for the audit log.
    Untrusted { status: i32 },
    /// No embedded signature at all.
    Unsigned,
}

/// Check one file. Never fails: an unreadable file reports `Unsigned`.
#[cfg(windows)]
pub fn check_file(path: &str) -> Signature {
    let status = trust_status(path);
    let publisher = signer_publisher(path);
    match (status, publisher) {
        (0, Some(publisher)) => Signature::Trusted { publisher },
        (0, None) => Signature::Trusted {
            publisher: String::new(),
        },
        (status, Some(_)) => Signature::Untrusted { status },
        (_, None) => Signature::Unsigned,
    }
}

#[cfg(not(windows))]
pub fn check_file(_path: &str) -> Signature {
    Signature::Unsigned
}

/// NUL-terminated UTF-16, the form every Win32 `W` API wants.
#[cfg(windows)]
fn wide_nul(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `WinVerifyTrust` over the file's embedded signature. 0 == trusted.
#[cfg(windows)]
fn trust_status(path: &str) -> i32 {
    use windows_sys::Win32::Security::WinTrust::{
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
        WINTRUST_FILE_INFO, WinVerifyTrust,
    };

    let wide = wide_nul(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    // SAFETY: every field is either zero or points at a live local for the
    // duration of both calls. `WINTRUST_DATA` is a plain C struct; the union
    // holds one pointer to `file`, which outlives the calls. The second call
    // (STATEACTION_CLOSE) releases the state data the first one allocated, which
    // the API requires even when the first call failed.
    unsafe {
        let mut data: WINTRUST_DATA = std::mem::zeroed();
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
        );
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
        );
        status
    }
}

/// Simple display name of the certificate that signed the file, e.g.
/// `Google LLC`. `None` when the file carries no readable signature.
#[cfg(windows)]
fn signer_publisher(path: &str) -> Option<String> {
    use windows_sys::Win32::Security::Cryptography::{
        CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM,
        CERT_INFO, CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
        CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject, HCERTSTORE,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let wide = wide_nul(path);
    let mut encoding = 0u32;
    let mut content = 0u32;
    let mut format = 0u32;
    let mut store: HCERTSTORE = std::ptr::null_mut();
    let mut msg: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: all handles are checked before use and released on every exit
    // path below. The signer buffer is owned by this function and outlives the
    // borrow of its `CMSG_SIGNER_INFO` view; the `CERT_INFO` passed to
    // `CertFindCertificateInStore` only borrows two blobs inside that buffer,
    // which the API reads during the call.
    unsafe {
        if CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr() as *const core::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &mut encoding,
            &mut content,
            &mut format,
            &mut store,
            &mut msg,
            std::ptr::null_mut(),
        ) == 0
        {
            return None;
        }
        let mut size = 0u32;
        if CryptMsgGetParam(
            msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            std::ptr::null_mut(),
            &mut size,
        ) == 0
            || size == 0
        {
            CryptMsgClose(msg);
            CertCloseStore(store, 0);
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if CryptMsgGetParam(
            msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
        ) == 0
        {
            CryptMsgClose(msg);
            CertCloseStore(store, 0);
            return None;
        }
        let signer = &*(buf.as_ptr() as *const CMSG_SIGNER_INFO);
        let mut info: CERT_INFO = std::mem::zeroed();
        info.Issuer = signer.Issuer;
        info.SerialNumber = signer.SerialNumber;
        let cert = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            &info as *const CERT_INFO as *const core::ffi::c_void,
            std::ptr::null(),
        );
        let mut publisher = None;
        if !cert.is_null() {
            let len = CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            );
            if len > 1 {
                let mut name = vec![0u16; len as usize];
                let got = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    std::ptr::null(),
                    name.as_mut_ptr(),
                    len,
                );
                if got > 1 {
                    name.truncate((got - 1) as usize);
                    publisher = Some(String::from_utf16_lossy(&name));
                }
            }
            CertFreeCertificateContext(cert);
        }
        CryptMsgClose(msg);
        CertCloseStore(store, 0);
        publisher
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn junk_file_reports_unsigned() {
        let dir = std::env::temp_dir().join("pv-authenticode-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("not-signed.exe");
        std::fs::write(&file, b"MZ not a real PE file").expect("write");
        let verdict = check_file(&file.to_string_lossy());
        assert!(
            matches!(verdict, Signature::Unsigned | Signature::Untrusted { .. }),
            "junk must never be Trusted: {verdict:?}"
        );
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn a_real_signed_browser_is_trusted_when_present() {
        // Uses whatever signed browser this machine has; skips on a bare box.
        // The only test that exercises the real WinTrust FFI, so a broken
        // `WINTRUST_DATA` marshalling fails here instead of in production.
        let candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
        ];
        let Some(path) = candidates
            .iter()
            .find(|p| std::path::Path::new(p).exists())
        else {
            return;
        };
        match check_file(path) {
            Signature::Trusted { publisher } => {
                let low = publisher.to_ascii_lowercase();
                assert!(
                    ["google", "microsoft", "mozilla"]
                        .iter()
                        .any(|v| low.contains(v)),
                    "unexpected publisher for {path}: {publisher}"
                );
            }
            other => panic!("expected a trusted signature on {path}: {other:?}"),
        }
    }

    #[test]
    fn missing_file_reports_unsigned() {
        let verdict = check_file(r"C:\definitely\not\here\chrome.exe");
        assert!(
            matches!(verdict, Signature::Unsigned | Signature::Untrusted { .. }),
            "missing file must never be Trusted: {verdict:?}"
        );
    }
}
