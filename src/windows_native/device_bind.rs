//! Machine binding (rules Cat 6 — Hardware Binding).
//!
//! First unlock DPAPI-seals this machine's `MachineGuid` next to the vault.
//! Later unlocks compare: a mismatch (or an unreadable seal, which DPAPI
//! itself enforces across machines/users) raises a loud, warn-only banner —
//! never a lockout. Portable-USB use intentionally trips it; the message
//! says so. All failures fail OPEN (return "no warning") except a verified
//! mismatch, so a broken registry read can never brick a vault.

use crate::core::memory::DpapiGuard;
use crate::error::{Result, VaultError};
use std::path::Path;

const DEVICE_FILE: &str = "device.dpapi";
const SUBKEY: &str = r"SOFTWARE\Microsoft\Cryptography";
const VALUE: &str = "MachineGuid";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid.
pub fn machine_guid() -> Result<String> {
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW,
    };
    let sub = wide(SUBKEY);
    let val = wide(VALUE);
    let mut buf = [0u16; 128];
    let mut size_bytes = (buf.len() * std::mem::size_of::<u16>()) as u32;
    // SAFETY: bounded stack buffer with exact byte size; the API retains nothing.
    // (windows-sys PCWSTR/WIN32_ERROR are plain aliases: *const u16 / u32.)
    let ret = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            sub.as_ptr(),
            val.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size_bytes,
        )
    };
    if ret != 0 {
        return Err(VaultError::Security(format!(
            "MachineGuid unreadable (0x{ret:X})"
        )));
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let guid = String::from_utf16_lossy(&buf[..end]).trim().to_string();
    if guid.is_empty() {
        return Err(VaultError::Security("MachineGuid empty".into()));
    }
    Ok(guid)
}

/// Check this machine against the sealed binding at `path`.
/// Returns true ONLY when the user must be warned (verified mismatch, or a
/// present-but-unverifiable seal — DPAPI itself refuses foreign machines).
pub fn check_device_at(path: &Path) -> bool {
    let guid = match machine_guid() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let blob = match std::fs::read(path) {
        // First bind: seal silently, no warning.
        Err(_) => {
            if let Ok(sealed) = DpapiGuard::protect(guid.as_bytes()) {
                let _ = std::fs::write(path, sealed);
            }
            return false;
        }
        Ok(b) => b,
    };
    match DpapiGuard::unprotect(&blob) {
        Ok(secret) => {
            // Constant-time compare directly on the unsealed bytes: no
            // intermediate String alloc, and length feeds the accumulator
            // (no early-out length oracle).
            let a = secret.expose();
            let b = guid.trim().as_bytes();
            let mut diff = (a.len() ^ b.len()) as u8;
            for i in 0..a.len().max(b.len()) {
                let x = *a.get(i).unwrap_or(&0);
                let y = *b.get(i).unwrap_or(&0);
                diff |= x ^ y;
            }
            drop(secret);
            diff != 0
        }
        // Sealed for another machine/user — that IS the tripwire.
        Err(_) => true,
    }
}

/// Default-path entrypoint (`device.dpapi` beside the vault).
pub fn check_device() -> bool {
    check_device_at(Path::new(DEVICE_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_reads_non_empty() {
        let g = machine_guid().unwrap();
        assert!(g.len() >= 8, "MachineGuid suspiciously short: {g}");
    }

    #[test]
    fn bind_then_match_is_quiet() {
        let path = std::env::temp_dir().join(format!("pv-devbind-{}-a.dpapi", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(!check_device_at(&path), "first bind must not warn");
        assert!(path.exists(), "binding seal must be written");
        assert!(!check_device_at(&path), "same machine must not warn");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_seal_warns() {
        let path = std::env::temp_dir().join(format!("pv-devbind-{}-b.dpapi", std::process::id()));
        std::fs::write(&path, b"definitely-not-a-dpapi-blob").unwrap();
        assert!(check_device_at(&path), "unverifiable seal must warn");
        let _ = std::fs::remove_file(&path);
    }
}
