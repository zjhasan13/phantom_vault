//! DPAPI-backed protection for cached secrets + VirtualLock paged-out defense.
//!
//! - `DpapiGuard`: Windows `CryptProtectData` / `CryptUnprotectData`
//!   (current-user scope, no additional entropy). Plaintext zeroized on drop.
//! - `LockedMemory<T>`: heap secret pinned with `VirtualLock` so the OS can
//!   never page it to `pagefile.sys`; zeroized + unlocked on drop.

use crate::error::{Result, VaultError};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Zeroizing holder for unprotected secret bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

pub struct DpapiGuard;

impl DpapiGuard {
    /// Protect plaintext with DPAPI (current-user scope). Returns opaque blob.
    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
        Self::protect_inner(plaintext, None)
    }

    fn protect_inner(plaintext: &[u8], entropy: Option<&CRYPT_INTEGER_BLOB>) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Err(VaultError::Biometric("nothing to protect".into()));
        }
        let mut buf = plaintext.to_vec();
        let input = CRYPT_INTEGER_BLOB {
            cbData: buf.len() as u32,
            pbData: buf.as_mut_ptr(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input (+entropy) buffers are valid for the duration of the call.
        // C4: CRYPTPROTECT_UI_FORBIDDEN (0x1) — DPAPI must never pop UI.
        // pOptionalEntropy is Option<*const BLOB> in this windows-rs version.
        let entropy_ptr = entropy.map(|e| e as *const CRYPT_INTEGER_BLOB);
        let status = unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                entropy_ptr,
                None,
                None,
                0x1,
                &mut output,
            )
        };
        buf.zeroize();
        if status.is_err() {
            return Err(VaultError::Biometric("DPAPI protect failed".into()));
        }
        if output.pbData.is_null() || output.cbData == 0 {
            return Err(VaultError::Biometric("DPAPI returned empty blob".into()));
        }
        // SAFETY: output was allocated by CryptProtectData on success.
        let bytes =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
            let _ = LocalFree(HLOCAL(output.pbData as _));
        }
        Ok(bytes)
    }

    /// Unprotect a DPAPI blob back into zeroizing memory.
    pub fn unprotect(blob: &[u8]) -> Result<SecretBytes> {
        Self::unprotect_inner(blob, None)
    }

    /// Protect with caller-supplied `optionalEntropy` (bound at seal time,
    /// required at unseal time). Used by App PIN: the Argon2id-derived PIN
    /// key rides here, so a stolen blob alone is useless without the PIN.
    /// The entropy slice is only borrowed for the duration of the call.
    pub fn protect_with_entropy(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() || entropy.is_empty() {
            return Err(VaultError::Biometric("nothing to protect".into()));
        }
        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: entropy.len() as u32,
            pbData: entropy.as_ptr() as *mut u8,
        };
        Self::protect_inner(plaintext, Some(&entropy_blob))
    }

    /// Unprotect a blob sealed with `protect_with_entropy`. Wrong entropy ⇒
    /// OS-level failure (no plaintext, no oracle beyond fail itself).
    pub fn unprotect_with_entropy(blob: &[u8], entropy: &[u8]) -> Result<SecretBytes> {
        if blob.is_empty() || entropy.is_empty() {
            return Err(VaultError::Biometric("empty DPAPI blob".into()));
        }
        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: entropy.len() as u32,
            pbData: entropy.as_ptr() as *mut u8,
        };
        Self::unprotect_inner(blob, Some(&entropy_blob))
    }

    fn unprotect_inner(blob: &[u8], entropy: Option<&CRYPT_INTEGER_BLOB>) -> Result<SecretBytes> {
        if blob.is_empty() {
            return Err(VaultError::Biometric("empty DPAPI blob".into()));
        }
        let mut buf = blob.to_vec();
        let input = CRYPT_INTEGER_BLOB {
            cbData: buf.len() as u32,
            pbData: buf.as_mut_ptr(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input (+entropy) buffers are valid for the duration of the call.
        let entropy_ptr = entropy.map(|e| e as *const CRYPT_INTEGER_BLOB);
        let status = unsafe {
            CryptUnprotectData(&input, None, entropy_ptr, None, None, 0x1, &mut output)
        };
        buf.zeroize();
        if status.is_err() {
            return Err(VaultError::Biometric("DPAPI unprotect failed".into()));
        }
        if output.pbData.is_null() || output.cbData == 0 {
            return Err(VaultError::Biometric("DPAPI returned empty secret".into()));
        }
        // SAFETY: output was allocated by CryptUnprotectData on success.
        // M8: zero the LocalAlloc'd plaintext before freeing (else it lingers
        // in the freed heap after we copied it out).
        let bytes =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
            let _ = LocalFree(HLOCAL(output.pbData as _));
        }
        Ok(SecretBytes(bytes))
    }
}

/// Pinned secret buffer: `VirtualLock`ed against pagefile swaps, zeroized
/// and unlocked on drop. The lock covers the whole OS page, so tiny secrets
/// are effectively free. Lock failure (no privilege / over quota) is a hard
/// Err.
///
/// Replaces the old generic `LockedMemory<T>`, which pinned `size_of::<T>()`
/// at the fat pointer for heap types (24 bytes for a `String`) instead of
/// the heap bytes holding the secret. This type always pins the real buffer.
pub struct LockedBytes {
    boxed: Box<[u8]>,
}

impl LockedBytes {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        if data.is_empty() {
            return Err(VaultError::Biometric("nothing to pin".into()));
        }
        let mut boxed = data.into_boxed_slice();
        // SAFETY: live heap slice, locked for exactly its length.
        let locked = unsafe {
            windows_sys::Win32::System::Memory::VirtualLock(
                boxed.as_ptr() as *const std::ffi::c_void,
                boxed.len(),
            ) != 0
        };
        if !locked {
            boxed.zeroize();
            return Err(VaultError::Biometric("VirtualLock failed".into()));
        }
        Ok(Self { boxed })
    }

    pub fn expose_str(&self) -> &str {
        std::str::from_utf8(&self.boxed).unwrap_or("")
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        self.boxed.zeroize();
        // SAFETY: same live allocation we locked; best-effort unlock.
        unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(
                self.boxed.as_ptr() as *const std::ffi::c_void,
                self.boxed.len(),
            );
        }
    }
}

/// M9: try to enable SeLockMemoryPrivilege for this process (best-effort,
/// once). VirtualLock without it fails for normal users, making the whole
/// pagefile defense inert. Returns true when the privilege is held+enabled.
/// Callers of LockedBytes already fail LOUD (never silently unpinned).
pub fn acquire_lock_privilege() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: standard token-privilege dance; fixed-size structs, no strings
    // retained. All failures → false (caller logs a warning, never blocks).
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let name: Vec<u16> = "SeLockMemoryPrivilege\0".encode_utf16().collect();
        let mut luid = Default::default();
        if LookupPrivilegeValueW(None, windows::core::PCWSTR(name.as_ptr()), &mut luid).is_err() {
            return false;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_roundtrip() {
        let blob = DpapiGuard::protect(b"hello-dpapi-test").unwrap();
        assert!(!blob.is_empty());
        let secret = DpapiGuard::unprotect(&blob).unwrap();
        assert_eq!(secret.expose(), b"hello-dpapi-test");
    }

    #[test]
    fn dpapi_rejects_empty() {
        assert!(DpapiGuard::protect(b"").is_err());
        assert!(DpapiGuard::unprotect(&[]).is_err());
    }

    #[test]
    fn locked_bytes_pins_heap_and_exposes_str() {
        let b = LockedBytes::new(b"heap-secret".to_vec()).unwrap();
        assert_eq!(b.expose_str(), "heap-secret");
        assert!(LockedBytes::new(Vec::new()).is_err());
        drop(b); // zeroize + unlock, must not crash
    }
}
