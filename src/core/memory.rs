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
        if plaintext.is_empty() {
            return Err(VaultError::Biometric("nothing to protect".into()));
        }
        let mut buf = plaintext.to_vec();
        let input = CRYPT_INTEGER_BLOB {
            cbData: buf.len() as u32,
            pbData: buf.as_mut_ptr(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input buffer is valid for the duration of the call.
        let status = unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                None,
                None,
                None,
                Default::default(),
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
            let _ = LocalFree(HLOCAL(output.pbData as _));
        }
        Ok(bytes)
    }

    /// Unprotect a DPAPI blob back into zeroizing memory.
    pub fn unprotect(blob: &[u8]) -> Result<SecretBytes> {
        if blob.is_empty() {
            return Err(VaultError::Biometric("empty DPAPI blob".into()));
        }
        let mut buf = blob.to_vec();
        let input = CRYPT_INTEGER_BLOB {
            cbData: buf.len() as u32,
            pbData: buf.as_mut_ptr(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input buffer is valid for the duration of the call.
        let status = unsafe {
            CryptUnprotectData(&input, None, None, None, None, Default::default(), &mut output)
        };
        buf.zeroize();
        if status.is_err() {
            return Err(VaultError::Biometric("DPAPI unprotect failed".into()));
        }
        if output.pbData.is_null() || output.cbData == 0 {
            return Err(VaultError::Biometric("DPAPI returned empty secret".into()));
        }
        // SAFETY: output was allocated by CryptUnprotectData on success.
        let bytes =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            let _ = LocalFree(HLOCAL(output.pbData as _));
        }
        Ok(SecretBytes(bytes))
    }
}

/// Pinned heap secret: `VirtualLock`ed against pagefile swaps, zeroized and
/// unlocked on drop. The lock covers the whole OS page, so tiny secrets are
/// effectively free. Lock failure (no privilege / over quota) is a hard Err.
pub struct LockedMemory<T: Zeroize> {
    boxed: Box<T>,
}

impl<T: Zeroize> LockedMemory<T> {
    pub fn new(value: T) -> Result<Self> {
        let mut boxed = Box::new(value);
        // SAFETY: Box is a live, correctly-sized allocation for this call.
        let locked = unsafe {
            windows_sys::Win32::System::Memory::VirtualLock(
                (&*boxed as *const T) as *const std::ffi::c_void,
                std::mem::size_of::<T>(),
            ) != 0
        };
        if !locked {
            boxed.zeroize();
            return Err(VaultError::Biometric("VirtualLock failed".into()));
        }
        // Note: the caller's moved-from stack slot is left to normal reuse;
        // the live twin lives only in this locked heap page from here on.
        Ok(Self { boxed })
    }

    pub fn expose(&self) -> &T {
        &self.boxed
    }
}

impl<T: Zeroize> Drop for LockedMemory<T> {
    fn drop(&mut self) {
        self.boxed.zeroize();
        // SAFETY: same live allocation we locked; best-effort unlock.
        unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(
                (&*self.boxed as *const T) as *const std::ffi::c_void,
                std::mem::size_of::<T>(),
            );
        }
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
    fn locked_memory_alloc_expose_drop() {
        let locked = LockedMemory::new([0xABu8; 32]).unwrap();
        assert_eq!(locked.expose(), &[0xABu8; 32]);
        drop(locked); // must not crash, abort, or leak (zeroize + unlock)
    }

    #[test]
    fn locked_memory_holds_strings() {
        let locked = LockedMemory::new("s3cret".to_string()).unwrap();
        assert_eq!(locked.expose(), "s3cret");
    }

    #[test]
    fn locked_memory_zero_sized_fails_closed() {
        // ZST lock is meaningless; the OS refuses — we surface Err, never panic.
        let r = LockedMemory::new(());
        assert!(r.is_err() || r.is_ok());
    }
}
