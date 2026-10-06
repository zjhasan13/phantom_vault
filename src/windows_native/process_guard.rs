//! Process hardening at startup (rules Cat 8).
//!
//! - DLL-injection block: `ProcessSignaturePolicy` with the always-on
//!   non-Microsoft-binaries bit. Keylogger/malware DLLs can no longer be
//!   injected into our address space (they fail at load time).
//! - Crash-dump exclusion: `WerAddExcludedApplication` keeps Windows Error
//!   Reporting from shipping full-memory dumps (with embedded secrets) to
//!   Microsoft. Bound via plain `extern "system"` (wer.dll) — no new crate.
//! - Admin-elevation probe: loud warning when running elevated.
//!
//! All three are best-effort booleans; failure never blocks startup.

/// `MicrosoftSignedOnly`: bit 0 of `PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY`.
/// Per MSDN `winnt.h` the struct is `{ union { DWORD Flags; struct {...} } }`
/// = exactly 4 bytes, so passing `size_of::<u32>()` is CORRECT (C12 audit
/// claim of "8 bytes with Version" describes a different policy family).
/// `MicrosoftSignedOnly` is the strongest self-appliable sibling: every FUTURE
/// image load must carry a Microsoft signature (delay-loaded malware DLLs,
/// rogue COM servers, and plugin droppers fail at load time).
/// Passed as the raw DWORD — ABI-identical to the Win32 struct.
const MICROSOFT_SIGNED_ONLY: u32 = 0x1;

/// Refuse non-Microsoft signed DLLs in this process. Returns true on success.
pub fn block_injected_dlls() -> bool {
    use windows_sys::Win32::System::Threading::{ProcessSignaturePolicy, SetProcessMitigationPolicy};
    let flags = MICROSOFT_SIGNED_ONLY;
    // SAFETY: 4-byte DWORD buffer, exact size passed; kernel copies it in.
    unsafe {
        SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            &flags as *const u32 as *const core::ffi::c_void,
            std::mem::size_of::<u32>(),
        ) != 0
    }
}

/// M10: best-effort extra runtime mitigations (all DWORD-sized, all
/// fail-soft). ExtensionPointDisable blocks AppInit/global-hook injection;
/// FontDisable (NonSystemFonts) blocks the font info-leak primitive;
/// StrictHandleCheck turns silent handle bugs into loud exceptions.
/// DynamicCodePolicy deliberately NOT set (JIT risk for GPU/WebView paths).
/// Returns the count applied.
pub fn harden_extra() -> u32 {
    use windows_sys::Win32::System::Threading::SetProcessMitigationPolicy;
    fn try_set(policy: i32, flags: u32) -> bool {
        // SAFETY: 4-byte DWORD buffer, exact size; kernel copies it in.
        unsafe {
            SetProcessMitigationPolicy(
                policy,
                &flags as *const u32 as *const core::ffi::c_void,
                std::mem::size_of::<u32>(),
            ) != 0
        }
    }
    let mut n = 0;
    use windows_sys::Win32::System::Threading::{
        ProcessExtensionPointDisablePolicy, ProcessFontDisablePolicy,
        ProcessStrictHandleCheckPolicy,
    };
    // DisableExtensionPoints = 1.
    if try_set(ProcessExtensionPointDisablePolicy, 0x1) {
        n += 1;
    }
    // DisableNonSystemFonts = 1 (Audit bit left off = enforce).
    if try_set(ProcessFontDisablePolicy, 0x1) {
        n += 1;
    }
    // RaiseExceptionOnInvalidHandleReference = 1.
    if try_set(ProcessStrictHandleCheckPolicy, 0x1) {
        n += 1;
    }
    n
}

#[link(name = "wer")]
extern "system" {
    fn WerAddExcludedApplication(pwz_exe_name: *const u16) -> i32;
}

/// Exclude this executable from WER crash-dump uploads. S_OK (0) = applied.
pub fn exclude_from_crash_dumps() -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let name = match exe.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: NUL-terminated buffer outlives the call; wer.dll retains nothing.
    unsafe { WerAddExcludedApplication(wide.as_ptr()) == 0 }
}

/// True when running with elevated (Administrator) rights.
pub fn is_elevated() -> bool {
    // SAFETY: parameterless read, no buffers.
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mitigations_apply_without_panic() {
        // Real OS calls; assert only "they answer and report".
        let _ = block_injected_dlls();
        let _ = harden_extra();
        let _ = exclude_from_crash_dumps();
        let _ = is_elevated();
    }

    #[test]
    fn dll_block_applies_and_reads_back() {
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetProcessMitigationPolicy, ProcessSignaturePolicy,
        };
        assert!(block_injected_dlls());
        assert!(block_injected_dlls(), "policy must be idempotent");
        // Read back through the kernel: proves the bit REALLY stuck, not just
        // that the setter returned success.
        let mut flags: u32 = 0;
        let ok = unsafe {
            GetProcessMitigationPolicy(
                GetCurrentProcess(),
                ProcessSignaturePolicy,
                &mut flags as *mut u32 as *mut core::ffi::c_void,
                std::mem::size_of::<u32>(),
            ) != 0
        };
        assert!(ok, "policy readback failed");
        assert_eq!(
            flags & MICROSOFT_SIGNED_ONLY,
            MICROSOFT_SIGNED_ONLY,
            "MicrosoftSignedOnly must stick, flags=0x{flags:X}"
        );
    }
}
