//! A22: device-bound ML-KEM key custody for the PQ-paranoid profile.
//!
//! Phase A shipped the sidecar; Phase B wires it into the `PV3\0` container
//! profile. Nothing turns it on from the UI until Phase C (Settings toggle +
//! mandatory portable backup + sync guards).
//!
//! Threat honesty: DPAPI is user+machine bound, not a TPM. A same-user process
//! can unseal this file; a TPM/CNG-backed key is the later hardening step.

use crate::core::memory::DpapiGuard;
use crate::core::pq_hybrid::{PqDecapsulationBytes, PqKeypair};

pub const PQ_DEVICE_KEY_FILE: &str = "pq_device.dpapi";

/// Tests in different modules mutate the process-wide sidecar path, so they
/// must not run concurrently.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn path() -> std::path::PathBuf {
    std::env::var("PV_PQ_DEVICE_KEY_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(PQ_DEVICE_KEY_FILE))
}

/// Whether a device key sidecar exists. Phase C reads this to gate the
/// Settings toggle.
#[allow(dead_code)] // wired up in Phase C (UI)
pub fn exists() -> bool {
    path().is_file()
}

/// Generate a fresh ML-KEM-768 keypair and seal the decapsulation key with
/// DPAPI. Returns the encapsulation key for the container.
#[allow(dead_code)] // wired up in Phase C (explicit "create device key" step)
pub fn generate_and_seal() -> Result<Vec<u8>, String> {
    let kp: PqKeypair = crate::core::pq_hybrid::PqHybridEngine::generate_keypair();
    let decap = kp.decapsulation.expose();
    let blob = DpapiGuard::protect(decap).map_err(|e| format!("PQ key seal failed: {e}"))?;
    let p = path();
    let tmp = p.with_extension("dpapi.tmp");
    std::fs::write(&tmp, &blob).map_err(|e| format!("PQ key write: {e}"))?;
    std::fs::rename(&tmp, &p).map_err(|e| format!("PQ key swap: {e}"))?;
    Ok(kp.encapsulation)
}

/// Load the sealed decapsulation key. Missing/corrupt fails closed.
pub fn load_decapsulation() -> Result<PqDecapsulationBytes, String> {
    let blob = std::fs::read(path()).map_err(|_| "PQ device key is missing".to_string())?;
    let secret = DpapiGuard::unprotect(&blob)
        .map_err(|_| "PQ device key cannot be unsealed".to_string())?;
    Ok(PqDecapsulationBytes(secret.expose().to_vec()))
}

/// A22: unseal once and return both halves. The encapsulation key is
/// re-derived from the decapsulation key (only one secret is custodied).
pub fn load_keypair() -> Result<(Vec<u8>, PqDecapsulationBytes), String> {
    let dk = load_decapsulation()?;
    let ek = crate::core::pq_hybrid::PqHybridEngine::encapsulation_from_decapsulation(dk.expose())
        .map_err(|e| format!("PQ device key is corrupt: {e}"))?;
    Ok((ek, dk))
}

/// A22: encapsulation key for a paranoid save.
pub fn load_encapsulation() -> Result<Vec<u8>, String> {
    load_keypair().map(|(ek, _)| ek)
}

/// Remove the sidecar (factory reset / disable). Idempotent.
#[allow(dead_code)] // wired up in Phase C (factory reset / disable)
pub fn clear() {
    let _ = std::fs::remove_file(path());
    let _ = std::fs::remove_file(path().with_extension("dpapi.tmp"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_key_roundtrips_and_missing_fails_closed() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let d = std::env::temp_dir().join(format!("pv-pq-dev-{}.dpapi", std::process::id()));
        std::env::set_var("PV_PQ_DEVICE_KEY_FILE", &d);
        clear();
        assert!(load_decapsulation().is_err());

        let ek = generate_and_seal().unwrap();
        assert!(!ek.is_empty());
        let dk1 = load_decapsulation().unwrap();
        let dk2 = load_decapsulation().unwrap();
        assert_eq!(dk1.expose(), dk2.expose());
        assert!(exists());
        let (loaded_ek, _) = load_keypair().unwrap();
        assert_eq!(loaded_ek, ek);

        clear();
        assert!(!exists());
        std::env::remove_var("PV_PQ_DEVICE_KEY_FILE");
    }
}
