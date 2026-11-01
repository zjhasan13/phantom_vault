//! A22 (Phase A): device-bound ML-KEM key custody for the PQ-paranoid profile.
//!
//! This slice only owns the sidecar. The container profile wiring (save/load
//! with `Argon2id + decapsulation`) lands in Phase B. Until then nothing calls
//! this module, and the portable default is untouched.
//!
//! Threat honesty: DPAPI is user+machine bound, not a TPM. A same-user process
//! can unseal this file; a TPM/CNG-backed key is the later hardening step.

use crate::core::memory::DpapiGuard;
use crate::core::pq_hybrid::{PqDecapsulationBytes, PqKeypair};

pub const PQ_DEVICE_KEY_FILE: &str = "pq_device.dpapi";

fn path() -> std::path::PathBuf {
    std::env::var("PV_PQ_DEVICE_KEY_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(PQ_DEVICE_KEY_FILE))
}

pub fn exists() -> bool {
    path().is_file()
}

/// Generate a fresh ML-KEM-768 keypair and seal the decapsulation key with
/// DPAPI. Returns the encapsulation key for the container.
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

/// Remove the sidecar (factory reset / disable). Idempotent.
pub fn clear() {
    let _ = std::fs::remove_file(path());
    let _ = std::fs::remove_file(path().with_extension("dpapi.tmp"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_key_roundtrips_and_missing_fails_closed() {
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

        clear();
        assert!(!exists());
        std::env::remove_var("PV_PQ_DEVICE_KEY_FILE");
    }
}
