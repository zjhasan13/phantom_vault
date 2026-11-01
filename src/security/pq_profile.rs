//! A22: device-bound ML-KEM key custody for the PQ-paranoid profile.
//!
//! Phase D1 adds a CNG backend: production stays on DPAPI until D2 wires the
//! preference, but the `pq_device.tpm` (`PVT1`) custody path and its tests are
//! live now. Load order is strict:
//!
//! 1. `pq_device.tpm` exists → unseal it. No fallback to DPAPI on failure.
//! 2. else `pq_device.dpapi` → DPAPI (current behaviour).
//!
//! Threat honesty: DPAPI is user+machine bound; a TPM-bound key survives
//! sidecar copying but **not** same-user malware (no user-presence prompt by
//! default). Losing the TPM key or the Windows profile means data loss.

use crate::core::memory::DpapiGuard;
use crate::core::pq_hybrid::{PqDecapsulationBytes, PqKeypair};
use crate::security::pq_tpm;
use std::sync::{Mutex, OnceLock};

pub const PQ_DEVICE_KEY_FILE: &str = "pq_device.dpapi";
/// A22 D1: TPM/CNG-sealed sidecar (`PVT1`).
pub const PQ_TPM_KEY_FILE: &str = "pq_device.tpm";

/// Which custody backend a sidecar belongs to.
#[allow(dead_code)] // D2 wires TPM/Software; tests construct them today
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceBackend {
    Dpapi,
    Tpm,
    /// Test-only: CNG software KSP (same code path, no TPM).
    Software,
}

impl DeviceBackend {
    fn cng(self) -> Option<pq_tpm::Backend> {
        match self {
            Self::Dpapi => None,
            Self::Tpm => Some(pq_tpm::Backend::Tpm),
            Self::Software => Some(pq_tpm::Backend::Software),
        }
    }
}

/// Tests in different modules mutate the process-wide sidecar path, so they
/// must not run concurrently.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn path() -> std::path::PathBuf {
    std::env::var("PV_PQ_DEVICE_KEY_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(PQ_DEVICE_KEY_FILE))
}

fn tpm_path() -> std::path::PathBuf {
    std::env::var("PV_PQ_TPM_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(PQ_TPM_KEY_FILE))
}

/// Whether any device key sidecar exists.
#[allow(dead_code)] // D2 reads this for the Settings status line
pub fn exists() -> bool {
    path().is_file() || tpm_path().is_file()
}

/// D1: which backend is on disk (`None` when no sidecar). Test-only software
/// blobs report `software` so the UI can never call them hardware custody.
#[allow(dead_code)] // D2 status line
pub fn active_backend() -> Option<&'static str> {
    if let Ok(blob) = std::fs::read(tpm_path()) {
        if let Some(label) = pq_tpm::blob_backend_label(&blob) {
            return Some(label);
        }
    }
    if path().is_file() {
        return Some("dpapi");
    }
    None
}

fn write_atomic(target: &std::path::Path, blob: &[u8]) -> Result<(), String> {
    let tmp = target.with_extension("tmp");
    std::fs::write(&tmp, blob).map_err(|e| format!("PQ key write: {e}"))?;
    std::fs::rename(&tmp, target).map_err(|e| format!("PQ key swap: {e}"))?;
    Ok(())
}

/// Generate a fresh ML-KEM-768 keypair and seal the decapsulation key with
/// DPAPI (the production default until D2 switches on the TPM preference).
pub fn generate_and_seal() -> Result<Vec<u8>, String> {
    generate_and_seal_with(DeviceBackend::Dpapi)
}

/// D1: seal with an explicit backend. `Tpm`/`Software` write `pq_device.tpm`
/// and never leave a DPAPI sidecar behind.
#[allow(dead_code)] // D2 wires `Tpm` into the Settings enable flow
pub fn generate_and_seal_with(backend: DeviceBackend) -> Result<Vec<u8>, String> {
    let kp: PqKeypair = crate::core::pq_hybrid::PqHybridEngine::generate_keypair();
    let decap = kp.decapsulation.expose();
    match backend.cng() {
        None => {
            let blob = DpapiGuard::protect(decap).map_err(|e| format!("PQ key seal failed: {e}"))?;
            write_atomic(&path(), &blob)?;
        }
        Some(cng) => {
            let blob = pq_tpm::seal(cng, decap)?;
            write_atomic(&tpm_path(), &blob)?;
        }
    }
    reset_encap_cache();
    Ok(kp.encapsulation)
}

/// D3: cache of the **public** encapsulation key, keyed by the exact sidecar
/// bytes. A TPM unseal costs ~350 ms on this hardware; saves only need the
/// public key, so caching it removes the TPM op from every save without
/// keeping a secret in RAM. Invalidated on any sidecar mutation.
struct EncapsulationCache {
    from_tpm: bool,
    blob: Vec<u8>,
    encapsulation: Vec<u8>,
}

fn encap_cache() -> &'static Mutex<Option<EncapsulationCache>> {
    static CACHE: OnceLock<Mutex<Option<EncapsulationCache>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

fn reset_encap_cache() {
    *encap_cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = None;
}

/// Read the active sidecar: TPM first, DPAPI second, no fallback.
fn read_active_sidecar() -> Result<(bool, Vec<u8>), String> {
    let tpm = tpm_path();
    if tpm.is_file() {
        let blob = std::fs::read(&tpm)
            .map_err(|_| "PQ TPM device key cannot be read".to_string())?;
        return Ok((true, blob));
    }
    let p = path();
    if !p.is_file() {
        return Err("PQ device key is missing".to_string());
    }
    let blob = std::fs::read(&p).map_err(|_| "PQ device key is missing".to_string())?;
    Ok((false, blob))
}

fn unseal_sidecar(from_tpm: bool, blob: &[u8]) -> Result<Vec<u8>, String> {
    if from_tpm {
        return pq_tpm::unseal(blob);
    }
    let secret = DpapiGuard::unprotect(blob)
        .map_err(|_| "PQ device key cannot be unsealed".to_string())?;
    Ok(secret.expose().to_vec())
}

/// Load the sealed decapsulation key. A present-but-unreadable TPM sidecar is
/// terminal — it never falls back to a neighbouring DPAPI file.
pub fn load_decapsulation() -> Result<PqDecapsulationBytes, String> {
    let (from_tpm, blob) = read_active_sidecar()?;
    Ok(PqDecapsulationBytes(unseal_sidecar(from_tpm, &blob)?))
}

/// A22: unseal once and return both halves. The encapsulation key is
/// re-derived from the decapsulation key (only one secret is custodied).
#[allow(dead_code)] // kept for callers that need both halves
pub fn load_keypair() -> Result<(Vec<u8>, PqDecapsulationBytes), String> {
    let dk = load_decapsulation()?;
    let ek = crate::core::pq_hybrid::PqHybridEngine::encapsulation_from_decapsulation(dk.expose())
        .map_err(|e| format!("PQ device key is corrupt: {e}"))?;
    Ok((ek, dk))
}

/// A22: encapsulation key for a paranoid save. Cached (public key only) so a
/// slow TPM unseal happens once per sidecar, not once per save.
pub fn load_encapsulation() -> Result<Vec<u8>, String> {
    let (from_tpm, blob) = read_active_sidecar()?;
    {
        let cache = encap_cache().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(cached) = cache.as_ref() {
            if cached.from_tpm == from_tpm && cached.blob == blob {
                return Ok(cached.encapsulation.clone());
            }
        }
    }
    let dk = unseal_sidecar(from_tpm, &blob)?;
    let ek = crate::core::pq_hybrid::PqHybridEngine::encapsulation_from_decapsulation(&dk)
        .map_err(|e| format!("PQ device key is corrupt: {e}"));
    // The DK is secret: zeroize before the cache only keeps the public half.
    let dk_guard = PqDecapsulationBytes(dk);
    let ek = ek?;
    drop(dk_guard);

    *encap_cache().lock().unwrap_or_else(|p| p.into_inner()) = Some(EncapsulationCache {
        from_tpm,
        blob,
        encapsulation: ek.clone(),
    });
    Ok(ek)
}

/// D2/D3: create a device key, preferring TPM 2.0 and falling back to DPAPI.
/// Returns the backend actually used so the caller can log it.
///
/// `PV_PQ_FORCE_DPAPI` is a **test-only** hook (`cfg!(test)`), used to exercise
/// the no-TPM fallback without disabling real hardware. Release builds compile
/// the check out, so a stray env var cannot weaken custody.
pub fn generate_preferring_tpm() -> Result<DeviceBackend, String> {
    if !tpm_forced_off()
        && pq_tpm::provider_available(pq_tpm::Backend::Tpm)
        && generate_and_seal_with(DeviceBackend::Tpm).is_ok()
    {
        return Ok(DeviceBackend::Tpm);
    }
    generate_and_seal()?;
    Ok(DeviceBackend::Dpapi)
}

fn tpm_forced_off() -> bool {
    cfg!(test) && std::env::var_os("PV_PQ_FORCE_DPAPI").is_some()
}

/// A22 D2: re-seal the existing device key with a CNG backend, keeping the old
/// sidecar in place until the caller proves the vault still opens.
///
/// Order: unseal current DK → TPM-seal → unseal the produced blob in memory →
/// only then write `pq_device.tpm`. The caller removes `pq_device.dpapi` after
/// an end-to-end vault load succeeds (`remove_dpapi`), or removes the TPM file
/// on failure (`remove_tpm`).
pub fn reseal_to(backend: DeviceBackend) -> Result<(), String> {
    let cng = backend
        .cng()
        .ok_or_else(|| "DPAPI is not a migration target".to_string())?;
    if tpm_path().is_file() {
        return Err("a CNG device key sidecar already exists".to_string());
    }
    let dk = load_decapsulation()?;
    let blob = pq_tpm::seal(cng, dk.expose())?;
    let proof = pq_tpm::unseal(&blob)?;
    if proof.as_slice() != dk.expose() {
        return Err("TPM reseal proof failed".to_string());
    }
    write_atomic(&tpm_path(), &blob)?;
    reset_encap_cache();
    Ok(())
}

/// A22 D2: drop the DPAPI sidecar after a successful TPM migration proof.
pub fn remove_dpapi() {
    let _ = std::fs::remove_file(path());
    let _ = std::fs::remove_file(path().with_extension("tmp"));
    reset_encap_cache();
}

/// A22 D2: drop a not-yet-proven TPM sidecar (rollback path).
pub fn remove_tpm() {
    let _ = std::fs::remove_file(tpm_path());
    let _ = std::fs::remove_file(tpm_path().with_extension("tmp"));
    reset_encap_cache();
}

/// Remove both sidecars (factory reset / explicit move). Idempotent.
#[allow(dead_code)] // D2 factory reset / backend move
pub fn clear() {
    remove_dpapi();
    remove_tpm();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_test_paths(dir: &std::path::Path) {
        std::env::set_var("PV_PQ_DEVICE_KEY_FILE", dir.join("pq_device.dpapi"));
        std::env::set_var("PV_PQ_TPM_FILE", dir.join("pq_device.tpm"));
    }

    #[test]
    fn device_key_roundtrips_and_missing_fails_closed() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("pv-pq-dev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_test_paths(&dir);
        clear();
        assert!(load_decapsulation().is_err());

        let ek = generate_and_seal().unwrap();
        assert!(!ek.is_empty());
        let dk1 = load_decapsulation().unwrap();
        let dk2 = load_decapsulation().unwrap();
        assert_eq!(dk1.expose(), dk2.expose());
        assert!(exists());
        assert_eq!(active_backend(), Some("dpapi"));
        let (loaded_ek, _) = load_keypair().unwrap();
        assert_eq!(loaded_ek, ek);

        clear();
        assert!(!exists());
        std::env::remove_var("PV_PQ_DEVICE_KEY_FILE");
        std::env::remove_var("PV_PQ_TPM_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tpm_sidecar_roundtrips_and_never_falls_back_to_dpapi() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _key = pq_tpm::TEST_KEY_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if !pq_tpm::provider_available(pq_tpm::Backend::Software) {
            eprintln!("software KSP unavailable; skipping");
            return;
        }
        let dir = std::env::temp_dir().join(format!("pv-pq-tpm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_test_paths(&dir);
        clear();

        let ek = generate_and_seal_with(DeviceBackend::Software).unwrap();
        assert!(!ek.is_empty());
        assert!(tpm_path().is_file());
        assert!(!path().is_file());
        assert_eq!(active_backend(), Some("software"));
        let dk1 = load_decapsulation().unwrap();
        let dk2 = load_decapsulation().unwrap();
        assert_eq!(dk1.expose(), dk2.expose());

        // Corrupt the TPM sidecar: load fails closed...
        let good = std::fs::read(tpm_path()).unwrap();
        let mut bad = good.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        std::fs::write(tpm_path(), &bad).unwrap();
        assert!(load_decapsulation().is_err());

        // ...even with a valid DPAPI sidecar next to it (no hidden fallback).
        generate_and_seal_with(DeviceBackend::Dpapi).unwrap();
        assert!(path().is_file());
        assert!(load_decapsulation().is_err());

        // Restoring the TPM blob works again.
        std::fs::write(tpm_path(), &good).unwrap();
        assert_eq!(load_decapsulation().unwrap().expose(), dk1.expose());

        clear();
        assert!(!exists());
        assert!(!path().exists());
        assert!(!tpm_path().exists());
        std::env::remove_var("PV_PQ_DEVICE_KEY_FILE");
        std::env::remove_var("PV_PQ_TPM_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_prefers_tpm_but_falls_back_to_dpapi_when_unavailable() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _key = pq_tpm::TEST_KEY_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("pv-pq-fallback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_test_paths(&dir);
        clear();

        // Simulate a machine where the TPM provider is unusable/denied.
        std::env::set_var("PV_PQ_FORCE_DPAPI", "1");
        let backend = generate_preferring_tpm().unwrap();
        std::env::remove_var("PV_PQ_FORCE_DPAPI");

        assert_eq!(backend, DeviceBackend::Dpapi);
        assert!(path().is_file());
        assert!(!tpm_path().is_file());
        assert_eq!(active_backend(), Some("dpapi"));
        assert_eq!(
            load_decapsulation().unwrap().expose().len(),
            crate::core::pq_hybrid::DK_LEN
        );

        clear();
        std::env::remove_var("PV_PQ_DEVICE_KEY_FILE");
        std::env::remove_var("PV_PQ_TPM_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encapsulation_cache_invalidates_when_the_sidecar_changes() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("pv-pq-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_test_paths(&dir);
        clear();

        let ek1 = generate_and_seal().unwrap();
        assert_eq!(load_encapsulation().unwrap(), ek1);
        assert_eq!(load_encapsulation().unwrap(), ek1);
        let ek2 = generate_and_seal().unwrap();
        assert_ne!(ek2, ek1);
        assert_eq!(load_encapsulation().unwrap(), ek2);
        clear();
        assert!(load_encapsulation().is_err());

        std::env::remove_var("PV_PQ_DEVICE_KEY_FILE");
        std::env::remove_var("PV_PQ_TPM_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_to_cng_keeps_the_same_decapsulation_key() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _key = pq_tpm::TEST_KEY_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if !pq_tpm::provider_available(pq_tpm::Backend::Software) {
            eprintln!("software KSP unavailable; skipping");
            return;
        }
        let dir = std::env::temp_dir().join(format!("pv-pq-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_test_paths(&dir);
        clear();

        generate_and_seal_with(DeviceBackend::Dpapi).unwrap();
        let before = load_decapsulation().unwrap().expose().to_vec();
        reseal_to(DeviceBackend::Software).unwrap();
        // Same DK through the CNG sidecar; DPAPI is still present pre-proof.
        assert_eq!(load_decapsulation().unwrap().expose(), before);
        assert!(path().is_file());
        remove_dpapi();
        assert!(!path().exists());
        assert_eq!(load_decapsulation().unwrap().expose(), before);
        // Rollback path.
        remove_tpm();
        assert!(load_decapsulation().is_err());

        std::env::remove_var("PV_PQ_DEVICE_KEY_FILE");
        std::env::remove_var("PV_PQ_TPM_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "requires a TPM 2.0 device"]
    fn tpm_device_roundtrip_manual() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _key = pq_tpm::TEST_KEY_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("pv-pq-real-tpm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_test_paths(&dir);
        clear();

        // D1: native TPM seal/unseal.
        let t0 = std::time::Instant::now();
        let ek = generate_and_seal_with(DeviceBackend::Tpm).unwrap();
        let seal_ms = t0.elapsed().as_millis();
        assert!(!ek.is_empty());
        let mut unseal_ms = 0u128;
        for _ in 0..5 {
            let t = std::time::Instant::now();
            let dk = load_decapsulation().unwrap();
            assert_eq!(dk.expose().len(), crate::core::pq_hybrid::DK_LEN);
            unseal_ms += t.elapsed().as_millis();
        }
        assert_eq!(active_backend(), Some("tpm"));
        let t_encap = std::time::Instant::now();
        let _ = load_encapsulation().unwrap();
        let encap_first_ms = t_encap.elapsed().as_millis();
        let t_cached = std::time::Instant::now();
        let _ = load_encapsulation().unwrap();
        let encap_cached_ms = t_cached.elapsed().as_millis();
        eprintln!(
            "D3 timings: TPM keygen+seal={seal_ms}ms, unseal avg={}ms, encap first={encap_first_ms}ms cached={encap_cached_ms}ms",
            unseal_ms / 5
        );
        clear();

        // D2: migrate an existing DPAPI key into the TPM, same DK.
        generate_and_seal_with(DeviceBackend::Dpapi).unwrap();
        let before = load_decapsulation().unwrap().expose().to_vec();
        let t1 = std::time::Instant::now();
        reseal_to(DeviceBackend::Tpm).unwrap();
        eprintln!(
            "D3 timings: DPAPI->TPM migration reseal={}ms",
            t1.elapsed().as_millis()
        );
        assert_eq!(load_decapsulation().unwrap().expose(), before);
        remove_dpapi();
        assert_eq!(load_decapsulation().unwrap().expose(), before);
        assert_eq!(active_backend(), Some("tpm"));

        clear();
        std::env::remove_var("PV_PQ_DEVICE_KEY_FILE");
        std::env::remove_var("PV_PQ_TPM_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
