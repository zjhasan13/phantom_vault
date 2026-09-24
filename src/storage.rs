use crate::core::memory::DpapiGuard;
use crate::core::pq_hybrid::PqDecapsulationBytes;
use crate::crypto::{
    decrypt_vault, decrypt_vault_hybrid_legacy, decrypt_vault_portable, detect_version,
    encrypt_vault_portable, VaultVersion,
};
use crate::models::Vault;
use std::fs;
use std::path::Path;

/// Legacy Phase-14 DPAPI sidecar. Only needed to OPEN old 3-byte-magic vaults
/// one final time during migration. New saves never create it.
const PQ_DK_FILE: &str = "pq_decapsulation.dpapi";

/// Cross-process save guard: atomic `create_new` lockfile beside the vault.
/// A second instance waits up to ~500ms, then fails LOUD instead of
/// interleaving two ciphertexts into one corrupt file. RAII — removed on drop.
struct FileLock {
    path: std::path::PathBuf,
}

impl FileLock {
    fn acquire(vault_path: &Path) -> Result<Self, String> {
        let dir = vault_path.parent().filter(|p| !p.as_os_str().is_empty());
        let mut lock_path = dir.map(|d| d.to_path_buf()).unwrap_or_else(|| std::path::PathBuf::from("."));
        lock_path.push("vault.lock");
        for _ in 0..50 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => return Ok(Self { path: lock_path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(format!("Vault lock failed: {e}")),
            }
        }
        Err("Vault file currently busy in another instance".to_string())
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn load_legacy_pq_dk() -> Result<PqDecapsulationBytes, String> {
    let blob = fs::read(PQ_DK_FILE).map_err(|_| {
        "Legacy hybrid vault needs pq_decapsulation.dpapi (restore its backup)".to_string()
    })?;
    let secret =
        DpapiGuard::unprotect(&blob).map_err(|e| format!("PQ key unseal failed: {e}"))?;
    Ok(PqDecapsulationBytes(secret.expose().to_vec()))
}

/// Save as the portable self-contained v2 container (fresh PQ keypair + DK
/// wrapped by the password key, every save). No sidecar is created.
pub fn save_vault<P: AsRef<Path>>(vault: &Vault, master_password: &str, file_path: P) -> Result<(), String> {
    // ১. বাইনারিতে সিরিয়ালাইজ করা (অতি ক্ষুদ্র সাইজ হবে)
    let serialized_bytes = bincode::serialize(vault)
        .map_err(|e| format!("Serialization error: {}", e))?;

    // ২. পোর্টেবল হাইব্রিড এনক্রিপ্ট (Argon2id × ML-KEM-768 → HKDF-SHA256 → XChaCha20)
    let encrypted_payload = encrypt_vault_portable(master_password, &serialized_bytes)?;

    // ৩. Cross-process lock, তারপর shredder-guarded রাইট
    let _guard = FileLock::acquire(std::path::Path::new(file_path.as_ref()))?;
    crate::security::shredder::secure_write(std::path::Path::new(file_path.as_ref()), &encrypted_payload)?;

    Ok(())
}

/// Load with 3-way dispatch:
///
/// - V2Portable: password alone (cross-device safe).
/// - V2Legacy: password + DPAPI sidecar (same-machine migration only).
/// - V1Classical: password alone (legacy fallback).
///
/// Returns `(vault, needs_migration)` — true for anything that isn't portable.
pub fn load_vault_versioned<P: AsRef<Path>>(
    master_password: &str,
    file_path: P,
) -> Result<(Vault, bool), String> {
    // ১. ডিস্ক থেকে বাইনারি পড়া
    let payload = fs::read(&file_path).map_err(|e| format!("File read error: {}", e))?;

    let decrypted = match detect_version(&payload) {
        VaultVersion::V2Portable => decrypt_vault_portable(master_password, &payload)?,
        VaultVersion::V2Legacy => {
            let dk = load_legacy_pq_dk()?;
            let out = decrypt_vault_hybrid_legacy(master_password, &payload, dk.expose());
            drop(dk);
            out?
        }
        VaultVersion::V1Classical => decrypt_vault(master_password, &payload)?,
    };
    let vault: Vault = match bincode::deserialize(&decrypted) {
        Ok(v) => v,
        // Older generations, newest-first: Gen3 (pre-dynamic-TOTP),
        // Gen2 (pre-attachments/travel), Gen1 (folders, lean credential), Gen0.
        Err(_) => match bincode::deserialize::<crate::models::VaultGen3>(&decrypted) {
            Ok(g3) => g3.into(),
            Err(_) => match bincode::deserialize::<crate::models::VaultGen2>(&decrypted) {
                Ok(g2) => g2.into(),
                Err(_) => match bincode::deserialize::<crate::models::VaultGen1>(&decrypted) {
                    Ok(g1) => g1.into(),
                    Err(_) => {
                        let legacy: crate::models::VaultLegacy =
                            bincode::deserialize(&decrypted)
                                .map_err(|e| format!("Deserialization error: {}", e))?;
                        legacy.into()
                    }
                },
            },
        },
    };
    let needs_migration = !matches!(detect_version(&payload), VaultVersion::V2Portable);
    Ok((vault, needs_migration))
}

/// Legacy entrypoint: loads any version (migration flag discarded).
pub fn load_vault<P: AsRef<Path>>(master_password: &str, file_path: P) -> Result<Vault, String> {
    load_vault_versioned(master_password, file_path).map(|(v, _)| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Vault};

    fn demo_vault() -> Vault {
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "t1".into(),
            title: "Test".into(),
            username: "u@example.com".into(),
            password: "s3cret!".into(),
            totp_secret: String::new(),
            urls: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
                    folder: crate::models::DEFAULT_FOLDER.to_string(),
                
            reprompt: false,
        
                    attachments: Vec::new(),
                    travel_safe: false,
                });
        v
    }

    #[test]
    fn portable_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("pv_portable_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        save_vault(&demo_vault(), "portable-pass-1", &path).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(crate::crypto::detect_version(&raw), VaultVersion::V2Portable);
        let (vault, needs_migration) =
            load_vault_versioned("portable-pass-1", &path).unwrap();
        assert!(!needs_migration);
        assert_eq!(vault.credentials[0].password, "s3cret!");
        assert!(load_vault_versioned("wrong-pass!!", &path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_save_is_rejected_not_corrupted() {
        let dir = std::env::temp_dir().join("pv_lock_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        // Hold the lock like a second instance would…
        let _held = FileLock::acquire(&path).unwrap();
        // …then a save must fail LOUD (~500ms) instead of interleaving bytes.
        let err = save_vault(&demo_vault(), "lock-pass-1", &path).unwrap_err();
        assert!(err.contains("busy"));
        drop(_held);
        // …and succeed once released, with no lockfile left behind.
        save_vault(&demo_vault(), "lock-pass-1", &path).unwrap();
        assert!(!dir.join("vault.lock").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v1_vault_migrates_to_portable_and_reopens() {
        let dir = std::env::temp_dir().join("pv_mig_test");
        let _ = std::fs::create_dir_all(&dir);
        let v1_path = dir.join("v1.enc");
        let v2_path = dir.join("v2.enc");
        // Simulate a legacy v1 container (classical layout, no magic).
        let raw = bincode::serialize(&demo_vault()).unwrap();
        let v1_bytes = crate::crypto::encrypt_vault("mig-pass-123", &raw).unwrap();
        assert_eq!(crate::crypto::detect_version(&v1_bytes), VaultVersion::V1Classical);
        std::fs::write(&v1_path, &v1_bytes).unwrap();
        // Load flags migration, then re-save → must become portable.
        let (vault, needs_migration) = load_vault_versioned("mig-pass-123", &v1_path).unwrap();
        assert!(needs_migration);
        save_vault(&vault, "mig-pass-123", &v2_path).unwrap();
        let raw2 = std::fs::read(&v2_path).unwrap();
        assert_eq!(crate::crypto::detect_version(&raw2), VaultVersion::V2Portable);
        let (vault2, needs_migration2) = load_vault_versioned("mig-pass-123", &v2_path).unwrap();
        assert!(!needs_migration2);
        assert_eq!(vault2.credentials[0].password, "s3cret!");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
