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

/// Versioned backup rotation (rules Cat 8): before overwriting, the previous
/// generation shifts `vault.enc → vault.bak.1.enc → … → vault.bak.N.enc`.
/// Generations past `BACKUP_KEEP` are DoD-shredded, never plain-deleted.
/// Ransomware/corruption recovery without unlimited disk growth.
pub const BACKUP_KEEP: usize = 5;

pub fn backup_name(path: &Path, generation: usize) -> std::path::PathBuf {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("vault");
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    path.with_file_name(format!("{stem}.bak.{generation}{ext}"))
}

/// Rotate backups for `path`. Pure filesystem op — unit tested.
/// Missing original = nothing to rotate (first save), still Ok.
pub fn rotate_backups(path: &Path) -> Result<(), String> {
    if std::fs::metadata(path).is_err() {
        return Ok(());
    }
    // Oldest generation is shredded first so a crash mid-rotation can only
    // ever leave an EXTRA backup behind, never a missing one.
    let oldest = backup_name(path, BACKUP_KEEP);
    if oldest.exists() {
        crate::security::shredder::shred_file(&oldest)
            .map_err(|e| format!("Backup shred failed: {e}"))?;
    }
    for gen in (1..BACKUP_KEEP).rev() {
        let src = backup_name(path, gen);
        if src.exists() {
            std::fs::rename(&src, backup_name(path, gen + 1))
                .map_err(|e| format!("Backup rotate failed: {e}"))?;
        }
    }
    std::fs::copy(path, backup_name(path, 1))
        .map_err(|e| format!("Backup snapshot failed: {e}"))?;
    Ok(())
}

/// Save as the portable self-contained v2 container (fresh PQ keypair + DK
/// wrapped by the password key, every save). No sidecar is created.
///
/// Inner format is JSON-first: field-name encoding means `#[serde(default)]`
/// fires reliably, so future appended fields can NEVER break old vaults
/// again (the bincode-EOF class of bug is retired at the source).
pub fn save_vault<P: AsRef<Path>>(vault: &Vault, master_password: &str, file_path: P) -> Result<(), String> {
    // ১. JSON-এ সিরিয়ালাইজ করা (field names + defaults = future-proof)
    let serialized_bytes = serde_json::to_vec(vault)
        .map_err(|e| format!("Serialization error: {}", e))?;

    // ২. পোর্টেবল হাইব্রিড এনক্রিপ্ট (Argon2id × ML-KEM-768 → HKDF-SHA256 → XChaCha20)
    let encrypted_payload = encrypt_vault_portable(master_password, &serialized_bytes)?;

    // ৩. Cross-process lock, backup rotation, তারপর shredder-guarded রাইট
    let _guard = FileLock::acquire(std::path::Path::new(file_path.as_ref()))?;
    rotate_backups(std::path::Path::new(file_path.as_ref()))?;
    crate::security::shredder::secure_write(std::path::Path::new(file_path.as_ref()), &encrypted_payload)?;

    Ok(())
}

/// Load with 3-way envelope dispatch (unchanged):
///
/// - V2Portable: password alone (cross-device safe).
/// - V2Legacy: password + DPAPI sidecar (same-machine migration only).
/// - V1Classical: password alone (legacy fallback).
///
/// Inner pipeline is JSON-first with bincode Gen-chain fallback:
/// - JSON hit → current vault, `needs_migration = false`.
/// - Bincode hit (any pre-JSON generation) → `needs_migration = true`, so the
///   next unlock transparently re-seals into JSON. No silent dual-format limbo.
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
    // JSON-first: appended fields resolve via #[serde(default)], and unknown
    // fields are ignored — forward-compatible in both directions.
    if let Ok(vault) = serde_json::from_slice::<Vault>(&decrypted) {
        return Ok((vault, false));
    }
    // Legacy bincode Gen-chain (pre-JSON vaults), newest-first: Gen3
    // (pre-dynamic-TOTP), Gen2 (pre-attachments/travel), Gen1 (folders, lean
    // credential), Gen0. Always flags migration into JSON.
    let vault: Vault = match bincode::deserialize(&decrypted) {
        Ok(v) => v,
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
    Ok((vault, true))
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
                    last_changed: crate::models::current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
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
    fn backup_rotation_keeps_five_and_shreds_rest() {
        let dir = std::env::temp_dir().join("pv_backup_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        // Seven cumulative saves → live file + exactly 5 generations.
        let mut v = demo_vault();
        for i in 0..7 {
            v.notes.push(crate::models::SecureNote {
                id: format!("n{i}"),
                title: format!("t{i}"),
                content: String::new(),
                folder: "General".into(),
                travel_safe: false,
                favorite: false,
                deleted_at: None,
            });
            save_vault(&v, "backup-pass-1", &path).unwrap();
        }
        assert!(path.exists());
        for gen in 1..=BACKUP_KEEP {
            assert!(backup_name(&path, gen).exists(), "gen {gen} missing");
        }
        assert!(!backup_name(&path, BACKUP_KEEP + 1).exists());
        // Newest backup holds the previous generation (6 notes), live holds 7.
        let prev: Vault = load_vault("backup-pass-1", backup_name(&path, 1)).unwrap();
        let live: Vault = load_vault("backup-pass-1", &path).unwrap();
        assert_eq!(prev.notes.len(), 6);
        assert_eq!(live.notes.len(), 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saved_inner_payload_is_json_not_bincode() {
        use crate::crypto::decrypt_vault_portable;
        let dir = std::env::temp_dir().join("pv_json_proof_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        save_vault(&demo_vault(), "json-proof-1", &path).unwrap();
        let file_bytes = std::fs::read(&path).unwrap();
        // Envelope untouched (still self-contained portable v2).
        assert_eq!(crate::crypto::detect_version(&file_bytes), VaultVersion::V2Portable);
        let inner = decrypt_vault_portable("json-proof-1", &file_bytes).unwrap();
        // JSON-first proof: object syntax, parses as a Vault.
        assert_eq!(inner.first(), Some(&b'{'));
        let parsed: Vault = serde_json::from_slice(&inner).unwrap();
        assert_eq!(parsed.credentials[0].password, "s3cret!");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_bincode_portable_loads_and_flags_migration() {
        use crate::crypto::encrypt_vault_portable;
        let dir = std::env::temp_dir().join("pv_bincode_compat_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        // A vault sealed by the pre-JSON writer: bincode inner, v2 envelope.
        let legacy_inner = bincode::serialize(&demo_vault()).unwrap();
        assert_ne!(legacy_inner.first(), Some(&b'{'));
        let blob = encrypt_vault_portable("compat-pass-1", &legacy_inner).unwrap();
        std::fs::write(&path, blob).unwrap();
        let (vault, needs_migration) = load_vault_versioned("compat-pass-1", &path).unwrap();
        assert!(needs_migration, "bincode inner must trigger re-seal");
        assert_eq!(vault.credentials[0].password, "s3cret!");
        // …and the unlock-path re-save converts it to JSON transparently.
        save_vault(&vault, "compat-pass-1", &path).unwrap();
        let (_, needs_migration) = load_vault_versioned("compat-pass-1", &path).unwrap();
        assert!(!needs_migration);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_ignores_unknown_future_fields() {
        use crate::crypto::{decrypt_vault_portable, encrypt_vault_portable};
        let dir = std::env::temp_dir().join("pv_future_field_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        save_vault(&demo_vault(), "future-pass-1", &path).unwrap();
        // Simulate a NEWER app version: inject an unknown top-level field.
        let file_bytes = std::fs::read(&path).unwrap();
        let inner = decrypt_vault_portable("future-pass-1", &file_bytes).unwrap();
        assert_eq!(inner.first(), Some(&b'{'));
        let mut future = b"{\"__future_field\":123,".to_vec();
        future.extend_from_slice(&inner[1..]);
        let resealed = encrypt_vault_portable("future-pass-1", &future).unwrap();
        std::fs::write(&path, resealed).unwrap();
        let (vault, needs_migration) = load_vault_versioned("future-pass-1", &path).unwrap();
        assert!(!needs_migration);
        assert_eq!(vault.credentials[0].password, "s3cret!");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn byte_fields_roundtrip_exact_without_number_arrays() {
        use crate::crypto::decrypt_vault_portable;
        use base64::Engine as _;
        let dir = std::env::temp_dir().join("pv_bytes_exact_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        // Every byte value incl. NUL, quotes, backslash (JSON-hostile bytes).
        let all_bytes: Vec<u8> = (0..=255u32).map(|b| b as u8).collect();
        let mut v = demo_vault();
        v.credentials[0].attachments.push(crate::models::EncryptedAttachment {
            id: "a1".into(),
            filename: "bin.dat".into(),
            mime_type: "application/octet-stream".into(),
            size_bytes: all_bytes.len(),
            data: all_bytes.clone(),
        });
        save_vault(&v, "bytes-pass-1", &path).unwrap();
        let file_bytes = std::fs::read(&path).unwrap();
        let inner = decrypt_vault_portable("bytes-pass-1", &file_bytes).unwrap();
        let text = String::from_utf8(inner).unwrap();
        // Compact base64 string form…
        let b64 = base64::engine::general_purpose::STANDARD.encode(&all_bytes);
        assert!(text.contains(&format!("\"data\":\"{b64}\"")));
        // …never a JSON number array.
        assert!(!text.contains("\"data\":["));
        // And the roundtrip is byte-exact.
        let back: Vault = load_vault("bytes-pass-1", &path).unwrap();
        assert_eq!(back.credentials[0].attachments[0].data, all_bytes);
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
