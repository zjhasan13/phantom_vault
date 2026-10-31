use crate::core::memory::DpapiGuard;
use crate::core::pq_hybrid::PqDecapsulationBytes;
use crate::crypto::{
    decrypt_vault_hybrid_legacy_secret, decrypt_vault_portable_secret, decrypt_vault_secret,
    detect_version, encrypt_vault_portable_secret, VaultVersion,
};
use crate::models::Vault;
use secrecy::SecretString;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

/// Automated scheduled backups (ciphertext snapshots + retention shred).
pub mod backup_scheduler;

/// Legacy Phase-14 DPAPI sidecar. Only needed to OPEN old 3-byte-magic vaults
/// one final time during migration. New saves never create it.
const PQ_DK_FILE: &str = "pq_decapsulation.dpapi";

/// Cross-process save guard: atomic `create_new` lockfile beside the vault.
/// A second instance waits up to ~500ms, then fails LOUD instead of
/// interleaving two ciphertexts into one corrupt file. RAII — removed on drop.
/// Crash-stale locks (mtime older than STALE_LOCK_SECS, e.g. killed process)
/// are reclaimed after one grace wait instead of wedging saves forever.
struct FileLock {
    path: std::path::PathBuf,
}

/// A lockfile older than this is presumed orphaned (crashed holder).
const STALE_LOCK_SECS: u64 = 60;

fn lock_is_stale(lock_path: &Path) -> bool {
    std::fs::metadata(lock_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|age| age.as_secs() > STALE_LOCK_SECS)
        .unwrap_or(false)
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
                    if lock_is_stale(&lock_path) {
                        // Orphaned by a crash — reclaim once, then retry.
                        let _ = std::fs::remove_file(&lock_path);
                        continue;
                    }
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

    pub(crate) fn load_legacy_pq_dk() -> Result<PqDecapsulationBytes, String> {
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
    // H4: a shred failure (e.g. read-only attribute restored from media)
    // must NEVER brick all future saves — warn and rotate anyway.
    let oldest = backup_name(path, BACKUP_KEEP);
    if oldest.exists() {
        if let Err(e) = crate::security::shredder::shred_file(&oldest) {
            eprintln!("warning: oldest backup shred failed (continuing): {e}");
            let _ = std::fs::remove_file(&oldest);
        }
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
///
/// Secret-owning variant — the password never materializes as `&str`.
/// Same shape as [`save_vault`]; legacy callers migrate one by one.
pub fn save_vault_secret<P: AsRef<Path>>(
    vault: &Vault,
    master_password: &SecretString,
    file_path: P,
) -> Result<(), String> {
    // ১. JSON-এ সিরিয়ালাইজ করা (field names + defaults = future-proof)
    let serialized_bytes = serde_json::to_vec(vault)
        .map_err(|e| format!("Serialization error: {}", e))?;

    // ২. পোর্টেবল হাইব্রিড এনক্রিপ্ট (Argon2id × ML-KEM-768 → HKDF-SHA256 → XChaCha20)
    let encrypted_payload = encrypt_vault_portable_secret(master_password, &serialized_bytes)?;

    // ৩. Cross-process lock, backup rotation, তারপর shredder-guarded রাইট
    let _guard = FileLock::acquire(std::path::Path::new(file_path.as_ref()))?;
    rotate_backups(std::path::Path::new(file_path.as_ref()))?;
    crate::security::shredder::secure_write(std::path::Path::new(file_path.as_ref()), &encrypted_payload)?;

    Ok(())
}

/// Legacy `&str` entrypoint — prefer [`save_vault_secret`].
/// (Compat tests only — all production call sites are migrated.)
#[deprecated(note = "use save_vault_secret with a SecretString")]
pub fn save_vault<P: AsRef<Path>>(vault: &Vault, master_password: &str, file_path: P) -> Result<(), String> {
    save_vault_secret(vault, &SecretString::new(master_password.to_string()), file_path)
}

/// A5: master-password rotation (rekey).
///
/// Re-encrypts the whole container inside `file_path` under `new_password`.
/// The portable save path already emits a fresh Argon2id salt and a fresh
/// ML-KEM keypair, so no KDF parameter or container-layout change is needed.
///
/// Safety order (the live file is never touched until all proofs pass):
/// 1. `old_password` must open the current container — otherwise no write.
/// 2. Serialize once, encrypt under the new password.
/// 3. Round-trip: the new container must decrypt to the exact same bytes.
/// 4. The old password must NOT open the new container.
/// 5. Lock, rotate backups (old container becomes `.bak.1.enc`, still sealed
///    with the OLD password = deliberate rollback snapshot), atomic write.
///
/// Callers must update the in-memory master and re-seal Hello/App-PIN seals;
/// backups, exports and printed shards stay on the old password by design.
pub fn rekey_vault_secret<P: AsRef<Path>>(
    vault: &Vault,
    old_password: &SecretString,
    new_password: &SecretString,
    file_path: P,
) -> Result<(), String> {
    use secrecy::ExposeSecret;
    if old_password.expose_secret() == new_password.expose_secret() {
        return Err("New master password must differ from the current one.".to_string());
    }
    let path = file_path.as_ref();

    // 1. Prove the caller knows the live password (no write on failure).
    //    The proof vault is decrypted material — wipe it before dropping.
    let (mut proof, _) = load_vault_versioned_secret(old_password, path)?;
    proof.zeroize();

    // 2. Encrypt with the new password (fresh salt + fresh PQ keypair).
    let mut serialized =
        serde_json::to_vec(vault).map_err(|e| format!("Serialization error: {}", e))?;
    let encrypted_payload = encrypt_vault_portable_secret(new_password, &serialized)?;

    // 3. Round-trip proof before replacing the only good copy.
    let mut probe = decrypt_vault_portable_secret(new_password, &encrypted_payload)?;
    let roundtrip_ok = probe == serialized;
    probe.zeroize();
    serialized.zeroize();
    if !roundtrip_ok {
        return Err("Rekey verification failed: the new container did not round-trip.".to_string());
    }

    // 4. Old password must not open the new container. Fresh salt makes this
    //    true cryptographically; verify it so a future format change cannot
    //    silently regress the promise.
    if let Ok(mut leaked) = decrypt_vault_portable_secret(old_password, &encrypted_payload) {
        leaked.zeroize();
        return Err(
            "Rekey refused: the old password still opens the new container.".to_string(),
        );
    }

    // 5. Cross-process lock, one rollback generation, atomic write.
    let _guard = FileLock::acquire(path)?;
    rotate_backups(path)?;
    crate::security::shredder::secure_write(path, &encrypted_payload)?;

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
///
/// Secret-owning variant — same shape as [`load_vault_versioned`].
pub fn load_vault_versioned_secret<P: AsRef<Path>>(
    master_password: &SecretString,
    file_path: P,
) -> Result<(Vault, bool), String> {
    // ১. ডিস্ক থেকে বাইনারি পড়া
    let payload = fs::read(&file_path).map_err(|e| format!("File read error: {}", e))?;

    // M7: single-byte magic flip (PV2\0 → PV2) forces the legacy branch
    // and bricks the open when the sidecar is absent. Fall back across
    // branches before failing — an attacker who can rewrite the file can
    // already delete it; a flipped magic must not brick a good vault.
    let decrypted = match detect_version(&payload) {
        VaultVersion::V2Portable => decrypt_vault_portable_secret(master_password, &payload)
            .or_else(|_| {
                let dk = load_legacy_pq_dk()?;
                let out = decrypt_vault_hybrid_legacy_secret(master_password, &payload, dk.expose());
                drop(dk);
                out
            })?,
        VaultVersion::V2Legacy => {
            let primary = (|| {
                let dk = load_legacy_pq_dk()?;
                let out = decrypt_vault_hybrid_legacy_secret(master_password, &payload, dk.expose());
                drop(dk);
                out
            })();
            match primary {
                Ok(d) => d,
                Err(_) => decrypt_vault_portable_secret(master_password, &payload)?,
            }
        }
        VaultVersion::V1Classical => decrypt_vault_secret(master_password, &payload)?,
    };
    // JSON-first: appended fields resolve via #[serde(default)], and unknown
    // fields are ignored — forward-compatible in both directions.
    if let Ok(vault) = serde_json::from_slice::<Vault>(&decrypted) {
        return Ok((vault, false));
    }
    // Legacy bincode Gen-chain (pre-JSON vaults), NARROWEST-first (C11):
    // bincode is not self-describing — trying the current Vault first can
    // mis-parse an older stream into a plausible-but-wrong Vault and then
    // re-seal the garbage over the only good copy. Size-capped options
    // prevent garbage-length OOM aborts on corrupt input.
    //
    // RUSTSEC-2025-0141 (bincode unmaintained) containment: bincode is
    // READ-ONLY here (pre-JSON migration only — all new saves are
    // `serde_json`, see save path), behind a 16MB length pre-check +
    // fixint + allocation cap. No format bump (would brick old vaults);
    // re-audit if bincode ever leaves this function.
    use bincode::Options;
    // Reject trailing bytes: with allow_trailing_bytes a current-Vault
    // payload prefix-parses as a legacy gen (false positive, empty vault).
    // fixint matches `bincode::serialize`/`deserialize` (the pre-JSON writer).
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024);
    if decrypted.len() > 16 * 1024 * 1024 {
        return Err("Deserialization error: payload too large".to_string());
    }
    if let Ok(legacy) = opts.deserialize::<crate::models::VaultLegacy>(&decrypted) {
        let v: Vault = legacy.into();
        return Ok((v, true));
    }
    if let Ok(g1) = opts.deserialize::<crate::models::VaultGen1>(&decrypted) {
        let v: Vault = g1.into();
        return Ok((v, true));
    }
    if let Ok(g2) = opts.deserialize::<crate::models::VaultGen2>(&decrypted) {
        let v: Vault = g2.into();
        return Ok((v, true));
    }
    if let Ok(g3) = opts.deserialize::<crate::models::VaultGen3>(&decrypted) {
        let v: Vault = g3.into();
        return Ok((v, true));
    }
    if let Ok(g4) = opts.deserialize::<crate::models::VaultGen4>(&decrypted) {
        let v: Vault = g4.into();
        return Ok((v, true));
    }
    // Current-schema bincode LAST (pre-JSON writers only).
    if let Ok(v) = opts.deserialize::<Vault>(&decrypted) {
        return Ok((v, true));
    }
    Err("Deserialization error: unknown legacy payload".to_string())
}

/// Legacy entrypoint: loads any version (migration flag discarded).
/// Secret-owning variant — same shape as [`load_vault`].
pub fn load_vault_secret<P: AsRef<Path>>(
    master_password: &SecretString,
    file_path: P,
) -> Result<Vault, String> {
    load_vault_versioned_secret(master_password, file_path).map(|(v, _)| v)
}

/// Legacy `&str` entrypoints — prefer the `_secret` variants.
/// (Compat tests only — all production call sites are migrated.)
#[deprecated(note = "use load_vault_versioned_secret with a SecretString")]
pub fn load_vault_versioned<P: AsRef<Path>>(
    master_password: &str,
    file_path: P,
) -> Result<(Vault, bool), String> {
    load_vault_versioned_secret(&SecretString::new(master_password.to_string()), file_path)
}

/// Legacy entrypoint: loads any version (migration flag discarded).
#[deprecated(note = "use load_vault_secret with a SecretString")]
pub fn load_vault<P: AsRef<Path>>(master_password: &str, file_path: P) -> Result<Vault, String> {
    load_vault_versioned_secret(&SecretString::new(master_password.to_string()), file_path)
        .map(|(v, _)| v)
}

#[cfg(test)]
#[allow(deprecated)]
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
            apps: Vec::new(),
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
    fn secret_variants_roundtrip_and_cross_compat() {
        let dir = std::env::temp_dir().join("pv_secret_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        let pw = SecretString::new("secret-path-pass-1".to_string());
        // Secret save → legacy (&str) load.
        save_vault_secret(&demo_vault(), &pw, &path).unwrap();
        let (vault, needs_migration) = load_vault_versioned("secret-path-pass-1", &path).unwrap();
        assert!(!needs_migration);
        assert_eq!(vault.credentials[0].password, "s3cret!");
        // Legacy save → secret load.
        save_vault(&demo_vault(), "secret-path-pass-1", &path).unwrap();
        let vault2 = load_vault_secret(&pw, &path).unwrap();
        assert_eq!(vault2.credentials[0].password, "s3cret!");
        assert!(load_vault_secret(&SecretString::new("wrong-pass!!".to_string()), &path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_save_emits_portable_container() {
        let dir = std::env::temp_dir().join("pv_secret_ver_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        save_vault_secret(
            &demo_vault(),
            &SecretString::new("secret-ver-pass-1".to_string()),
            &path,
        )
        .unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(crate::crypto::detect_version(&raw), VaultVersion::V2Portable);
        let _ = std::fs::remove_dir_all(&dir);
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
                custom_fields: Vec::new(),
                attachments: Vec::new(),
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
    fn fresh_lock_is_not_stale_but_acquire_recovers() {
        let dir = std::env::temp_dir().join("pv_lock_stale");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        // A just-created lock is fresh: a second acquire must wait, not steal.
        let _held = FileLock::acquire(&path).unwrap();
        assert!(!lock_is_stale(&dir.join("vault.lock")));
        drop(_held);
        // Released lock reacquires cleanly.
        let _held2 = FileLock::acquire(&path).unwrap();
        drop(_held2);
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

    #[test]
    fn rekey_opens_with_new_password_and_refuses_old() {
        let dir = std::env::temp_dir().join("pv_rekey_open_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        let old = SecretString::new("old-master-pass-1".to_string());
        let new = SecretString::new("new-master-pass-2".to_string());
        save_vault_secret(&demo_vault(), &old, &path).unwrap();

        rekey_vault_secret(&demo_vault(), &old, &new, &path).unwrap();

        let reopened = load_vault_secret(&new, &path).unwrap();
        assert_eq!(reopened.credentials[0].password, "s3cret!");
        assert_eq!(reopened.credentials[0].username, "u@example.com");
        assert!(load_vault_secret(&old, &path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_keeps_one_old_password_rollback_snapshot() {
        let dir = std::env::temp_dir().join("pv_rekey_rollback_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        let old = SecretString::new("old-rollback-pass".to_string());
        let new = SecretString::new("new-rollback-pass".to_string());
        save_vault_secret(&demo_vault(), &old, &path).unwrap();

        rekey_vault_secret(&demo_vault(), &old, &new, &path).unwrap();

        let rollback = backup_name(&path, 1);
        assert!(rollback.exists(), "rekey must leave .bak.1.enc");
        let old_vault = load_vault_secret(&old, &rollback).unwrap();
        assert_eq!(old_vault.credentials[0].password, "s3cret!");
        // The rollback stays on the OLD password — a new-password open fails.
        assert!(load_vault_secret(&new, &rollback).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_wrong_old_password_leaves_live_file_untouched() {
        let dir = std::env::temp_dir().join("pv_rekey_wrong_old_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        let old = SecretString::new("right-old-pass-1".to_string());
        let wrong = SecretString::new("wrong-old-pass-9".to_string());
        let new = SecretString::new("new-wrong-test-2".to_string());
        save_vault_secret(&demo_vault(), &old, &path).unwrap();
        let before = std::fs::read(&path).unwrap();

        let err = rekey_vault_secret(&demo_vault(), &wrong, &new, &path).unwrap_err();
        assert!(!err.is_empty(), "wrong old password must be refused");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(load_vault_secret(&old, &path).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_fresh_salt_and_ciphertext_on_every_run() {
        let dir = std::env::temp_dir().join("pv_rekey_fresh_salt_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        let p1 = SecretString::new("fresh-old-pass-01".to_string());
        let p2 = SecretString::new("fresh-new-pass-02".to_string());
        let p3 = SecretString::new("fresh-new-pass-03".to_string());
        save_vault_secret(&demo_vault(), &p1, &path).unwrap();
        rekey_vault_secret(&demo_vault(), &p1, &p2, &path).unwrap();
        let first = std::fs::read(&path).unwrap();
        rekey_vault_secret(&demo_vault(), &p2, &p3, &path).unwrap();
        let second = std::fs::read(&path).unwrap();
        // Same vault bytes, different container bytes: fresh salt + PQ keypair.
        assert_ne!(first, second);
        assert_ne!(first[4..20], second[4..20], "salt must not be reused");
        assert!(load_vault_secret(&p3, &path).is_ok());
        assert!(load_vault_secret(&p2, &path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_refuses_identical_old_and_new_password() {
        let dir = std::env::temp_dir().join("pv_rekey_same_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("vault.enc");
        let pw = SecretString::new("same-password-123".to_string());
        save_vault_secret(&demo_vault(), &pw, &path).unwrap();
        let err = rekey_vault_secret(&demo_vault(), &pw, &pw, &path).unwrap_err();
        assert!(err.contains("must differ"), "unexpected error: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
