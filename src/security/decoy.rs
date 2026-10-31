//! Phase 15 (Option 1) — Decoy / duress vault.
//!
//! Model: a fully separate encrypted container (`decoy_vault.enc`) with its own
//! password. On unlock, the real vault is tried first; only if it fails is the
//! decoy tried — so the duress password is useless without coercion context,
//! and the real password never touches the decoy path.
//! The duress-password verifier itself is DPAPI-sealed (`duress.dpapi`).

use crate::error::{Result, VaultError};
use crate::models::{Credential, TotpAccount, Vault};
use crate::storage::save_vault_secret_flat;
use secrecy::SecretString;
use std::path::PathBuf;
use zeroize::Zeroize;

/// A18: the decoy container intentionally looks like an extra backup
/// generation. Rotation only touches `.bak.1`–`.bak.5`, so gen 0 is safe.
pub const DECOY_FILE: &str = "my_secure_vault.enc.bak.0.enc";
pub const LEGACY_DECOY_FILE: &str = "decoy_vault.enc";
pub const LEGACY_VERIFIER_FILE: &str = "duress.dpapi";

fn decoy_path() -> PathBuf {
    std::env::var("PV_DECOY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DECOY_FILE))
}

fn legacy_decoy_path() -> PathBuf {
    PathBuf::from(LEGACY_DECOY_FILE)
}

/// Remove the old tell-tale files/backups after migration/provisioning.
fn cleanup_legacy() {
    let _ = std::fs::remove_file(legacy_decoy_path());
    let _ = std::fs::remove_file(LEGACY_VERIFIER_FILE);
    for gen in 1..=6 {
        let _ = std::fs::remove_file(format!("{LEGACY_DECOY_FILE}.bak.{gen}.enc"));
    }
}

/// A18 migration: an old `decoy_vault.enc` becomes the backup-like name; the
/// separate duress verifier is deleted (the AEAD tag is the verifier now).
fn migrate_legacy() {
    let new = decoy_path();
    if !new.exists() && legacy_decoy_path().exists() {
        let _ = std::fs::rename(legacy_decoy_path(), &new);
    }
    if new.exists() {
        let _ = std::fs::remove_file(LEGACY_VERIFIER_FILE);
        for gen in 1..=6 {
            let _ = std::fs::remove_file(format!("{LEGACY_DECOY_FILE}.bak.{gen}.enc"));
        }
    }
}

/// Is a decoy container provisioned on this device?
pub fn decoy_exists() -> bool {
    decoy_path().exists() || legacy_decoy_path().exists()
}

/// Set/rotate the duress password AND (re)provision the decoy container
/// with believable dummy entries. The password never persists in plaintext.
pub fn provision_decoy(duress_password: &str) -> Result<()> {
    let mut pw = duress_password.trim().to_string();
    if pw.chars().count() < 8 {
        pw.zeroize();
        return Err(VaultError::Security("duress password too short".into()));
    }
    // Verifier = DPAPI seal of the password itself (constant-time-ish compare on open).
    // NOTE: sealed ONLY after the container below persists — a failed seal
    // must never leave a valid verifier pointing at a missing/stale decoy.
    let mut vault = Vault::new();
    vault.credentials.push(Credential {
        id: "d1".into(),
        title: "Gmail".into(),
        username: "me.2009@gmail.com".into(),
        password: "Summer2009!".into(),
        totp_secret: String::new(),
        backup_codes: Vec::new(),
        custom_fields: Vec::new(),
        urls: vec![crate::models::LoginUrl::from("https://mail.google.com")],
        apps: Vec::new(),
        notes: "Personal".into(),
                    folder: crate::models::DEFAULT_FOLDER.to_string(),
                
        reprompt: false,
    
                    attachments: Vec::new(),
                    travel_safe: false,
                    last_changed: crate::models::current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                });
    vault.credentials.push(Credential {
        id: "d2".into(),
        title: "Facebook".into(),
        username: "me.2009".into(),
        password: "Football#2010".into(),
        totp_secret: String::new(),
        backup_codes: Vec::new(),
        custom_fields: Vec::new(),
        urls: vec![crate::models::LoginUrl::from("https://facebook.com")],
        apps: Vec::new(),
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
    vault.totp_accounts.push(TotpAccount {
        id: "d3".into(),
        account_name: "Old Yahoo".into(),
        issuer: "Yahoo".into(),
        secret: "JBSWY3DPEHPK3PXP".into(),
        digits: 6,
        period: 30,
        algorithm: "SHA1".to_string(),
        otp_type: "totp".to_string(),
        counter: 0,
        favorite: false,
    });
    save_vault_secret_flat(&vault, &SecretString::new(pw.clone()), decoy_path())
        .map_err(|e| VaultError::Security(format!("decoy seal failed: {e}")))?;
    // A18: no separate duress verifier file — the AEAD tag is the verifier.
    cleanup_legacy();
    pw.zeroize();
    Ok(())
}

/// Try the decoy path. The AEAD tag is the duress-password proof: a wrong
/// candidate simply fails to decrypt (no separate verifier file).
pub fn try_open_decoy(candidate: &str) -> Option<Vault> {
    try_open_decoy_secret(&SecretString::new(candidate.to_string()))
}

/// Secret-owning variant — the candidate never lingers as `&str` past this
/// call.
pub fn try_open_decoy_secret(candidate: &SecretString) -> Option<Vault> {
    migrate_legacy();
    crate::storage::load_vault_secret(candidate, decoy_path()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a18_decoy_is_padded_neutral_and_verifier_free() {
        let dir = std::env::temp_dir().join(format!("pv-decoy-a18-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("my_secure_vault.enc.bak.0.enc");
        std::env::set_var("PV_DECOY_FILE", &path);
        let _ = std::fs::remove_file(&path);

        assert!(!decoy_exists());
        provision_decoy("duress-pass-1").unwrap();
        assert!(decoy_exists());
        assert!(path.exists());
        assert!(!PathBuf::from(LEGACY_VERIFIER_FILE).exists());
        let len = std::fs::metadata(&path).unwrap().len();
        // Same plaintext bucket → identical container size as the real vault.
        let real = dir.join("my_secure_vault.enc");
        crate::storage::save_vault_secret(
            &Vault::new(),
            &SecretString::new("master-pass-1".to_string()),
            &real,
        )
        .unwrap();
        assert_eq!(len, std::fs::metadata(&real).unwrap().len(), "decoy size must match the vault");
        assert!(try_open_decoy("duress-pass-1").is_some());
        assert!(try_open_decoy("wrong-pass-1").is_none());

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("PV_DECOY_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
