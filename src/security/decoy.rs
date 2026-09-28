//! Phase 15 (Option 1) — Decoy / duress vault.
//!
//! Model: a fully separate encrypted container (`decoy_vault.enc`) with its own
//! password. On unlock, the real vault is tried first; only if it fails is the
//! decoy tried — so the duress password is useless without coercion context,
//! and the real password never touches the decoy path.
//! The duress-password verifier itself is DPAPI-sealed (`duress.dpapi`).

use crate::core::memory::DpapiGuard;
use crate::error::{Result, VaultError};
use crate::models::{Credential, TotpAccount, Vault};
use crate::storage::save_vault;
use std::path::Path;
use zeroize::Zeroize;

pub const DECOY_FILE: &str = "decoy_vault.enc";
const DURESS_VERIFIER_FILE: &str = "duress.dpapi";

/// Is a decoy container provisioned on this device?
pub fn decoy_exists() -> bool {
    Path::new(DECOY_FILE).exists()
}

/// Set/rotate the duress password AND (re)provision the decoy container
/// with believable dummy entries. The password never persists in plaintext.
pub fn provision_decoy(duress_password: &str) -> Result<()> {
    let mut pw = duress_password.trim().to_string();
    if pw.len() < 8 {
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
        urls: vec!["https://mail.google.com".to_string()],
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
        urls: vec!["https://facebook.com".to_string()],
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
    save_vault(&vault, &pw, DECOY_FILE)
        .map_err(|e| VaultError::Security(format!("decoy seal failed: {e}")))?;
    // Verifier LAST: only a persisted container gets a valid verifier.
    let blob = DpapiGuard::protect(pw.as_bytes())
        .map_err(|e| VaultError::Security(format!("duress seal failed: {e}")))?;
    std::fs::write(DURESS_VERIFIER_FILE, blob)
        .map_err(|e| VaultError::Security(format!("duress store failed: {e}")))?;
    pw.zeroize();
    Ok(())
}

/// Verify a candidate against the sealed duress verifier (no plaintext stored).
fn verify_duress(candidate: &str) -> bool {
    let blob = match std::fs::read(DURESS_VERIFIER_FILE) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let secret = match DpapiGuard::unprotect(&blob) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let expected = String::from_utf8_lossy(secret.expose()).into_owned();
    drop(secret);
    // Length-first + full compare (adequate for an interactive-attempt-rate path).
    expected.len() == candidate.len()
        && expected
            .as_bytes()
            .iter()
            .zip(candidate.as_bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Try the decoy path. Returns Some(vault) only if the duress password
/// verifies AND the decoy container decrypts with it.
pub fn try_open_decoy(candidate: &str) -> Option<Vault> {
    if !verify_duress(candidate) {
        return None;
    }
    crate::storage::load_vault(candidate, DECOY_FILE).ok()
}
