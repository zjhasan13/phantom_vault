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
use crate::storage::save_vault_secret;
use secrecy::{ExposeSecret, SecretString};
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
    save_vault_secret(&vault, &SecretString::new(pw.clone()), DECOY_FILE)
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
    // Constant-time compare on the sealed bytes: no String alloc, and the
    // length difference feeds the accumulator (no early-out length oracle).
    let a = secret.expose();
    let b = candidate.as_bytes();
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    drop(secret);
    diff == 0
}

/// Try the decoy path. Returns Some(vault) only if the duress password
/// verifies AND the decoy container decrypts with it.
pub fn try_open_decoy(candidate: &str) -> Option<Vault> {
    try_open_decoy_secret(&SecretString::new(candidate.to_string()))
}

/// Secret-owning variant — the candidate never lingers as `&str` past this
/// call (the DPAPI-seal comparison inside still exposes transiently).
pub fn try_open_decoy_secret(candidate: &SecretString) -> Option<Vault> {
    if !verify_duress(candidate.expose_secret()) {
        return None;
    }
    crate::storage::load_vault_secret(candidate, DECOY_FILE).ok()
}
