//! Phase 15 (Option 1) — Canary trap / honeytokens.
//!
//! A canary is an ordinary-looking credential whose `notes` carry the marker
//! `CANARY:`. Nobody legitimate ever touches it — so ANY copy/type event on it
//! means the vault is being ransacked (or the viewer is coerced/curious).
//! Response is local-first: append a timestamped trip record to
//! `canary_alert.log` (also git-ignored) and surface a loud UI alert.
//! No model change needed — the marker hides in the existing notes field.

use crate::models::{Credential, Vault};

pub const CANARY_MARKER: &str = "CANARY:";
const ALERT_FILE: &str = "canary_alert.log";

pub fn is_canary(c: &Credential) -> bool {
    c.notes.trim_start().starts_with(CANARY_MARKER)
}

/// Find a canary credential matching leaked password material.
/// Passwords are the only handle the copy/type callbacks carry.
pub fn find_canary_by_password<'a>(vault: &'a Vault, password: &str) -> Option<&'a Credential> {
    vault
        .credentials
        .iter()
        .find(|c| is_canary(c) && c.password == password)
}

/// Plant a fresh honeytoken. Returns its title for the confirmation message.
pub fn plant_canary(vault: &mut Vault) -> String {
    let n = vault.credentials.iter().filter(|c| is_canary(c)).count() + 1;
    let title = format!("AWS Root [{n}]");
    vault.credentials.push(Credential {
        id: format!("canary-{n}"),
        title: title.clone(),
        username: "root-prod@company.com".into(),
        password: format!("AKIAIOSFODNN7EXAMPLE{n}#"),
        totp_secret: String::new(),
        backup_codes: Vec::new(),
        custom_fields: Vec::new(),
        urls: vec![crate::models::LoginUrl::from("https://console.aws.amazon.com")],
        notes: format!("{CANARY_MARKER} billing alerts — do not rotate without infra team"),
                    folder: crate::models::DEFAULT_FOLDER.to_string(),
                
        reprompt: false,
    
                    attachments: Vec::new(),
                    travel_safe: false,
                    last_changed: crate::models::current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                });
    title
}

/// Record a trip. Timestamped, single-line, append-only.
pub fn record_trip(title: &str, via: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{now} CANARY-TRIPPED title={title:?} via={via}\n");
    if let Ok(existing) = std::fs::read(ALERT_FILE) {
        let mut buf = existing;
        buf.extend_from_slice(line.as_bytes());
        let _ = std::fs::write(ALERT_FILE, buf);
    } else {
        let _ = std::fs::write(ALERT_FILE, line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plants_and_detects() {
        let mut v = Vault::new();
        assert!(find_canary_by_password(&v, "x").is_none());
        let title = plant_canary(&mut v);
        assert!(title.contains("AWS Root"));
        let found = find_canary_by_password(&v, "AKIAIOSFODNN7EXAMPLE1#");
        assert!(found.is_some() && is_canary(found.unwrap()));
    }

    #[test]
    fn legit_creds_are_not_canaries() {
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "1".into(),
            title: "GitHub".into(),
            username: "u".into(),
            password: "p".into(),
            totp_secret: String::new(),
            urls: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: "my token".into(),
                    folder: crate::models::DEFAULT_FOLDER.to_string(),
                
            reprompt: false,
        
                    attachments: Vec::new(),
                    travel_safe: false,
                    last_changed: crate::models::current_timestamp(),
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                });
        assert!(find_canary_by_password(&v, "p").is_none());
    }
}
