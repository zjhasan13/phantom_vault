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
const PENDING_FILE: &str = "canary_pending.jsonl";
const REMOTE_FLAG: &str = "canary_remote.flag";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_id() -> String {
    use rand_core::RngCore as _;
    let mut b = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A19 alert body: NO title, NO secret — only a hash + metadata.
pub fn alert_json(id: &str, time: u64, title_hash: &str, via: &str, device: &str) -> String {
    serde_json::json!({
        "id": id, "time": time, "title_hash": title_hash,
        "via": via, "device": device,
    })
    .to_string()
}

fn queue_pending(body: &str) {
    // Only queue when a peer is actually paired: an unpaired device has no
    // destination, and tests must not litter the cwd.
    if crate::sync::p2p_pairing::list_pairs().is_empty() {
        return;
    }
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(PENDING_FILE)
    {
        let _ = writeln!(f, "{body}");
    }
}

/// Best-effort flush of alerts queued while no peer was reachable.
pub fn flush_pending() {
    let Ok(text) = std::fs::read_to_string(PENDING_FILE) else {
        return;
    };
    let mut keep = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        if !crate::sync::p2p_local::broadcast_canary(line) {
            keep.push(line.to_string());
        }
    }
    let out = if keep.is_empty() {
        String::new()
    } else {
        format!("{}\n", keep.join("\n"))
    };
    let _ = std::fs::write(PENDING_FILE, out);
}

/// Receiver side: append a remote trip to the local alert log and leave a
/// startup notification flag.
pub fn record_remote_alert(v: &serde_json::Value) {
    let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("");
    let via = v.get("via").and_then(|x| x.as_str()).unwrap_or("");
    let device = v.get("device").and_then(|x| x.as_str()).unwrap_or("");
    let hash = v.get("title_hash").and_then(|x| x.as_str()).unwrap_or("");
    let line = format!(
        "{} CANARY-TRIPPED-REMOTE device={device:?} via={via:?} title_hash={hash:?} id={id:?}\n",
        now()
    );
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ALERT_FILE)
    {
        let _ = f.write_all(line.as_bytes());
    }
    if id.is_empty() {
        return;
    }
    let _ = std::fs::write(
        REMOTE_FLAG,
        format!("Remote canary tripped on {device} ({via}). id={id}"),
    );
}

/// Startup hook: consume the one-shot remote alert flag.
pub fn take_remote_alert() -> Option<String> {
    let text = std::fs::read_to_string(REMOTE_FLAG).ok()?;
    let _ = std::fs::remove_file(REMOTE_FLAG);
    Some(format!("🚨 {text}"))
}

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
        apps: Vec::new(),
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
    // A19: notify paired devices; queue if none is reachable.
    let device = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "device".to_string());
    let body = alert_json(
        &new_id(),
        now,
        &crate::storage::sha256_hex(title.as_bytes()),
        via,
        &device,
    );
    std::thread::spawn(move || {
        if !crate::sync::p2p_local::broadcast_canary(&body) {
            queue_pending(&body);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a19_alert_has_hash_not_secret() {
        let body = alert_json("id1", 42, "abc123", "copy", "PC");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["title_hash"], "abc123");
        assert_eq!(v["via"], "copy");
        assert_eq!(v["device"], "PC");
        assert!(!body.contains("AWS Root"));
        assert!(!body.contains("password"));
    }

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
            apps: Vec::new(),
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
