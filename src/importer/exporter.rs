//! Zero-lockin vault exporter — the importer's mirror.
//!
//! - Bitwarden unencrypted JSON (`{folders, items}`): logins (with TOTP,
//!   URIs, custom fields, passwordHistory), cards, identities, secure notes.
//!   Licenses / SSH keys / passkeys have no Bitwarden type — they export as
//!   secure notes (title + content), which round-trips back as notes.
//! - Standard CSV: logins + cards in Bitwarden-style columns.
//! - Attachments: binaries are NOT embedded (a 5MB photo would nuke the
//!   file); filename + size ride the notes so nothing is silently lost.
//! Only ACTIVE items export (trash stays behind). Pure + unit tested.

use crate::models::{CustomFieldType, Vault};

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ` (inverse of the import parser).
pub(crate) fn unix_to_iso(ts: u64) -> String {
    let days = (ts / 86400) as i64;
    let rem = (ts % 86400) as i64;
    // civil-from-days (Howard Hinnant).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146097) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60
    )
}

fn folder_id(folders: &std::collections::HashMap<String, String>, name: &str) -> serde_json::Value {
    match folders.get(name) {
        Some(id) => serde_json::Value::String(id.clone()),
        None => serde_json::Value::Null,
    }
}

fn bw_fields(custom: &[crate::models::CustomField]) -> Vec<serde_json::Value> {
    custom
        .iter()
        .map(|f| {
            let (t, linked) = match f.field_type {
                CustomFieldType::Text => (0, None),
                CustomFieldType::Hidden => (1, None),
                CustomFieldType::Checkbox => (2, None),
                CustomFieldType::Linked => (
                    3,
                    Some(if f.value == "username" { 100 } else { 101 }),
                ),
            };
            let mut o = serde_json::json!({"name": f.name, "value": f.value, "type": t});
            if let Some(id) = linked {
                o["linkedId"] = serde_json::json!(id);
            }
            o
        })
        .collect()
}

fn attachment_note(vault_notes: &mut String, atts: &[crate::models::EncryptedAttachment]) -> usize {
    if atts.is_empty() {
        return 0;
    }
    if !vault_notes.is_empty() {
        vault_notes.push('\n');
    }
    vault_notes.push_str("[Attachments — binaries not embedded in export: ");
    let parts: Vec<String> = atts
        .iter()
        .map(|a| format!("{} ({} bytes)", a.filename, a.size_bytes))
        .collect();
    vault_notes.push_str(&parts.join(", "));
    vault_notes.push(']');
    atts.len()
}

/// Full Bitwarden-compatible export document + attachment count.
pub fn export_bitwarden_json(vault: &Vault) -> (serde_json::Value, usize) {
    let mut folders: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut folder_arr = Vec::new();
    for (i, name) in vault.folders.iter().enumerate() {
        let id = format!("export-f{i}");
        folder_arr.push(serde_json::json!({"id": id, "name": name}));
        folders.insert(name.clone(), id);
    }
    let mut items = Vec::new();
    let mut attachments = 0usize;

    for c in vault.credentials.iter().filter(|c| c.deleted_at.is_none()) {
        let mut notes = c.notes.clone();
        attachments += attachment_note(&mut notes, &c.attachments);
        items.push(serde_json::json!({
            "id": c.id, "organizationId": null,
            "folderId": folder_id(&folders, &c.folder),
            "type": 1, "name": c.title, "notes": notes, "favorite": c.favorite,
            "login": {
                "username": c.username, "password": c.password,
                "totp": c.totp_secret,
                "uris": c.urls.iter().map(|u| serde_json::json!({"uri": u})).collect::<Vec<_>>(),
                "passwordHistory": c.password_history.iter().map(|h| {
                    serde_json::json!({"lastUsedDate": unix_to_iso(h.changed_at), "password": h.password})
                }).collect::<Vec<_>>(),
            },
            "fields": bw_fields(&c.custom_fields),
        }));
    }
    for k in vault.cards.iter().filter(|k| k.deleted_at.is_none()) {
        let mut notes = k.notes.clone();
        attachments += attachment_note(&mut notes, &[]);
        items.push(serde_json::json!({
            "id": k.id, "organizationId": null,
            "folderId": folder_id(&folders, &k.folder),
            "type": 3, "name": k.title, "notes": notes, "favorite": k.favorite,
            "card": {"cardholderName": k.cardholder_name, "number": k.card_number,
                     "expMonth": k.exp_month, "expYear": k.exp_year, "code": k.cvv},
        }));
    }
    for n in vault.notes.iter().filter(|n| n.deleted_at.is_none()) {
        items.push(serde_json::json!({
            "id": n.id, "organizationId": null,
            "folderId": folder_id(&folders, &n.folder),
            "type": 2, "name": n.title, "notes": n.content, "favorite": n.favorite,
        }));
    }
    for i in vault.identities.iter().filter(|i| i.deleted_at.is_none()) {
        let mut notes = i.notes.clone();
        attachments += attachment_note(&mut notes, &[]);
        let mut parts = i.full_name.split_whitespace();
        let first = parts.next().unwrap_or("").to_string();
        let last = parts.collect::<Vec<_>>().join(" ");
        items.push(serde_json::json!({
            "id": i.id, "organizationId": null,
            "folderId": folder_id(&folders, &i.folder),
            "type": 4, "name": i.title, "notes": notes, "favorite": i.favorite,
            "identity": {"firstName": first, "lastName": last,
                         "email": i.email, "phone": i.phone,
                         "address1": i.address, "passportNumber": i.nid_or_passport},
        }));
    }
    // No native Bitwarden type → secure notes (documented, readable).
    for l in vault.licenses.iter().filter(|l| l.deleted_at.is_none()) {
        let mut notes = format!("License key: {}", l.license_key);
        if let Some(e) = &l.expiry_date {
            notes.push_str(&format!("\nExpiry: {e}"));
        }
        attachments += attachment_note(&mut notes, &l.attachments);
        items.push(serde_json::json!({
            "id": l.id, "organizationId": null,
            "folderId": folder_id(&folders, &l.folder),
            "type": 2, "name": format!("{} (license)", l.app_name),
            "notes": notes, "favorite": l.favorite,
        }));
    }
    for s in vault.ssh_keys.iter().filter(|s| s.deleted_at.is_none()) {
        let mut notes = format!("Public key:\n{}\n\nPrivate key:\n{}\n\nFingerprint: {}",
            s.public_key, s.private_key, s.fingerprint);
        if !s.notes.is_empty() {
            notes.push_str(&format!("\n\n{}", s.notes));
        }
        items.push(serde_json::json!({
            "id": s.id, "organizationId": null,
            "folderId": folder_id(&folders, &s.folder),
            "type": 2, "name": format!("{} (ssh)", s.title),
            "notes": notes, "favorite": s.favorite,
        }));
    }
    for p in vault.passkeys.iter().filter(|p| p.deleted_at.is_none()) {
        items.push(serde_json::json!({
            "id": p.id, "organizationId": null,
            "folderId": serde_json::Value::Null,
            "type": 2, "name": format!("{} (passkey — re-register after move)", p.rp_id),
            "notes": format!("Passkey for {}. Private material does not export; register a new passkey in the target manager.", p.rp_id),
            "favorite": false,
        }));
    }
    (
        serde_json::json!({"encrypted": false, "folders": folder_arr, "items": items}),
        attachments,
    )
}

/// Standard CSV (Bitwarden-style columns): logins + cards, active only.
pub fn export_csv(vault: &Vault) -> String {
    let mut w = csv::WriterBuilder::new().from_writer(Vec::new());
    let _ = w.write_record([
        "folder", "favorite", "type", "name", "notes", "fields", "login_uri",
        "login_username", "login_password", "login_totp",
    ]);
    for c in vault.credentials.iter().filter(|c| c.deleted_at.is_none()) {
        let fields = c
            .custom_fields
            .iter()
            .map(|f| format!("{}: {}", f.name, f.value))
            .collect::<Vec<_>>()
            .join("; ");
        let _ = w.write_record([
            c.folder.as_str(),
            if c.favorite { "1" } else { "0" },
            "login",
            c.title.as_str(),
            c.notes.as_str(),
            &fields,
            &c.urls.join("; "),
            c.username.as_str(),
            c.password.as_str(),
            c.totp_secret.as_str(),
        ]);
    }
    for k in vault.cards.iter().filter(|k| k.deleted_at.is_none()) {
        let _ = w.write_record([
            k.folder.as_str(),
            if k.favorite { "1" } else { "0" },
            "card",
            k.title.as_str(),
            k.notes.as_str(),
            "",
            "",
            k.cardholder_name.as_str(),
            k.card_number.as_str(),
            &format!("{}/{} cvv {}", k.exp_month, k.exp_year, k.cvv),
        ]);
    }
    String::from_utf8(w.into_inner().unwrap_or_default()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Vault};

    fn vault_one() -> Vault {
        let mut v = Vault::new();
        v.folders = vec!["Work".to_string()];
        v.credentials.push(Credential {
            id: "c1".into(),
            title: "GitHub".into(),
            username: "me".into(),
            password: "pw".into(),
            totp_secret: "ABC".into(),
            urls: vec!["https://github.com".into()],
            backup_codes: vec!["zzz".into()],
            custom_fields: vec![crate::models::CustomField {
                name: "PIN".into(),
                value: "1".into(),
                field_type: crate::models::CustomFieldType::Hidden,
            }],
            notes: "n".into(),
            folder: "Work".into(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: 1_717_243_200,
            password_history: vec![crate::models::PasswordHistoryEntry {
                password: "old".into(),
                changed_at: 1_700_000_000,
            }],
            favorite: true,
            deleted_at: None,
        });
        v
    }

    #[test]
    fn iso_roundtrips_import_parser() {
        assert_eq!(unix_to_iso(1_717_243_200), "2024-06-01T12:00:00Z");
        let back = crate::importer::parse_bw_datetime("2024-06-01T12:00:00Z").unwrap();
        assert_eq!(back, 1_717_243_200);
    }

    #[test]
    fn bw_json_roundtrips_through_importer() {
        let v = vault_one();
        let (doc, atts) = export_bitwarden_json(&v);
        assert_eq!(atts, 0);
        assert_eq!(doc["folders"][0]["name"], "Work");
        let item = &doc["items"][0];
        assert_eq!(item["type"], 1);
        assert_eq!(item["login"]["username"], "me");
        assert_eq!(item["login"]["passwordHistory"][0]["password"], "old");
        assert_eq!(item["fields"][0]["type"], 1);
        // Back through the real importer: zero loss on the important bits.
        let bytes = serde_json::to_vec(&doc).unwrap();
        let mut summary = crate::importer::ImportSummary::default();
        let mut v2 = Vault::new();
        let raws = crate::importer::bitwarden::parse_json(&bytes, &mut summary).unwrap();
        crate::importer::merge(&mut v2, raws, &mut summary);
        assert_eq!(v2.credentials.len(), 1);
        let c = &v2.credentials[0];
        assert_eq!(c.username, "me");
        assert_eq!(c.password, "pw");
        assert_eq!(c.totp_secret, "ABC");
        assert_eq!(c.folder, "Work");
        assert_eq!(c.password_history.len(), 1);
        assert_eq!(c.password_history[0].password, "old");
        assert_eq!(c.custom_fields.len(), 1);
    }

    #[test]
    fn csv_exports_logins_and_cards() {
        let mut v = vault_one();
        v.cards.push(crate::models::PaymentCard {
            id: "k1".into(),
            title: "Visa".into(),
            cardholder_name: "Me".into(),
            card_number: "4111".into(),
            exp_month: "12".into(),
            exp_year: "28".into(),
            cvv: "1".into(),
            folder: "Work".into(),
            notes: String::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        let csv = export_csv(&v);
        assert!(csv.contains("login_username"));
        assert!(csv.contains("GitHub"));
        assert!(csv.contains(",card,Visa"));
    }
}
