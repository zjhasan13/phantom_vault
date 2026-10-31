//! Zero-lockin vault exporter — the importer's mirror.
//!
//! - Bitwarden unencrypted JSON (`{folders, items}`): logins (with TOTP,
//!   URIs, custom fields, passwordHistory), cards, identities, secure notes.
//!   Licenses / SSH keys / passkeys have no Bitwarden type — they export as
//!   secure notes (title + content), which round-trips back as notes.
//! - Standard CSV: logins + cards in Bitwarden-style columns.
//! - Attachments: binaries are NOT embedded (a 5MB photo would nuke the
//!   file); filename + size ride the notes so nothing is silently lost.
//!
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
        // Backup codes ride as a hidden custom field: Bitwarden has no
        // native slot, and our importer's auto-sort ("backup" in the name)
        // restores them into backup_codes on the way back in.
        let mut fields = bw_fields(&c.custom_fields);
        if !c.backup_codes.is_empty() {
            fields.push(serde_json::json!({
                "name": "PhantomVault Backup Codes",
                "value": c.backup_codes.join("\n"),
                "type": 1,
            }));
        }
        items.push(serde_json::json!({
            "id": c.id, "organizationId": null,
            "folderId": folder_id(&folders, &c.folder),
            "type": 1, "name": c.title, "notes": notes, "favorite": c.favorite,
            "login": {
                "username": c.username, "password": c.password,
                "totp": c.totp_secret,
                // Bitwarden UriMatchType: 0 base, 1 host, 2 starts-with,
                // 3 exact, 5 never (4 regex has no counterpart — Default).
                // Rule 0 (inherit) exports as match:null like stock clients.
                "uris": c.urls.iter().map(|u| {
                    let m = match u.rule() {
                        crate::models::url_rule::BASE => serde_json::json!(0),
                        crate::models::url_rule::HOST => serde_json::json!(1),
                        crate::models::url_rule::PREFIX => serde_json::json!(2),
                        crate::models::url_rule::EXACT => serde_json::json!(3),
                        crate::models::url_rule::NEVER => serde_json::json!(5),
                        _ => serde_json::Value::Null,
                    };
                    serde_json::json!({"match": m, "uri": u.url()})
                }).collect::<Vec<_>>(),
                "passwordHistory": c.password_history.iter().map(|h| {
                    serde_json::json!({"lastUsedDate": unix_to_iso(h.changed_at), "password": h.password})
                }).collect::<Vec<_>>(),
            },
            "fields": fields,
        }));
    }
    for k in vault.cards.iter().filter(|k| k.deleted_at.is_none()) {
        let mut notes = k.notes.clone();
        attachments += attachment_note(&mut notes, &k.attachments);
        items.push(serde_json::json!({
            "id": k.id, "organizationId": null,
            "folderId": folder_id(&folders, &k.folder),
            "type": 3, "name": k.title, "notes": notes, "favorite": k.favorite,
            "card": {"cardholderName": k.cardholder_name, "number": k.card_number,
                     "expMonth": k.exp_month, "expYear": k.exp_year, "code": k.cvv},
            "fields": bw_fields(&k.custom_fields),
        }));
    }
    for n in vault.notes.iter().filter(|n| n.deleted_at.is_none()) {
        let mut notes = n.content.clone();
        attachments += attachment_note(&mut notes, &n.attachments);
        items.push(serde_json::json!({
            "id": n.id, "organizationId": null,
            "folderId": folder_id(&folders, &n.folder),
            "type": 2, "name": n.title, "notes": notes, "favorite": n.favorite,
            "fields": bw_fields(&n.custom_fields),
        }));
    }
    for i in vault.identities.iter().filter(|i| i.deleted_at.is_none()) {
        let mut notes = i.notes.clone();
        attachments += attachment_note(&mut notes, &i.attachments);
        let mut parts = i.full_name.split_whitespace();
        let first = parts.next().unwrap_or("").to_string();
        let last = parts.collect::<Vec<_>>().join(" ");
        items.push(serde_json::json!({
            "id": i.id, "organizationId": null,
            "folderId": folder_id(&folders, &i.folder),
            "type": 4, "name": i.title, "notes": notes, "favorite": i.favorite,
            "identity": {"firstName": first, "lastName": last,
                         "email": i.email, "phone": i.phone,
                         "address1": i.address, "address2": "",
                         "city": i.city, "state": i.state,
                         "postalCode": i.zip, "country": i.country,
                         "company": i.company, "passportNumber": i.nid_or_passport},
            "fields": bw_fields(&i.custom_fields),
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
            "fields": bw_fields(&l.custom_fields),
        }));
    }
    for s in vault.ssh_keys.iter().filter(|s| s.deleted_at.is_none()) {
        let mut notes = format!("Public key:\n{}\n\nPrivate key:\n{}\n\nFingerprint: {}",
            s.public_key, s.private_key, s.fingerprint);
        if !s.notes.is_empty() {
            notes.push_str(&format!("\n\n{}", s.notes));
        }
        attachments += attachment_note(&mut notes, &s.attachments);
        items.push(serde_json::json!({
            "id": s.id, "organizationId": null,
            "folderId": folder_id(&folders, &s.folder),
            "type": 2, "name": format!("{} (ssh)", s.title),
            "notes": notes, "favorite": s.favorite,
            "fields": bw_fields(&s.custom_fields),
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

/// H1: neutralize spreadsheet formula injection. Any cell starting with
/// `= + - @` or tab/CR is prefixed with `'` so Excel/Sheets/LibreOffice
/// treat a hostile password/notes/URL as text, never a live formula.
pub fn csv_safe(s: &str) -> String {
    let first = s.chars().next().unwrap_or('\0');
    if matches!(first, '=' | '+' | '-' | '@' | '\t' | '\r') {
        format!("'{s}")
    } else {
        s.to_string()
    }
}

/// M5: export gate. The master-reprompt lives in the UI today, so any
/// direct call would bypass it — route UI exports through these wrappers
/// (decoy refused loud). The pure serializers stay for tests/importers.
pub fn export_csv_gated(vault: &Vault, is_decoy: bool) -> Result<String, String> {
    if is_decoy {
        return Err("decoy mode is read-only".to_string());
    }
    export_csv_result(vault)
}

pub fn export_bitwarden_json_gated(
    vault: &Vault,
    is_decoy: bool,
) -> Result<(serde_json::Value, usize), String> {
    if is_decoy {
        return Err("decoy mode is read-only".to_string());
    }
    Ok(export_bitwarden_json(vault))
}

/// Standard CSV (Bitwarden-style columns): logins + cards, active only.
/// NOTE (M5): pure serializer — callers MUST enforce master-reprompt +
/// decoy refusal (use `export_csv_gated` from UI paths).
/// Legacy non-fallible wrapper (tests + importers). UI paths use
/// `export_csv_gated`/`export_csv_result` so failures are loud.
#[allow(dead_code)]
pub fn export_csv(vault: &Vault) -> String {
    export_csv_result(vault).unwrap_or_default()
}

/// Fallible CSV serializer: row/I-O/UTF-8 failures propagate instead of
/// yielding a silently truncated export that looks successful.
pub fn export_csv_result(vault: &Vault) -> Result<String, String> {
    let mut w = csv::WriterBuilder::new().from_writer(Vec::new());
    w.write_record([
        "folder", "favorite", "type", "name", "notes", "fields", "login_uri",
        "login_username", "login_password", "login_totp", "backupcodes",
    ])
    .map_err(|e| format!("csv header failed: {e}"))?;
    for c in vault.credentials.iter().filter(|c| c.deleted_at.is_none()) {
        let fields = c
            .custom_fields
            .iter()
            .map(|f| format!("{}: {}", f.name, f.value))
            .collect::<Vec<_>>()
            .join("; ");
        let fav = if c.favorite { "1" } else { "0" };
        w.write_record([
            csv_safe(c.folder.as_str()),
            fav.to_string(),
            "login".to_string(),
            csv_safe(c.title.as_str()),
            csv_safe(c.notes.as_str()),
            csv_safe(&fields),
            csv_safe(&crate::models::LoginUrl::join(&c.urls, "; ")),
            csv_safe(c.username.as_str()),
            csv_safe(c.password.as_str()),
            csv_safe(c.totp_secret.as_str()),
            csv_safe(&c.backup_codes.join("\n")),
        ])
        .map_err(|e| format!("csv login row failed: {e}"))?;
    }
    for k in vault.cards.iter().filter(|k| k.deleted_at.is_none()) {
        let fav = if k.favorite { "1" } else { "0" };
        w.write_record([
            csv_safe(k.folder.as_str()),
            fav.to_string(),
            "card".to_string(),
            csv_safe(k.title.as_str()),
            csv_safe(k.notes.as_str()),
            String::new(),
            String::new(),
            csv_safe(k.cardholder_name.as_str()),
            csv_safe(k.card_number.as_str()),
            csv_safe(&format!("{}/{} cvv {}", k.exp_month, k.exp_year, k.cvv)),
            String::new(),
        ])
        .map_err(|e| format!("csv card row failed: {e}"))?;
    }
    // M4: never return a silent empty string as success — propagate the error.
    let bytes = w
        .into_inner()
        .map_err(|e| format!("csv finalize failed: {e}"))?;
    String::from_utf8(bytes).map_err(|e| format!("csv utf8 failed: {e}"))
}

/// Marker written into every native PhantomVault backup document. The
/// sniffer keys on it, so a hand-edited `format` string is a loud refusal
/// rather than a silent partial import.
pub const NATIVE_FORMAT: &str = "phantomvault-backup";
/// Native backup schema version (bump only on a breaking field change).
pub const NATIVE_VERSION: u32 = 1;

/// Active-only deep copy for native export: trash stays behind and
/// machine-local state (sharing grants, verified ids) never travels.
fn active_copy(vault: &Vault) -> Vault {
    let mut out = vault.clone();
    out.credentials.retain(|c| c.deleted_at.is_none());
    out.licenses.retain(|l| l.deleted_at.is_none());
    out.notes.retain(|n| n.deleted_at.is_none());
    out.cards.retain(|k| k.deleted_at.is_none());
    out.identities.retain(|i| i.deleted_at.is_none());
    out.ssh_keys.retain(|s| s.deleted_at.is_none());
    out.passkeys.retain(|p| p.deleted_at.is_none());
    out.shared_grants.clear();
    out.verified_ids.clear();
    out
}

/// Lossless native backup document (PLAINTEXT �?" never write this directly;
/// use [`export_native_encrypted`]). Passkeys, SSH keys, 2FA accounts and
/// attachment bytes all survive a round-trip.
pub fn export_native_json(vault: &Vault) -> serde_json::Value {
    serde_json::json!({
        "format": NATIVE_FORMAT,
        "version": NATIVE_VERSION,
        "exported_at": crate::models::current_timestamp(),
        "vault": active_copy(vault),
    })
}

/// Item + attachment footprint for the export summary line.
pub fn native_stats(vault: &Vault) -> (usize, usize, u64) {
    let v = active_copy(vault);
    let items = v.credentials.len()
        + v.licenses.len()
        + v.notes.len()
        + v.cards.len()
        + v.identities.len()
        + v.ssh_keys.len()
        + v.passkeys.len()
        + v.totp_accounts.len();
    let atts: Vec<&crate::models::EncryptedAttachment> = v
        .credentials
        .iter()
        .flat_map(|c| c.attachments.iter())
        .chain(v.licenses.iter().flat_map(|l| l.attachments.iter()))
        .chain(v.notes.iter().flat_map(|n| n.attachments.iter()))
        .chain(v.cards.iter().flat_map(|k| k.attachments.iter()))
        .chain(v.identities.iter().flat_map(|i| i.attachments.iter()))
        .chain(v.ssh_keys.iter().flat_map(|s| s.attachments.iter()))
        .collect();
    let bytes: u64 = atts.iter().map(|a| a.size_bytes as u64).sum();
    (items, atts.len(), bytes)
}

/// A6: `.pvx` v2 envelope tag. A file that starts with this marker is sealed
/// with a dedicated **backup passphrase**; the importer refuses the vault
/// master password for it. Files without the tag are legacy backups sealed with
/// the master password and keep working through the old path.
pub const BACKUP_V2_MAGIC: &[u8; 5] = b"PVBK1";

/// `.pvx` container: the native JSON sealed with the portable hybrid
/// envelope (same Argon2id + ML-KEM + XChaCha20Poly1305 as the vault file),
/// under its own backup passphrase and prefixed with [`BACKUP_V2_MAGIC`].
pub fn export_native_encrypted(
    vault: &Vault,
    backup_passphrase: &secrecy::SecretString,
) -> Result<Vec<u8>, String> {
    let doc = export_native_json(vault);
    let plain = serde_json::to_vec(&doc).map_err(|e| format!("native encode failed: {e}"))?;
    let container = crate::crypto::encrypt_vault_portable_secret(backup_passphrase, &plain)?;
    let mut out = Vec::with_capacity(BACKUP_V2_MAGIC.len() + container.len());
    out.extend_from_slice(BACKUP_V2_MAGIC);
    out.extend_from_slice(&container);
    Ok(out)
}

pub fn export_native_gated(
    vault: &Vault,
    is_decoy: bool,
    backup_passphrase: &secrecy::SecretString,
) -> Result<Vec<u8>, String> {
    if is_decoy {
        return Err("decoy mode is read-only".to_string());
    }
    export_native_encrypted(vault, backup_passphrase)
}

/// Full-fidelity CSV for spreadsheets: EVERY item kind, one row each, with
/// the complete item JSON in `data_json`. PLAINTEXT (secrets included) �?"
/// use only through the gated UI path, never for vendor interop.
pub fn export_csv_full_gated(vault: &Vault, is_decoy: bool) -> Result<String, String> {
    if is_decoy {
        return Err("decoy mode is read-only".to_string());
    }
    export_csv_full_result(vault)
}

pub fn export_csv_full_result(vault: &Vault) -> Result<String, String> {
    let mut w = csv::WriterBuilder::new().from_writer(Vec::new());
    w.write_record(["kind", "folder", "favorite", "title", "notes", "data_json"])
        .map_err(|e| format!("csv header failed: {e}"))?;
    fn row(
        w: &mut csv::Writer<Vec<u8>>,
        kind: &str,
        folder: &str,
        favorite: bool,
        title: &str,
        notes: &str,
        data: serde_json::Value,
    ) -> Result<(), String> {
        w.write_record([
            kind.to_string(),
            csv_safe(folder),
            if favorite { "1" } else { "0" }.to_string(),
            csv_safe(title),
            csv_safe(notes),
            csv_safe(&data.to_string()),
        ])
        .map_err(|e| format!("csv {kind} row failed: {e}"))
    }
    for c in vault.credentials.iter().filter(|c| c.deleted_at.is_none()) {
        row(&mut w, "login", &c.folder, c.favorite, &c.title, &c.notes, serde_json::to_value(c).unwrap_or(serde_json::Value::Null))?;
    }
    for l in vault.licenses.iter().filter(|l| l.deleted_at.is_none()) {
        row(&mut w, "license", &l.folder, l.favorite, &l.app_name, "", serde_json::to_value(l).unwrap_or(serde_json::Value::Null))?;
    }
    for n in vault.notes.iter().filter(|n| n.deleted_at.is_none()) {
        row(&mut w, "note", &n.folder, n.favorite, &n.title, "", serde_json::to_value(n).unwrap_or(serde_json::Value::Null))?;
    }
    for k in vault.cards.iter().filter(|k| k.deleted_at.is_none()) {
        row(&mut w, "card", &k.folder, k.favorite, &k.title, &k.notes, serde_json::to_value(k).unwrap_or(serde_json::Value::Null))?;
    }
    for i in vault.identities.iter().filter(|i| i.deleted_at.is_none()) {
        row(&mut w, "identity", &i.folder, i.favorite, &i.title, &i.notes, serde_json::to_value(i).unwrap_or(serde_json::Value::Null))?;
    }
    for s in vault.ssh_keys.iter().filter(|s| s.deleted_at.is_none()) {
        row(&mut w, "ssh", &s.folder, s.favorite, &s.title, &s.notes, serde_json::to_value(s).unwrap_or(serde_json::Value::Null))?;
    }
    for p in vault.passkeys.iter().filter(|p| p.deleted_at.is_none()) {
        row(&mut w, "passkey", "", p.favorite, &p.rp_id, "", serde_json::to_value(p).unwrap_or(serde_json::Value::Null))?;
    }
    for t in &vault.totp_accounts {
        let title = format!("{} {}", t.issuer, t.account_name).trim().to_string();
        row(&mut w, "totp", "", t.favorite, &title, "", serde_json::to_value(t).unwrap_or(serde_json::Value::Null))?;
    }
    let bytes = w.into_inner().map_err(|e| format!("csv finalize failed: {e}"))?;
    String::from_utf8(bytes).map_err(|e| format!("csv utf8 failed: {e}"))
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
            apps: Vec::new(),
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
        // PIN custom + re-imported backup-codes field (auto-sort restores box).
        assert_eq!(c.custom_fields.len(), 2);
        // Backup codes round-trip via the hidden customs field + auto-sort.
        assert!(c.backup_codes.contains(&"zzz".to_string()));
    }

    #[test]
    fn csv_roundtrips_login_with_backup() {
        let v = vault_one();
        let csv = export_csv(&v);
        assert!(csv.contains("backupcodes"));
        // Back through OUR csv path: login, totp, customs, backup all survive.
        let bytes = csv.into_bytes();
        let mut summary = crate::importer::ImportSummary::default();
        let mut v2 = Vault::new();
        // Sniff ours as BitwardenCsv (login_username header) and parse.
        let raws = crate::importer::bitwarden::parse_csv(&bytes, &mut summary).unwrap();
        crate::importer::merge(&mut v2, raws, &mut summary);
        assert_eq!(v2.credentials.len(), 1);
        let c = &v2.credentials[0];
        assert_eq!(c.username, "me");
        assert_eq!(c.totp_secret, "ABC");
        assert!(c.backup_codes.contains(&"zzz".to_string()));
        assert!(c.custom_fields.iter().any(|f| f.name == "PIN"));
    }

    #[test]
    fn bw_json_roundtrips_card_and_identity_customs() {
        // Non-login customs must survive export → re-import (they used to
        // drop on both ends: no `fields` on export, no parse on import).
        use crate::models::{CustomField, CustomFieldType};
        let mut v = vault_one();
        v.cards.push(crate::models::PaymentCard {
            id: "k9".into(),
            title: "MC".into(),
            cardholder_name: "Me".into(),
            card_number: "5555555555554444".into(),
            exp_month: "01".into(),
            exp_year: "30".into(),
            cvv: "2".into(),
            folder: "Work".into(),
            notes: String::new(),
            custom_fields: vec![CustomField {
                name: "Branch".into(),
                value: "Dhaka".into(),
                field_type: CustomFieldType::Text,
            }],
            attachments: Vec::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        v.identities.push(crate::models::IdentityItem {
            id: "i9".into(),
            title: "Home".into(),
            full_name: "Me Myself".into(),
            nid_or_passport: String::new(),
            email: "me@x.com".into(),
            phone: String::new(),
            address: String::new(),
            company: "Acme".into(),
            city: "Dhaka".into(),
            state: String::new(),
            zip: "1000".into(),
            country: "BD".into(),
            folder: "Work".into(),
            notes: String::new(),
            custom_fields: vec![CustomField {
                name: "PIN".into(),
                value: "4242".into(),
                field_type: CustomFieldType::Hidden,
            }],
            attachments: Vec::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        let (doc, _) = export_bitwarden_json(&v);
        let bytes = serde_json::to_vec(&doc).unwrap();
        let mut summary = crate::importer::ImportSummary::default();
        let mut v2 = Vault::new();
        let raws = crate::importer::bitwarden::parse_json(&bytes, &mut summary).unwrap();
        crate::importer::merge(&mut v2, raws, &mut summary);
        assert_eq!(v2.cards.len(), 1);
        assert_eq!(v2.cards[0].card_number, "5555555555554444");
        assert!(v2.cards[0].custom_fields.iter().any(|f| f.name == "Branch" && f.value == "Dhaka"));
        assert_eq!(v2.identities.len(), 1);
        assert_eq!(v2.identities[0].email, "me@x.com");
        assert!(v2.identities[0].custom_fields.iter().any(|f| f.name == "PIN" && f.value == "4242"));
        // Structured identity parts survive the Bitwarden identity object.
        let ii = &v2.identities[0];
        assert_eq!(ii.company, "Acme");
        assert_eq!(ii.city, "Dhaka");
        assert_eq!(ii.zip, "1000");
        assert_eq!(ii.country, "BD");
    }

    #[test]
    fn bw_json_roundtrips_url_match_rules() {
        use crate::models::{url_rule, LoginUrl};
        let mut v = vault_one();
        v.credentials[0].urls = vec![
            LoginUrl::new("https://github.com/login".into(), url_rule::EXACT),
            LoginUrl::Plain("https://github.com".into()),
        ];
        let (doc, _) = export_bitwarden_json(&v);
        // Bitwarden wire shape: match 3 = exact, null = default.
        let uris = doc["items"][0]["login"]["uris"].as_array().unwrap();
        assert_eq!(uris.len(), 2);
        assert_eq!(uris[0]["match"], serde_json::json!(3));
        assert!(uris[1].get("match").unwrap().is_null());
        // Back through the importer: rules restored, order kept.
        let bytes = serde_json::to_vec(&doc).unwrap();
        let mut summary = crate::importer::ImportSummary::default();
        let mut v2 = Vault::new();
        let raws = crate::importer::bitwarden::parse_json(&bytes, &mut summary).unwrap();
        crate::importer::merge(&mut v2, raws, &mut summary);
        assert_eq!(v2.credentials.len(), 1);
        let urls = &v2.credentials[0].urls;
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].url(), "https://github.com/login");
        assert_eq!(urls[0].rule(), url_rule::EXACT);
        assert_eq!(urls[1].rule(), url_rule::DEFAULT);
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
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        let csv = export_csv(&v);
        assert!(csv.contains("login_username"));
        assert!(csv.contains("GitHub"));
        assert!(csv.contains(",card,Visa"));
    }

    #[test]
    fn csv_neutralizes_formula_payloads() {
        assert_eq!(csv_safe("=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")");
        assert_eq!(csv_safe("+cmd"), "'+cmd");
        assert_eq!(csv_safe("-2+3"), "'-2+3");
        assert_eq!(csv_safe("@evil"), "'@evil");
        assert_eq!(csv_safe("normal"), "normal");
        let mut v = vault_one();
        v.credentials[0].password = "=cmd|'/c calc'!A1".into();
        let csv = export_csv(&v);
        assert!(csv.contains("'=cmd"), "formula password must be quoted");
    }

    fn vault_all_kinds() -> Vault {
        let mut v = vault_one();
        v.credentials[0].attachments.push(crate::models::EncryptedAttachment {
            id: "att1".into(),
            filename: "id.bin".into(),
            mime_type: "application/octet-stream".into(),
            size_bytes: 3,
            data: vec![1, 2, 3],
        });
        v.totp_accounts.push(crate::models::TotpAccount {
            id: "t1".into(),
            account_name: "me@x.com".into(),
            issuer: "GitHub".into(),
            secret: "JBSWY3DP".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        });
        v.licenses.push(crate::models::SoftwareLicense {
            id: "l1".into(),
            app_name: "IDE".into(),
            license_key: "KEY-1".into(),
            expiry_date: None,
            folder: "Work".into(),
            custom_fields: vec![],
            attachments: vec![],
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        v.notes.push(crate::models::SecureNote {
            id: "n1".into(),
            title: "Note".into(),
            content: "body".into(),
            folder: "Work".into(),
            custom_fields: vec![],
            attachments: vec![],
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        v.cards.push(crate::models::PaymentCard {
            id: "k1".into(),
            title: "Visa".into(),
            cardholder_name: "Me".into(),
            card_number: "4111".into(),
            exp_month: "12".into(),
            exp_year: "30".into(),
            cvv: "1".into(),
            folder: "Work".into(),
            notes: String::new(),
            custom_fields: vec![],
            attachments: vec![],
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        v.identities.push(crate::models::IdentityItem {
            id: "i1".into(),
            title: "Home".into(),
            full_name: "Me".into(),
            nid_or_passport: String::new(),
            email: "me@x.com".into(),
            phone: String::new(),
            address: String::new(),
            company: String::new(),
            city: String::new(),
            state: String::new(),
            zip: String::new(),
            country: String::new(),
            folder: "Work".into(),
            notes: String::new(),
            custom_fields: vec![],
            attachments: vec![],
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        v.ssh_keys.push(crate::models::SshKeyItem {
            id: "s1".into(),
            title: "Server".into(),
            public_key: "ssh-ed25519 A".into(),
            private_key: "PRIV".into(),
            fingerprint: "fp".into(),
            folder: "Work".into(),
            notes: String::new(),
            custom_fields: vec![],
            attachments: vec![],
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        v.passkeys.push(crate::models::PasskeyItem {
            id: "p1".into(),
            rp_id: "github.com".into(),
            user_name: "me".into(),
            user_handle: vec![1],
            credential_id: vec![2, 3],
            private_key_pkcs8: vec![9, 8, 7],
            public_key_der: vec![4],
            sign_count: 1,
            created_at: 5,
            favorite: false,
            deleted_at: None,
        });
        v
    }

    #[test]
    fn native_backup_is_lossless_and_encrypted() {
        let v = vault_all_kinds();
        let pw = secrecy::SecretString::new("backup-passphrase-1".to_string());
        let blob = export_native_encrypted(&v, &pw).unwrap();
        assert_eq!(&blob[..5], BACKUP_V2_MAGIC);
        let plain =
            crate::crypto::decrypt_vault_portable_secret(&pw, &blob[BACKUP_V2_MAGIC.len()..])
                .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(doc["format"], NATIVE_FORMAT);
        assert_eq!(doc["version"], NATIVE_VERSION);
        let back: Vault = serde_json::from_value(doc["vault"].clone()).unwrap();
        assert_eq!(back.credentials.len(), 1);
        assert_eq!(back.totp_accounts.len(), 1);
        assert_eq!(back.licenses.len(), 1);
        assert_eq!(back.passkeys.len(), 1);
        assert_eq!(back.passkeys[0].private_key_pkcs8, vec![9, 8, 7]);
        assert_eq!(back.credentials[0].attachments[0].data, vec![1, 2, 3]);
        let bad = secrecy::SecretString::new("wrong".to_string());
        assert!(
            crate::crypto::decrypt_vault_portable_secret(&bad, &blob[BACKUP_V2_MAGIC.len()..])
                .is_err()
        );
    }

    #[test]
    fn a6_backup_opens_with_passphrase_but_never_with_the_master() {
        let v = vault_all_kinds();
        let backup = secrecy::SecretString::new("backup-passphrase-1".to_string());
        let master = secrecy::SecretString::new("master-password-1".to_string());
        let blob = export_native_gated(&v, false, &backup).unwrap();
        let body = &blob[BACKUP_V2_MAGIC.len()..];
        assert!(crate::crypto::decrypt_vault_portable_secret(&backup, body).is_ok());
        assert!(
            crate::crypto::decrypt_vault_portable_secret(&master, body).is_err(),
            "the vault master must not open a backup export"
        );
    }

    #[test]
    fn a6_backup_export_uses_a_fresh_salt_every_time() {
        let v = vault_all_kinds();
        let backup = secrecy::SecretString::new("backup-passphrase-1".to_string());
        let a = export_native_gated(&v, false, &backup).unwrap();
        let b = export_native_gated(&v, false, &backup).unwrap();
        assert_ne!(a, b, "same vault, different container bytes");
        assert_ne!(a[5..21], b[5..21], "salt must not be reused");
    }

    #[test]
    fn native_export_skips_trash_and_local_state() {
        let mut v = vault_all_kinds();
        v.credentials[0].deleted_at = Some(7);
        v.verified_ids.push("x".into());
        let doc = export_native_json(&v);
        assert!(doc["vault"]["credentials"].as_array().unwrap().is_empty());
        assert!(doc["vault"]["verified_ids"].as_array().unwrap().is_empty());
        assert!(doc["vault"]["shared_grants"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_csv_covers_every_kind() {
        let csv = export_csv_full_result(&vault_all_kinds()).unwrap();
        for kind in ["login", "license", "note", "card", "identity", "ssh", "passkey", "totp"] {
            assert!(csv.contains(kind), "missing {kind} row");
        }
        assert!(csv.contains("JBSWY3DP"), "2FA secret must be in the full CSV");
    }

    #[test]
    fn native_backup_parses_through_the_real_sniffer() {
        let v = vault_all_kinds();
        let pw = secrecy::SecretString::new("backup-passphrase-1".to_string());
        let blob = export_native_encrypted(&v, &pw).unwrap();
        let path = std::env::temp_dir().join(format!("pv-native-{}.pvx", std::process::id()));
        std::fs::write(&path, &blob).unwrap();
        let parsed = crate::importer::parse_import_any(&path, None, Some(&pw)).unwrap();
        let _ = std::fs::remove_file(&path);
        match parsed {
            crate::importer::ParsedImport::Native(src, _) => {
                let mut dst = Vault::new();
                let mut s = crate::importer::ImportSummary::default();
                crate::importer::merge_native(
                    &mut dst,
                    *src,
                    &mut s,
                    crate::importer::MergeMode::SkipDupes,
                );
                assert_eq!(dst.passkeys.len(), 1);
                assert_eq!(dst.passkeys[0].private_key_pkcs8, vec![9, 8, 7]);
                assert_eq!(dst.totp_accounts.len(), 1);
                assert_eq!(dst.credentials.len(), 1);
                assert_eq!(dst.credentials[0].attachments[0].data, vec![1, 2, 3]);
                assert_eq!(s.passkeys, 1);
                assert_eq!(s.totp_accounts, 1);
            }
            crate::importer::ParsedImport::Rows(..) => panic!("native backup sniffed as rows"),
        }
    }

    #[test]
    fn a6_new_backup_refuses_the_master_and_legacy_keeps_it() {
        let v = vault_all_kinds();
        let backup = secrecy::SecretString::new("backup-passphrase-1".to_string());
        let master = secrecy::SecretString::new("master-password-1".to_string());
        let dir = std::env::temp_dir().join("pv_a6_import");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        // New export: master alone must not open it, even with no other error.
        let new_path = dir.join("new.pvx");
        std::fs::write(&new_path, export_native_gated(&v, false, &backup).unwrap()).unwrap();
        assert!(
            crate::importer::parse_import_any(&new_path, Some(&master), None).is_err(),
            "a PVBK1 backup must not open with the master password"
        );
        assert!(crate::importer::parse_import_any(&new_path, None, Some(&backup)).is_ok());
        // Wrong backup passphrase fails loudly, vault untouched (parse only).
        let wrong = secrecy::SecretString::new("wrong-backup-pass".to_string());
        assert!(crate::importer::parse_import_any(&new_path, None, Some(&wrong)).is_err());

        // Legacy `.pvx` (no PVBK1 tag) still opens with the master password.
        let doc = export_native_json(&v);
        let plain = serde_json::to_vec(&doc).unwrap();
        let legacy = crate::crypto::encrypt_vault_portable_secret(&master, &plain).unwrap();
        let legacy_path = dir.join("legacy.pvx");
        std::fs::write(&legacy_path, &legacy).unwrap();
        assert!(crate::importer::parse_import_any(&legacy_path, Some(&master), None).is_ok());
        assert!(crate::importer::parse_import_any(&legacy_path, None, Some(&backup)).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
