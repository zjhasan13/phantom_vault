//! Phase 18 — Omni-Universal Zero-Failure Vault Importer.
//!
//! Format is sniffed, never asked. Every engine is total (never aborts the
//! batch on a bad row), secrets stay in-RAM only, and exact duplicates are
//! skipped case-insensitively.

pub mod bitwarden;
pub mod browser_csv;
pub mod fuzzy;
pub mod keepass;
pub mod onepassword;
pub mod sniffer;

use crate::error::{Result, VaultError};
use crate::models::{
    Credential, IdentityItem, PaymentCard, SecureNote, SoftwareLicense, SshKeyItem, Vault,
    DEFAULT_FOLDER,
};

/// One normalized row from any engine. Unused kinds stay empty.
#[derive(Debug, Default, Clone)]
pub struct RawItem {
    pub kind: i32, // 1 login, 2 license, 3 note, 4 card, 5 identity, 6 ssh
    pub title: String,
    pub a: String,
    pub b: String,
    pub c: String,
    pub d: String,
    pub e: String,
    pub notes: String,
    pub folder: String,
    pub totp: String,
    pub backup: Vec<String>,
    pub custom_text: Vec<(String, String)>,
    pub custom_hidden: Vec<(String, String)>,
    pub custom_check: Vec<(String, bool)>,
    pub custom_linked: Vec<(String, String)>, // (label, "username"|"password")
}

/// Field layout per kind (mirrors main.rs push_new_item):
/// login: a=user b=pass c=urls(\n) totp backup customs
/// license: a=key b=expiry | note: a=content
/// card: a=holder b=number c=exp d=cvv | identity: a..e | ssh: a=pub b=priv c=fp
#[derive(Debug, Default)]
pub struct ImportSummary {
    pub source: String,
    pub logins: usize,
    pub licenses: usize,
    pub notes: usize,
    pub cards: usize,
    pub identities: usize,
    pub ssh_keys: usize,
    pub folders: usize,
    pub duplicates_skipped: usize,
    pub rows_failed: usize,
    pub warnings: Vec<String>,
}

impl ImportSummary {
    pub fn total(&self) -> usize {
        self.logins + self.licenses + self.notes + self.cards + self.identities + self.ssh_keys
    }

    pub fn headline(&self) -> String {
        let mut extra = String::new();
        if self.rows_failed > 0 {
            extra.push_str(&format!(", ⚠️ {} bad rows skipped", self.rows_failed));
        }
        for w in &self.warnings {
            extra.push_str(&format!(" | ⚠️ {w}"));
        }
        format!(
            "✨ {} — ✅ {} items ({} logins, {} notes/cards) in {} folders, ⏭️ {} dupes skipped{}",
            self.source,
            self.total(),
            self.logins,
            self.notes + self.cards,
            self.folders,
            self.duplicates_skipped,
            extra
        )
    }
}

fn new_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let n = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("imp{ms}-{n}")
}

fn folder_of(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() {
        DEFAULT_FOLDER.to_string()
    } else {
        t.to_string()
    }
}

fn to_custom(
    text: &[(String, String)],
    hidden: &[(String, String)],
    check: &[(String, bool)],
    linked: &[(String, String)],
) -> Vec<crate::models::CustomField> {
    use crate::models::{CustomField, CustomFieldType};
    let mut out = Vec::new();
    for (n, v) in text {
        out.push(CustomField { name: n.clone(), value: v.clone(), field_type: CustomFieldType::Text });
    }
    for (n, v) in hidden {
        out.push(CustomField { name: n.clone(), value: v.clone(), field_type: CustomFieldType::Hidden });
    }
    for (n, v) in check {
        out.push(CustomField {
            name: n.clone(),
            value: v.to_string(),
            field_type: CustomFieldType::Checkbox,
        });
    }
    for (n, v) in linked {
        let target = if v == "username" { "username" } else { "password" };
        out.push(CustomField {
            name: n.clone(),
            value: target.to_string(),
            field_type: CustomFieldType::Linked,
        });
    }
    out
}

/// Master entrypoint: sniff → parse → dedup → merge → persist-ready summary.
/// Never fails on bad ROWS (counts them); fails only on unreadable files or
/// encrypted exports that need user action.
pub fn import_any_file(
    path: &std::path::Path,
    vault: &mut Vault,
) -> Result<ImportSummary> {
    let bytes = std::fs::read(path)
        .map_err(|e| VaultError::Sync(format!("cannot read import file: {e}")))?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(VaultError::Sync("import file too large (64MB cap)".into()));
    }
    let format = sniffer::sniff(&bytes)?;
    let mut summary = ImportSummary { source: format.label(), ..Default::default() };
    let raws = match format {
        sniffer::Format::BitwardenJson => bitwarden::parse_json(&bytes, &mut summary)?,
        sniffer::Format::BitwardenCsv => bitwarden::parse_csv(&bytes, &mut summary)?,
        sniffer::Format::KeepassXml => keepass::parse_xml(&bytes, &mut summary)?,
        sniffer::Format::KeepassCsv => keepass::parse_csv(&bytes, &mut summary)?,
        sniffer::Format::OnePasswordCsv => onepassword::parse_csv(&bytes, &mut summary)?,
        sniffer::Format::ProtonJson => onepassword::parse_proton(&bytes, &mut summary)?,
        sniffer::Format::ChromeCsv
        | sniffer::Format::SafariCsv
        | sniffer::Format::LastPassCsv => browser_csv::parse(&bytes, &format, &mut summary)?,
        sniffer::Format::GenericJson => bitwarden::parse_generic_json(&bytes, &mut summary)?,
        sniffer::Format::FuzzyCsv(delim) => fuzzy::parse(&bytes, delim, &mut summary)?,
    };
    merge(vault, raws, &mut summary);
    vault.ensure_folders();
    summary.folders = vault.folders.len();
    Ok(summary)
}

fn dup_login(vault: &Vault, title: &str, user: &str) -> bool {
    vault.credentials.iter().any(|c| {
        c.title.to_lowercase() == title.to_lowercase()
            && c.username.to_lowercase() == user.to_lowercase()
    })
}

fn merge(vault: &mut Vault, raws: Vec<RawItem>, summary: &mut ImportSummary) {
    for r in raws {
        let title = if r.title.trim().is_empty() { "(untitled)" } else { r.title.trim() }.to_string();
        let folder = folder_of(&r.folder);
        if !vault.folders.iter().any(|f| f == &folder) {
            vault.folders.push(folder.clone());
        }
        match r.kind {
            2 => {
                if vault.licenses.iter().any(|l| {
                    l.app_name.to_lowercase() == title.to_lowercase() && l.license_key == r.a
                }) {
                    summary.duplicates_skipped += 1;
                    continue;
                }
                vault.licenses.push(SoftwareLicense {
                    id: new_id(),
                    app_name: title,
                    license_key: r.a,
                    expiry_date: (!r.b.trim().is_empty()).then(|| r.b.clone()),
                    folder,
                });
                summary.licenses += 1;
            }
            3 => {
                if vault.notes.iter().any(|n| n.title.to_lowercase() == title.to_lowercase()) {
                    summary.duplicates_skipped += 1;
                    continue;
                }
                vault.notes.push(SecureNote { id: new_id(), title, content: r.a, folder });
                summary.notes += 1;
            }
            4 => {
                if vault.cards.iter().any(|k| {
                    k.title.to_lowercase() == title.to_lowercase() && k.card_number == r.b
                }) {
                    summary.duplicates_skipped += 1;
                    continue;
                }
                let (em, ey) = split_expiry(&r.c);
                vault.cards.push(PaymentCard {
                    id: new_id(),
                    title,
                    cardholder_name: r.a,
                    card_number: r.b,
                    exp_month: em,
                    exp_year: ey,
                    cvv: r.d,
                    folder,
                    notes: r.notes,
                });
                summary.cards += 1;
            }
            5 => {
                if vault.identities.iter().any(|i| {
                    i.title.to_lowercase() == title.to_lowercase()
                        && i.full_name.to_lowercase() == r.a.to_lowercase()
                }) {
                    summary.duplicates_skipped += 1;
                    continue;
                }
                vault.identities.push(IdentityItem {
                    id: new_id(),
                    title,
                    full_name: r.a,
                    nid_or_passport: r.b,
                    email: r.c,
                    phone: r.d,
                    address: r.e,
                    folder,
                    notes: r.notes,
                });
                summary.identities += 1;
            }
            6 => {
                if vault.ssh_keys.iter().any(|s| s.title.to_lowercase() == title.to_lowercase()) {
                    summary.duplicates_skipped += 1;
                    continue;
                }
                vault.ssh_keys.push(SshKeyItem {
                    id: new_id(),
                    title,
                    public_key: r.a,
                    private_key: r.b,
                    fingerprint: r.c,
                    folder,
                    notes: r.notes,
                });
                summary.ssh_keys += 1;
            }
            _ => {
                if r.a.trim().is_empty() && r.b.trim().is_empty() {
                    summary.rows_failed += 1;
                    continue;
                }
                if dup_login(vault, &title, &r.a) {
                    summary.duplicates_skipped += 1;
                    continue;
                }
                vault.credentials.push(Credential {
                    id: new_id(),
                    title,
                    username: r.a,
                    password: r.b,
                    totp_secret: r.totp,
                    urls: r.c.lines().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect(),
                    backup_codes: r.backup,
                    custom_fields: to_custom(&r.custom_text, &r.custom_hidden, &r.custom_check, &r.custom_linked),
                    notes: r.notes,
                    folder,
                    reprompt: false,
                });
                summary.logins += 1;
            }
        }
    }
    vault.folders.sort();
    vault.folders.dedup();
}

fn split_expiry(raw: &str) -> (String, String) {
    let t = raw.trim().replace([' ', '-', '.'], "/");
    let mut parts = t.split('/');
    let m = parts.next().unwrap_or("").trim().to_string();
    let y = parts.next().unwrap_or("").trim().to_string();
    (m, y)
}
