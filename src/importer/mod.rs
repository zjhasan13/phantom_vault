//! Phase 18 — Omni-Universal Zero-Failure Vault Importer.
//!
//! Format is sniffed, never asked. Every engine is total (never aborts the
//! batch on a bad row), secrets stay in-RAM only, and exact duplicates are
//! skipped case-insensitively.

pub mod bitwarden;
pub mod browser_csv;
pub mod browser_direct;
pub mod exporter;
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
    /// Identity structured parts (kind 5 only; Bitwarden company/city/
    /// state/postalCode/country). Others leave empty (String::default).
    pub company: String,
    pub city: String,
    pub state: String,
    pub zip: String,
    pub country: String,
    pub totp: String,
    pub backup: Vec<String>,
    /// Bitwarden login.passwordHistory (newest-first, capped at KEEP on merge).
    pub history: Vec<crate::models::PasswordHistoryEntry>,
    pub custom_text: Vec<(String, String)>,
    pub custom_hidden: Vec<(String, String)>,
    pub custom_check: Vec<(String, bool)>,
    pub custom_linked: Vec<(String, String)>, // (label, "username"|"password")
    /// Per-URL match rules index-aligned with `c` lines (Bitwarden UriMatchType
    /// mapped to our rule ids; missing/short = Default). Other engines leave empty.
    pub url_rules: Vec<u8>,
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

/// Parse-only half of the import pipeline (sniff → parse, NO merge).
/// Powers the dry-run preview: the caller dry-merges the returned rows into
/// a CLONED vault for exact counts, then merges for real only on confirm.
pub fn parse_import_file(
    path: &std::path::Path,
) -> Result<(Vec<RawItem>, ImportSummary)> {
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
    Ok((raws, summary))
}

/// Master entrypoint: sniff → parse → dedup → merge → persist-ready summary.
/// Never fails on bad ROWS (counts them); fails only on unreadable files or
/// encrypted exports that need user action.
/// (The GUI dry-run flow calls parse_import_file + merge directly; this stays
/// as the single-call convenience for tests and future headless callers.)
#[allow(dead_code)]
pub fn import_any_file(
    path: &std::path::Path,
    vault: &mut Vault,
) -> Result<ImportSummary> {
    let (raws, mut summary) = parse_import_file(path)?;
    merge(vault, raws, &mut summary);
    vault.ensure_folders();
    summary.folders = vault.folders.len();
    Ok(summary)
}

/// Login dedup key: title + username (case-insensitive, trimmed) + EXACT
/// password (case-sensitive — passwords are). Two rows sharing title/user
/// but different passwords are NEVER the same item (decoy vs real password,
/// rotation) and must both import.
fn dedup_key(title: &str, username: &str, password: &str) -> String {
    format!(
        "{}:{}:{}",
        title.trim().to_lowercase(),
        username.trim().to_lowercase(),
        password
    )
}

/// Duplicate probe for the login dedup path. Trashed items never block:
/// the user may re-add (or re-import) a credential whose older copy sits in
/// Trash awaiting its 30-day shred. An item is ONLY a duplicate when title,
/// username, AND password are all identical — a different password (rotation,
/// decoy/fake entry alongside the real one) ALWAYS imports visibly instead
/// of vanishing as a "duplicate". Pure — unit tested.
fn dup_login(vault: &Vault, title: &str, user: &str, password: &str) -> bool {
    let want = dedup_key(title, user, password);
    vault.credentials.iter().any(|c| {
        c.deleted_at.is_none() && dedup_key(&c.title, &c.username, &c.password) == want
    })
}

pub(crate) fn merge(vault: &mut Vault, raws: Vec<RawItem>, summary: &mut ImportSummary) {
    // Intra-batch fingerprints: the same row twice in ONE file imports once.
    let mut seen_batch: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in raws {
        let title = if r.title.trim().is_empty() { "(untitled)" } else { r.title.trim() }.to_string();
        let folder = folder_of(&r.folder);
        if !vault.folders.iter().any(|f| f == &folder) {
            vault.folders.push(folder.clone());
        }
        // Login-shaped rows (kind 1 + fallback arm) dedup within the batch.
        // Password-aware: identical rows collapse, but a second row with a
        // different password (or URL) imports instead of vanishing.
        if r.kind != 2 && r.kind != 3 && r.kind != 4 && r.kind != 5 && r.kind != 6 {
            let fp = format!("L\x00{}\x00{}", dedup_key(&title, &r.a, &r.b), r.c);
            if !seen_batch.insert(fp) {
                summary.duplicates_skipped += 1;
                continue;
            }
        }
        match r.kind {
            2 => {
                if vault.licenses.iter().any(|l| {
                    l.deleted_at.is_none()
                        && l.app_name.to_lowercase() == title.to_lowercase()
                        && l.license_key == r.a
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
                    custom_fields: to_custom(&r.custom_text, &r.custom_hidden, &r.custom_check, &r.custom_linked),
                    attachments: Vec::new(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                });
                summary.licenses += 1;
            }
            3 => {
                // Notes: same title AND same content (retitled edits re-import).
                if vault.notes.iter().any(|n| {
                    n.deleted_at.is_none()
                        && n.title.to_lowercase() == title.to_lowercase()
                        && n.content == r.a
                }) {
                    summary.duplicates_skipped += 1;
                    continue;
                }
                vault.notes.push(SecureNote { id: new_id(), title, content: r.a, folder, custom_fields: to_custom(&r.custom_text, &r.custom_hidden, &r.custom_check, &r.custom_linked), attachments: Vec::new(), travel_safe: false, favorite: false, deleted_at: None });
                summary.notes += 1;
            }
            4 => {
                // Cards: same number AND same expiry (renewals re-import).
                let (em, ey) = split_expiry(&r.c);
                if vault.cards.iter().any(|k| {
                    k.deleted_at.is_none()
                        && k.title.to_lowercase() == title.to_lowercase()
                        && k.card_number == r.b
                        && k.exp_month == em
                        && k.exp_year == ey
                }) {
                    summary.duplicates_skipped += 1;
                    continue;
                }
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
                    custom_fields: to_custom(&r.custom_text, &r.custom_hidden, &r.custom_check, &r.custom_linked),
                    attachments: Vec::new(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                });
                summary.cards += 1;
            }
            5 => {
                // Identities: same name AND same email (changed email re-imports).
                if vault.identities.iter().any(|i| {
                    i.deleted_at.is_none()
                        && i.title.to_lowercase() == title.to_lowercase()
                        && i.full_name.to_lowercase() == r.a.to_lowercase()
                        && i.email.to_lowercase() == r.c.to_lowercase()
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
                    company: r.company,
                    city: r.city,
                    state: r.state,
                    zip: r.zip,
                    country: r.country,
                    folder,
                    notes: r.notes,
                    custom_fields: to_custom(&r.custom_text, &r.custom_hidden, &r.custom_check, &r.custom_linked),
                    attachments: Vec::new(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                });
                summary.identities += 1;
            }
            6 => {
                // SSH: same title AND same private key (re-keys re-import).
                if vault.ssh_keys.iter().any(|s| {
                    s.deleted_at.is_none()
                        && s.title.to_lowercase() == title.to_lowercase()
                        && s.private_key == r.b
                }) {
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
                    custom_fields: to_custom(&r.custom_text, &r.custom_hidden, &r.custom_check, &r.custom_linked),
                    attachments: Vec::new(),
                    travel_safe: false,
                    favorite: false,
                    deleted_at: None,
                });
                summary.ssh_keys += 1;
            }
            _ => {
                if r.a.trim().is_empty() && r.b.trim().is_empty() {
                    summary.rows_failed += 1;
                    continue;
                }
                // URLs carry their match rules (index-aligned url_rules from
                // Bitwarden `match`; other engines leave it empty = Default).
                // Order-preserving dedup on the URL string; first rule wins.
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                let mut urls: Vec<crate::models::LoginUrl> = Vec::new();
                for (i, line) in r.c.lines().enumerate() {
                    let t = line.trim();
                    if t.is_empty() {
                        continue;
                    }
                    if !seen.insert(t.to_lowercase()) {
                        continue;
                    }
                    let rule = r.url_rules.get(i).copied().unwrap_or(0);
                    urls.push(crate::models::LoginUrl::new(t.to_string(), rule));
                }
                if dup_login(vault, &title, &r.a, &r.b) {
                    summary.duplicates_skipped += 1;
                    continue;
                }
                // Backup auto-sort + history are computed BEFORE the struct
                // move (both borrow `r` while other fields move out of it).
                let backup_codes = collect_backup(&r);
                let history: Vec<crate::models::PasswordHistoryEntry> = r
                    .history
                    .into_iter()
                    .take(crate::models::PASSWORD_HISTORY_KEEP)
                    .collect();
                vault.credentials.push(Credential {
                    id: new_id(),
                    title,
                    username: r.a,
                    password: r.b,
                    totp_secret: r.totp,
                    urls,
                    apps: Vec::new(),
                    // Backup auto-sort: named fields + notes sniff, capped/deduped.
                    backup_codes,
                    custom_fields: to_custom(&r.custom_text, &r.custom_hidden, &r.custom_check, &r.custom_linked),
                    notes: r.notes,
                    folder,
                    reprompt: false,
                    attachments: Vec::new(),
                    travel_safe: false,
                    // Imported now: rotation clock starts at import.
                    last_changed: crate::models::current_timestamp(),
                    password_history: history,
                    favorite: false,
                    deleted_at: None,
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

/// Normalize + report non-default parameters (HOTP counter, SHA256/512,
/// 8 digits, 60s period) that the login `totp_secret` slot CANNOT carry
/// (bare secret only). Callers stash the warning in notes + summary so the
/// user can verify codes instead of silently mistyping them as plain TOTP.
pub(crate) fn normalize_totp_with_meta(raw: &str) -> (String, Option<String>) {
    let t = raw.trim();
    if t.is_empty() {
        return (String::new(), None);
    }
    if t.to_lowercase().starts_with("otpauth://") {
        match crate::authenticator::google_migration::parse_otpauth_url(t) {
            Ok(acc) => {
                let mut flags = Vec::new();
                if acc.otp_type.eq_ignore_ascii_case("hotp") {
                    flags.push(format!("HOTP counter {}", acc.counter));
                }
                if acc.algorithm.to_uppercase() != "SHA1" {
                    flags.push(acc.algorithm.clone());
                }
                if acc.period != 30 {
                    flags.push(format!("{}s period", acc.period));
                }
                if acc.digits != 6 {
                    flags.push(format!("{} digits", acc.digits));
                }
                let warn = if flags.is_empty() {
                    None
                } else {
                    Some(format!(
                        "non-default TOTP params ({}) imported as standard TOTP — verify codes",
                        flags.join(", ")
                    ))
                };
                (acc.secret.clone(), warn)
            }
            Err(_) => (
                t.to_string(),
                Some("unparseable otpauth URL kept verbatim".to_string()),
            ),
        }
    } else {
        (t.to_string(), None)
    }
}

/// Apply `normalize_totp_with_meta` at a login parse site: returns the
/// (secret, notes) pair with any parameter warning preserved inline AND in
/// the summary (the original URL's counter/algo would otherwise vanish).
pub(crate) fn apply_totp(
    raw: &str,
    title: &str,
    mut notes: String,
    summary: &mut ImportSummary,
) -> (String, String) {
    let (secret, warn) = normalize_totp_with_meta(raw);
    if let Some(w) = warn {
        if !notes.is_empty() {
            notes.push('\n');
        }
        notes.push_str(&format!("[TOTP import note: {w}]"));
        summary.warnings.push(format!("{title}: {w}"));
    }
    (secret, notes)
}

/// Field-name gate for backup auto-sort: "backup"/"recovery" (+ plurals,
/// underscores, spaces) match. Compound names ("backupemail") also match —
/// the code-like line filter below is the real false-positive guard.
pub(crate) fn looks_like_backup_name(name: &str) -> bool {
    let n: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    n.contains("backup") || n.contains("recover") || n == "otpbackupcodes"
}

/// One line is code-like: 6–16 alnum chars after stripping spaces/dashes
/// (covers 8/10-digit authenticator codes, hex recovery keys, xxx-xxx).
fn code_like(line: &str) -> bool {
    let s: String = line.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    (6..=16).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Pull code-like lines out of a blob (named-field path).
fn code_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && code_like(l))
        .take(50)
        .map(str::to_string)
        .collect()
}

/// Scan free-text notes for a backup header ("Backup codes:", "Recovery—")
/// and harvest the code block beneath it. Header-with-colon needs ≥1 code,
/// bare headers need ≥2 (avoids "Backup: yes" false positives).
pub(crate) fn sniff_backup_in_notes(notes: &str) -> Vec<String> {
    let lines: Vec<&str> = notes.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        let flat: String = t.to_lowercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        let is_header = (flat.contains("backup") || flat.contains("recover")) && t.len() < 80;
        if is_header {
            let strict = !t.ends_with(':');
            let mut block = Vec::new();
            let mut j = i + 1;
            while j < lines.len() && out.len() + block.len() < 50 {
                let u = lines[j].trim();
                if u.is_empty() {
                    j += 1;
                    continue;
                }
                if code_like(u) {
                    block.push(u.to_string());
                    j += 1;
                } else {
                    break;
                }
            }
            if block.len() >= if strict { 2 } else { 1 } {
                out.extend(block);
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Uniform backup harvest for the login merge arm: named custom fields
/// (text + hidden) plus the notes sniff. Values stay where they are —
/// codes are COPIED into backup_codes, never moved.
pub(crate) fn collect_backup(r: &RawItem) -> Vec<String> {
    let mut out: Vec<String> = r.backup.clone();
    for (name, value) in r.custom_text.iter().chain(r.custom_hidden.iter()) {
        if !looks_like_backup_name(name) {
            continue;
        }
        let mut lines = code_lines(value);
        if lines.is_empty() {
            // Single-code field ("Backup PIN: 482917"): keep the raw value.
            let v = value.trim();
            if !v.is_empty() && v.len() <= 64 {
                lines.push(v.to_string());
            }
        }
        out.extend(lines);
        if out.len() >= 50 {
            break;
        }
    }
    out.extend(sniff_backup_in_notes(&r.notes));
    out.truncate(50);
    let mut seen = std::collections::HashSet::new();
    out.retain(|c| seen.insert(c.clone()));
    out
}

/// Bitwarden `passwordHistory[].lastUsedDate` ISO8601 → unix seconds.
/// Handles `Z` and `±hh:mm` offsets, fractional seconds ignored.
/// Returns None when the stamp is unreadable (caller skips the entry).
pub(crate) fn parse_bw_datetime(raw: &str) -> Option<u64> {
    let t = raw.trim();
    let (head, off_secs) = if let Some(stripped) = t.strip_suffix(['Z', 'z']) {
        (stripped, 0i64)
    } else if t.len() >= 6 {
        // Offset suffix is ASCII (±hh:mm). Use `get` (never `split_at`/byte
        // indexing) so a malformed multi-byte stamp returns None instead of
        // panicking on a non-char boundary.
        let tail = t.get(t.len() - 6..)?;
        let sign = match tail.as_bytes()[0] {
            b'+' => 1i64,
            b'-' => -1i64,
            _ => return None,
        };
        let hh: i64 = tail.get(1..3)?.parse().ok()?;
        let mm: i64 = tail.get(4..6)?.parse().ok()?;
        if tail.as_bytes()[3] != b':' {
            return None;
        }
        (t.get(..t.len() - 6)?, sign * (hh * 3600 + mm * 60))
    } else {
        return None;
    };
    let head = head.split('.').next().unwrap_or(head); // drop .000
    let (date, time) = head.split_once(['T', ' '])?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) =
        (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    let mut tm = time.split(':');
    let (hh, mm, ss): (i64, i64, i64) =
        (tm.next()?.parse().ok()?, tm.next()?.parse().ok()?, tm.next()?.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Howard Hinnant days-from-civil → unix days.
    let (y2, m2) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (m2 - 3) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe.div_euclid(4) - yoe.div_euclid(100) + doy;
    let days = era * 146097 + doe - 719468;
    let ts = days * 86400 + hh * 3600 + mm * 60 + ss - off_secs;
    if ts < 0 {
        return None;
    }
    Some(ts as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Credential;

    fn trashed_login(title: &str, user: &str) -> Credential {
        Credential {
            id: "old".into(),
            title: title.into(),
            username: user.into(),
            password: "oldpw".into(),
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
            last_changed: 0,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: Some(1000),
        }
    }

    fn login_raw(title: &str, user: &str) -> RawItem {
        RawItem {
            kind: 1,
            title: title.into(),
            a: user.into(),
            b: "newpw".into(),
            ..Default::default()
        }
    }

    #[test]
    fn trashed_dupes_do_not_block_reimport() {
        let mut v = Vault::new();
        v.credentials.push(trashed_login("GitHub", "me"));
        // Same title+user as the trashed copy must IMPORT (not skip).
        let mut s = ImportSummary::default();
        merge(&mut v, vec![login_raw("GitHub", "me")], &mut s);
        assert_eq!(s.logins, 1);
        assert_eq!(s.duplicates_skipped, 0);
        // ...but the now-LIVE copy still dedups a second import.
        let mut s2 = ImportSummary::default();
        merge(&mut v, vec![login_raw("github", "ME")], &mut s2);
        assert_eq!(s2.logins, 0);
        assert_eq!(s2.duplicates_skipped, 1);
    }

    #[test]
    fn trashed_notes_and_cards_reimport() {
        let mut v = Vault::new();
        v.notes.push(crate::models::SecureNote {
            id: "n-old".into(),
            title: "Memo".into(),
            content: "gone".into(),
            folder: "General".into(),
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: Some(1000),
        });
        let mut s = ImportSummary::default();
        merge(
            &mut v,
            vec![RawItem {
                kind: 3,
                title: "Memo".into(),
                a: "fresh".into(),
                ..Default::default()
            }],
            &mut s,
        );
        assert_eq!(s.notes, 1);
        assert_eq!(s.duplicates_skipped, 0);
    }

    #[test]
    fn bw_datetime_handles_z_and_offsets() {
        // 2024-06-01T12:00:00Z == 2024-06-01T14:00:00+02:00.
        let a = parse_bw_datetime("2024-06-01T12:00:00.000Z").unwrap();
        let b = parse_bw_datetime("2024-06-01T14:00:00+02:00").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, 1_717_243_200);
        assert!(parse_bw_datetime("garbage").is_none());
        assert!(parse_bw_datetime("2024-13-01T00:00:00Z").is_none());
    }

    #[test]
    fn backup_sniff_avoids_false_positives() {
        // "Backup: yes" (bare header, single non-code) → nothing.
        assert!(sniff_backup_in_notes("Notes here\nBackup: yes\nDone").is_empty());
        // Colon header + one code → harvest.
        assert_eq!(
            sniff_backup_in_notes("Recovery codes:\nAB12CD34"),
            vec!["AB12CD34".to_string()]
        );
        // Bare header needs 2+ codes.
        assert!(sniff_backup_in_notes("My recovery\nonlyone").is_empty());
        assert!(!looks_like_backup_name("Username"));
        assert!(looks_like_backup_name("recovery_codes"));
    }

    #[test]
    fn dry_run_parse_never_touches_live_vault() {
        // The GUI preview contract: parse → dry-merge on a CLONE for exact
        // counts. The live vault must be byte-identical until Confirm.
        let dir = std::env::temp_dir().join(format!("pv-dryrun-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("chrome.csv");
        std::fs::write(
            &file,
            "name,url,username,password\nGitHub,https://github.com,me,pw1\nGitHub,https://github.com,me,pw2\n",
        )
        .unwrap();
        let live = Vault::new();
        let (raws, summary) = parse_import_file(&file).unwrap();
        assert_eq!(raws.len(), 2);
        assert!(live.credentials.is_empty());
        let mut probe = live.clone();
        let mut dry = ImportSummary { source: summary.source.clone(), ..Default::default() };
        merge(&mut probe, raws.clone(), &mut dry);
        // Same title+user, different passwords → both import, none skipped.
        assert_eq!(dry.logins, 2);
        assert_eq!(dry.duplicates_skipped, 0);
        assert!(live.credentials.is_empty());
        assert_eq!(probe.credentials.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_reimports_but_identical_skips() {
        let mut v = Vault::new();
        let mut s = ImportSummary::default();
        merge(&mut v, vec![login_raw("GitHub", "me")], &mut s);
        assert_eq!(s.logins, 1);
        // Same title+user but ROTATED password (no shared URL) → visible import.
        let mut rotated = login_raw("GitHub", "me");
        rotated.b = "rotated-pw".into();
        let mut s2 = ImportSummary::default();
        merge(&mut v, vec![rotated], &mut s2);
        assert_eq!(s2.logins, 1);
        assert_eq!(s2.duplicates_skipped, 0);
        assert_eq!(v.credentials.len(), 2);
        // Identical row twice in ONE batch → second skipped in-batch.
        let mut s3 = ImportSummary::default();
        merge(&mut v, vec![login_raw("GitHub", "me"), login_raw("GitHub", "me")], &mut s3);
        assert_eq!(s3.logins, 0);
        assert_eq!(s3.duplicates_skipped, 2);
    }

    #[test]
    fn same_user_different_password_never_drops_either() {
        // The Facebook data-loss case: decoy/fake entries plus the ONE real
        // password, all sharing title + username + URL. Every distinct
        // password must survive the import.
        fn fb(pw: &str) -> RawItem {
            RawItem {
                kind: 1,
                title: "Facebook".into(),
                a: "me".into(),
                b: pw.into(),
                c: "https://facebook.com".into(),
                ..Default::default()
            }
        }
        let mut v = Vault::new();
        let mut s = ImportSummary::default();
        merge(&mut v, vec![fb("fake-1"), fb("REAL-PW"), fb("fake-2")], &mut s);
        assert_eq!(s.logins, 3);
        assert_eq!(s.duplicates_skipped, 0);
        assert!(v.credentials.iter().any(|c| c.password == "REAL-PW"));
        // Re-import of the identical batch merges nothing and wipes nothing.
        let mut s2 = ImportSummary::default();
        merge(&mut v, vec![fb("fake-1"), fb("REAL-PW"), fb("fake-2")], &mut s2);
        assert_eq!(s2.logins, 0);
        assert_eq!(s2.duplicates_skipped, 3);
        assert_eq!(v.credentials.len(), 3);
        assert!(v.credentials.iter().any(|c| c.password == "REAL-PW"));
    }

    #[test]
    fn totp_meta_flags_non_default_params() {
        // Plain secret: clean.
        let (s, w) = normalize_totp_with_meta("JBSWY3DPEHPK3PXP");
        assert_eq!(s, "JBSWY3DPEHPK3PXP");
        assert!(w.is_none());
        // otpauth URL with HOTP counter + SHA256 → secret + loud warning.
        let (s2, w2) = normalize_totp_with_meta(
            "otpauth://hotp/X:a@x?secret=JBSWY3DPEHPK3PXP&issuer=X&algorithm=SHA256&counter=7",
        );
        assert_eq!(s2, "JBSWY3DPEHPK3PXP");
        let w2 = w2.unwrap();
        assert!(w2.contains("HOTP counter 7"));
        assert!(w2.contains("SHA256"));
    }

    #[test]
    fn bw_datetime_offset_parses_and_unicode_never_panics() {
        // Same instant: Z, +00:00, and +05:30 / -05:30 offsets.
        let z = parse_bw_datetime("2024-06-01T12:00:00Z").unwrap();
        assert_eq!(parse_bw_datetime("2024-06-01T12:00:00+00:00"), Some(z));
        assert_eq!(parse_bw_datetime("2024-06-01T17:30:00+05:30"), Some(z));
        assert_eq!(parse_bw_datetime("2024-06-01T06:30:00-05:30"), Some(z));
        // Fractional seconds are dropped.
        assert_eq!(parse_bw_datetime("2024-06-01T12:00:00.123Z"), Some(z));
        // Malformed multi-byte stamps must return None, not panic on a
        // non-char-boundary slice.
        assert_eq!(parse_bw_datetime("€abcd"), None);
        assert_eq!(parse_bw_datetime("তাংখ্যা"), None);
        assert_eq!(parse_bw_datetime("2024-06-01T12:00:00+০৫:৩০"), None);
    }
}
