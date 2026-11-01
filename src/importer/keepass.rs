//! KeePass 2.x XML (`<KeePassFile>`), KeePass CSV, and A13 KDBX 3.1/4.

use super::{ImportSummary, RawItem};
use crate::error::{Result, VaultError};
use crate::models::Vault;
use quick_xml::events::Event;
use quick_xml::Reader;
use secrecy::{ExposeSecret, SecretString};

struct KEntry {
    title: String,
    user: String,
    pass: String,
    url: String,
    notes: String,
    otp: String,
    custom: Vec<(String, String)>,
}

/// Resolve one XML entity body (the text between `&` and `;`, as delivered
/// by quick-xml 0.41's `GeneralRef` event): the 5 predefined entities plus
/// decimal/hex char refs. Anything else → None (fail-closed).
fn resolve_xml_ref(name: &str) -> Option<String> {
    match name {
        "amp" => Some("&".to_string()),
        "lt" => Some("<".to_string()),
        "gt" => Some(">".to_string()),
        "quot" => Some("\"".to_string()),
        "apos" => Some("'".to_string()),
        _ => {
            let digits = name.strip_prefix('#')?;
            let n = if let Some(hex) = digits.strip_prefix(['x', 'X']) {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                digits.parse::<u32>().ok()?
            };
            // from_u32 rejects surrogates + out-of-range → None.
            char::from_u32(n).map(|c| c.to_string())
        }
    }
}

/// Parse KeePass XML. Group hierarchy becomes `Parent / Child` folders;
/// `<History>` snapshots are skipped (current entries only).
pub fn parse_xml(bytes: &[u8], summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
    let text = super::sniffer::decode_text(bytes);
    let mut reader = Reader::from_str(&text);
    reader.config_mut().trim_text(true);

    let mut out = Vec::new();
    let mut group_stack: Vec<String> = Vec::new();
    let mut group_depth = 0usize;
    // Entry state.
    let mut in_entry = false;
    let mut entry_depth = 0usize;
    let mut in_history = false;
    let mut in_string = false;
    let mut cur_key = String::new();
    let mut cur_val = String::new();
    let mut cur = KEntry {
        title: String::new(),
        user: String::new(),
        pass: String::new(),
        url: String::new(),
        notes: String::new(),
        otp: String::new(),
        custom: Vec::new(),
    };
    let mut group_name_pending = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(VaultError::Sync(format!("bad KeePass XML: {e}"))),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                match name.as_str() {
                    "Group" => {
                        group_depth += 1;
                        // <Name> directly under a Group carries its name.
                        group_name_pending = true;
                    }
                    "Entry" => {
                        // Entries end the pending group-name (Name came before).
                        group_name_pending = false;
                        if !in_entry {
                            in_entry = true;
                            entry_depth = 1;
                            in_history = false;
                            cur = KEntry {
                                title: String::new(),
                                user: String::new(),
                                pass: String::new(),
                                url: String::new(),
                                notes: String::new(),
                                otp: String::new(),
                                custom: Vec::new(),
                            };
                        } else {
                            entry_depth += 1;
                        }
                    }
                    "History" => {
                        if in_entry {
                            in_history = true;
                            entry_depth += 1;
                        }
                    }
                    "String" => {
                        if in_entry {
                            entry_depth += 1;
                            if !in_history {
                                in_string = true;
                                cur_key.clear();
                                cur_val.clear();
                            }
                        }
                    }
                    _ => {
                        if in_entry {
                            entry_depth += 1;
                        }
                    }
                }
            }
            Ok(Event::Empty(_)) => {}
            Ok(Event::Text(e)) => {
                // quick-xml 0.41: `unescape()` removed; `xml_content()`
                // resolves the same predefined entities + char refs.
                // KeePass exports declare `<?xml version="1.0"?>`.
                // APPEND (not assign): 0.41 fragments text around entity
                // refs (Text + GeneralRef events), so one Value arrives
                // as several pieces that must be concatenated.
                let txt = e
                    .xml_content(quick_xml::XmlVersion::Explicit1_0)
                    .unwrap_or_default()
                    .into_owned();
                if group_name_pending && !in_entry {
                    // Push every group level verbatim (Root DB name included):
                    // deterministic, never loses hierarchy info.
                    if !txt.trim().is_empty() {
                        group_stack.push(txt.trim().to_string());
                    }
                    group_name_pending = false;
                } else if in_string && !in_history {
                    if cur_key.is_empty() {
                        cur_key.push_str(&txt);
                    } else {
                        cur_val.push_str(&txt);
                    }
                }
            }
            Ok(Event::GeneralRef(e)) => {
                // Entity fragment (`&amp;`, `&#65;`, …) inside a Key/Value.
                // Unknown/custom entities → contribute nothing (fail-closed:
                // no raw `&foo;` ever lands in the vault).
                if in_string && !in_history {
                    if let Some(txt) = resolve_xml_ref(&e.decode().unwrap_or_default()) {
                        if cur_key.is_empty() {
                            cur_key.push_str(&txt);
                        } else {
                            cur_val.push_str(&txt);
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                match name.as_str() {
                    "Group" => {
                        group_stack.pop();
                        group_depth = group_depth.saturating_sub(1);
                        group_name_pending = false;
                    }
                    "String" => {
                        if in_entry && !in_history {
                            match cur_key.as_str() {
                                "Title" => cur.title = cur_val.clone(),
                                "UserName" => cur.user = cur_val.clone(),
                                "Password" => cur.pass = cur_val.clone(),
                                "URL" => cur.url = cur_val.clone(),
                                "Notes" => cur.notes = cur_val.clone(),
                                "otp" | "TOTP" | "totp" => cur.otp = cur_val.clone(),
                                // KeePass custom String fields ride as Text
                                // customs (protected values arrive decrypted
                                // from the XML — same trust as the password).
                                _ => {
                                    let k = cur_key.trim();
                                    let v = cur_val.trim();
                                    if !k.is_empty() && !v.is_empty() {
                                        cur.custom.push((k.to_string(), v.to_string()));
                                    }
                                }
                            }
                        }
                        in_string = false;
                        entry_depth = entry_depth.saturating_sub(1);
                    }
                    "History" => {
                        in_history = false;
                        entry_depth = entry_depth.saturating_sub(1);
                    }
                    "Entry" => {
                        if entry_depth > 1 {
                            entry_depth -= 1;
                        } else if in_entry {
                            in_entry = false;
                            if cur.title.is_empty() && cur.user.is_empty() && cur.pass.is_empty() {
                                summary.rows_failed += 1;
                            } else {
                                let folder = group_stack.join(" / ");
                                let (totp, notes) = super::apply_totp(
                                    &cur.otp,
                                    &cur.title,
                                    cur.notes.clone(),
                                    summary,
                                );
                                out.push(RawItem {
                                    kind: 1,
                                    title: cur.title.clone(),
                                    a: cur.user.clone(),
                                    b: cur.pass.clone(),
                                    c: cur.url.clone(),
                                    totp,
                                    notes,
                                    folder,
                                    custom_text: cur.custom.clone(),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                    _ => {
                        entry_depth = entry_depth.saturating_sub(1);
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

/// A13: cap the KDF work declared in the (plaintext) KDBX header before the
/// crate allocates/iterates. A hostile file must not be able to request
/// gigabytes of Argon2 memory or unbounded AES rounds.
const KDBX_MAX_ARGON2_MEMORY: u64 = 1024 * 1024 * 1024; // 1 GiB
const KDBX_MAX_ARGON2_ITERATIONS: u64 = 200_000;
const KDBX_MAX_PARALLELISM: u32 = 64;
const KDBX_MAX_AES_ROUNDS: u64 = 20_000_000;

fn kdbx_kdf_guard(bytes: &[u8]) -> std::result::Result<(), String> {
    if bytes.len() < 12 {
        return Err("KDBX file is truncated".to_string());
    }
    let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let major = (version >> 16) & 0xFFFF;
    if major != 3 && major != 4 {
        return Err(format!("unsupported KDBX version {major}.x"));
    }
    let mut off = 12usize;
    let mut kdf_params: Option<&[u8]> = None;
    let mut transform_rounds: Option<u64> = None;
    loop {
        if off + 5 > bytes.len() {
            return Err("KDBX header is truncated".to_string());
        }
        let id = bytes[off];
        let len =
            u32::from_le_bytes([bytes[off + 1], bytes[off + 2], bytes[off + 3], bytes[off + 4]])
                as usize;
        off += 5;
        if id == 0 {
            break;
        }
        if len > 64 * 1024 || off + len > bytes.len() {
            return Err("KDBX header field is invalid".to_string());
        }
        let data = &bytes[off..off + len];
        off += len;
        match id {
            // KDBX3 TransformRounds.
            6 if len == 8 => {
                transform_rounds = Some(u64::from_le_bytes(data.try_into().unwrap()));
            }
            // KDBX4 KdfParameters (VariantDictionary).
            11 => kdf_params = Some(data),
            _ => {}
        }
    }
    if let Some(dict) = kdf_params {
        return check_kdbx4_kdf(dict);
    }
    match transform_rounds {
        Some(r) if r <= KDBX_MAX_AES_ROUNDS => Ok(()),
        Some(_) => Err("KDBX KDF rounds are too high — refusing a hostile header".to_string()),
        None => Err("KDBX header has no KDF parameters".to_string()),
    }
}

fn check_kdbx4_kdf(dict: &[u8]) -> std::result::Result<(), String> {
    if dict.len() < 2 {
        return Err("KDBX KDF parameters are truncated".to_string());
    }
    let mut off = 2usize; // version u16
    let mut uuid: Option<&[u8]> = None;
    let mut memory = None;
    let mut iterations = None;
    let mut parallelism = None;
    let mut rounds = None;
    while off < dict.len() {
        let ty = dict[off];
        off += 1;
        if ty == 0 {
            break;
        }
        if off + 4 > dict.len() {
            return Err("KDBX KDF entry is truncated".to_string());
        }
        let klen = u32::from_le_bytes([dict[off], dict[off + 1], dict[off + 2], dict[off + 3]])
            as usize;
        off += 4;
        if klen == 0 || klen > 64 || off + klen > dict.len() {
            return Err("KDBX KDF key is invalid".to_string());
        }
        let key = &dict[off..off + klen];
        off += klen;
        if off + 4 > dict.len() {
            return Err("KDBX KDF value is truncated".to_string());
        }
        let vlen = u32::from_le_bytes([dict[off], dict[off + 1], dict[off + 2], dict[off + 3]])
            as usize;
        off += 4;
        if vlen > 1024 || off + vlen > dict.len() {
            return Err("KDBX KDF value is invalid".to_string());
        }
        let val = &dict[off..off + vlen];
        off += vlen;
        match key {
            b"$UUID" if vlen == 16 => uuid = Some(val),
            b"M" if vlen == 8 && ty == 0x05 => {
                memory = Some(u64::from_le_bytes(val.try_into().unwrap()))
            }
            b"I" if vlen == 8 && ty == 0x05 => {
                iterations = Some(u64::from_le_bytes(val.try_into().unwrap()))
            }
            b"P" if vlen == 4 && ty == 0x04 => {
                parallelism = Some(u32::from_le_bytes(val.try_into().unwrap()))
            }
            b"R" if vlen == 8 && ty == 0x05 => {
                rounds = Some(u64::from_le_bytes(val.try_into().unwrap()))
            }
            _ => {}
        }
    }
    let Some(uuid) = uuid else {
        return Err("KDBX KDF is missing its UUID".to_string());
    };
    const ARGON2: [u8; 16] = [
        0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a,
        0x0c,
    ];
    const ARGON2ID: [u8; 16] = [
        0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1,
        0xe6,
    ];
    const AES_KDBX3: [u8; 16] = [
        0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f,
        0xea,
    ];
    const AES_KDBX4: [u8; 16] = [
        0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64, 0x82,
        0x38,
    ];
    if uuid == ARGON2 || uuid == ARGON2ID {
        let (m, i, p) = (
            memory.ok_or_else(|| "KDBX Argon2 memory is missing".to_string())?,
            iterations.ok_or_else(|| "KDBX Argon2 iterations are missing".to_string())?,
            parallelism.ok_or_else(|| "KDBX Argon2 parallelism is missing".to_string())?,
        );
        if m == 0 || m > KDBX_MAX_ARGON2_MEMORY {
            return Err("KDBX Argon2 memory request is too high — refusing".to_string());
        }
        if i == 0 || i > KDBX_MAX_ARGON2_ITERATIONS {
            return Err("KDBX Argon2 iteration count is too high — refusing".to_string());
        }
        if p == 0 || p > KDBX_MAX_PARALLELISM {
            return Err("KDBX Argon2 parallelism is invalid — refusing".to_string());
        }
        return Ok(());
    }
    if uuid == AES_KDBX3 || uuid == AES_KDBX4 {
        return match rounds {
            Some(r) if r > 0 && r <= KDBX_MAX_AES_ROUNDS => Ok(()),
            Some(_) => Err("KDBX AES-KDF rounds are too high — refusing".to_string()),
            None => Err("KDBX AES-KDF rounds are missing".to_string()),
        };
    }
    Err("KDBX uses an unsupported key-derivation function".to_string())
}

/// A13: open an encrypted KeePass KDBX 3.1/4 database and map its current
/// entries through the same `RawItem` pipeline as the XML importer.
///
/// The `keepass` crate performs the container crypto (Argon2/AES-KDF,
/// AES-256-CBC/ChaCha20, HMAC block stream, inner stream). We only map the
/// decrypted model, so there is no hand-rolled KDBX cryptography here.
///
/// Honest scope: password or password+keyfile; KDBX attachment bytes are not
/// imported (same as the XML/CSV paths). Recycled/deleted entries follow the
/// file's group layout, exactly like the XML import.
pub fn parse_kdbx(
    bytes: &[u8],
    password: &SecretString,
    keyfile: Option<&[u8]>,
    summary: &mut ImportSummary,
) -> Result<Vec<RawItem>> {
    kdbx_kdf_guard(bytes).map_err(VaultError::Sync)?;
    let mut key = keepass::DatabaseKey::new().with_password(password.expose_secret());
    if let Some(kf) = keyfile {
        let mut cursor = std::io::Cursor::new(kf);
        key = key
            .with_keyfile(&mut cursor)
            .map_err(|e| VaultError::Sync(format!("KeePass key file: {e}")))?;
    }
    let db = keepass::Database::parse(bytes, key).map_err(|e| {
        let text = e.to_string().to_lowercase();
        // KDBX4 reports header/HMAC/block hash mismatches for a wrong key.
        if text.contains("hash mismatch")
            || text.contains("hmac")
            || text.contains("block hash")
            || text.contains("incorrect key")
            || text.contains("invalid padding")
        {
            VaultError::Sync(
                "cannot open KeePass database — wrong password or key file".into(),
            )
        } else {
            VaultError::Sync(format!("cannot open KeePass database: {e}"))
        }
    })?;

    let mut out = Vec::new();
    let root = db.root();
    let root_path = if root.name.trim().is_empty() {
        String::new()
    } else {
        root.name.trim().to_string()
    };
    walk_kdbx_group(&root, &root_path, summary, &mut out);
    Ok(out)
}

fn walk_kdbx_group(
    group: &keepass::db::GroupRef<'_>,
    path: &str,
    summary: &mut ImportSummary,
    out: &mut Vec<RawItem>,
) {
    const KNOWN: [&str; 8] = [
        "Title", "UserName", "Password", "URL", "Notes", "otp", "TOTP", "totp",
    ];
    for entry in group.entries() {
        let get = |k: &str| entry.get(k).unwrap_or("").to_string();
        let title = get("Title");
        let user = get("UserName");
        let pass = get("Password");
        let url = get("URL");
        let notes = get("Notes");
        let otp = get("otp");
        let otp = if otp.is_empty() { get("TOTP") } else { otp };
        let otp = if otp.is_empty() { get("totp") } else { otp };
        let mut custom = Vec::new();
        for (k, v) in &entry.fields {
            if KNOWN.contains(&k.as_str()) {
                continue;
            }
            let val = v.get();
            if !k.trim().is_empty() && !val.trim().is_empty() {
                custom.push((k.trim().to_string(), val.trim().to_string()));
            }
        }
        if title.is_empty() && user.is_empty() && pass.is_empty() {
            summary.rows_failed += 1;
            continue;
        }
        let (totp, notes) =
            super::apply_totp(&otp, &title, notes, summary);
        out.push(RawItem {
            kind: 1,
            title,
            a: user,
            b: pass,
            c: url,
            totp,
            notes,
            folder: path.to_string(),
            custom_text: custom,
            ..Default::default()
        });
    }
    for child in group.groups() {
        let name = child.name.trim();
        let child_path = if path.is_empty() {
            name.to_string()
        } else if name.is_empty() {
            path.to_string()
        } else {
            format!("{path} / {name}")
        };
        walk_kdbx_group(&child, &child_path, summary, out);
    }
}

/// A13 slice 2: write the vault's logins as a KeePass KDBX4 database.
///
/// Only logins are representable losslessly; cards/identities/notes stay in
/// `.pvx`/CSV. The password is a **new KDBX password** chosen by the user, never
/// the vault master. Groups mirror `Credential.folder`; TOTP is written as an
/// `otpauth://` URI in the `otp` field; hidden custom fields are protected.
pub fn export_kdbx(vault: &Vault, password: &SecretString) -> Result<Vec<u8>> {
    if password.expose_secret().is_empty() {
        return Err(VaultError::Sync("KeePass export needs a password".into()));
    }
    let mut db = keepass::Database::new();
    db.root_mut().name = "PhantomVault".to_string();
    for c in vault
        .credentials
        .iter()
        .filter(|c| c.deleted_at.is_none())
    {
        let segments: Vec<&str> = c
            .folder
            .split('/')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let gid = ensure_kdbx_group(&mut db, &segments);
        let mut group = db.group_mut(gid).expect("just-created group exists");
        let mut entry = group.add_entry();
        entry.set_unprotected("Title", c.title.clone());
        entry.set_unprotected("UserName", c.username.clone());
        entry.set_protected("Password", c.password.clone());
        if let Some(url) = c.urls.first() {
            entry.set_unprotected("URL", url.url().to_string());
        }
        if !c.notes.is_empty() {
            entry.set_unprotected("Notes", c.notes.clone());
        }
        if !c.totp_secret.is_empty() {
            let label = percent_encoding::utf8_percent_encode(
                &c.title,
                percent_encoding::NON_ALPHANUMERIC,
            )
            .to_string();
            entry.set_unprotected(
                "otp",
                format!("otpauth://totp/{label}?secret={}", c.totp_secret),
            );
        }
        for field in &c.custom_fields {
            match field.field_type {
                crate::models::CustomFieldType::Linked => continue,
                crate::models::CustomFieldType::Hidden => {
                    entry.set_protected(field.name.clone(), field.value.clone())
                }
                _ => entry.set_unprotected(field.name.clone(), field.value.clone()),
            }
        }
    }
    let mut out = Vec::new();
    let key = keepass::DatabaseKey::new().with_password(password.expose_secret());
    db.save(&mut out, key)
        .map_err(|e| VaultError::Sync(format!("KDBX export failed: {e}")))?;
    Ok(out)
}

fn ensure_kdbx_group(db: &mut keepass::Database, segments: &[&str]) -> keepass::db::GroupId {
    let mut parent = db.root().id();
    for name in segments {
        let existing = db.group(parent).and_then(|g| {
            g.groups()
                .find(|c| c.name.eq_ignore_ascii_case(name))
                .map(|c| c.id())
        });
        parent = match existing {
            Some(id) => id,
            None => {
                let mut group = db.group_mut(parent).expect("parent group exists");
                let mut child = group.add_group();
                child.name = (*name).to_string();
                child.id()
            }
        };
    }
    parent
}

/// KeePass CSV: Group,Title,Username,Password,URL,Notes (+Account/Login Name variants).
pub fn parse_csv(bytes: &[u8], summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
    let text = super::sniffer::decode_text(bytes);
    let header = text.lines().next().unwrap_or("");
    let delim = super::sniffer::detect_delimiter(header);
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .from_reader(text.as_bytes());
    let raw_headers = rdr
        .headers()
        .map_err(|e| VaultError::Sync(format!("bad CSV: {e}")))?
        .clone();
    let headers: Vec<String> = raw_headers
        .iter()
        .map(|h| {
            h.trim()
                .trim_matches(['"', '\''])
                .to_lowercase()
                .replace([' ', '-', '_'], "")
        })
        .collect();
    let col = |m: &std::collections::HashMap<String, String>, keys: &[&str]| {
        keys.iter()
            .filter_map(|k| m.get(*k))
            .find(|v| !v.is_empty())
            .cloned()
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    for rec in rdr.records().flatten() {
        let mut m = std::collections::HashMap::new();
        for (i, h) in headers.iter().enumerate() {
            if let Some(v) = rec.get(i) {
                m.insert(h.clone(), v.trim().to_string());
            }
        }
        let title = col(&m, &["title", "account"]);
        let user = col(&m, &["username", "loginname"]);
        let pass = col(&m, &["password"]);
        if title.is_empty() && user.is_empty() && pass.is_empty() {
            summary.rows_failed += 1;
            continue;
        }
        let (totp, notes) = super::apply_totp(
            &col(&m, &["totp", "otp", "onetimepassword", "2fa"]),
            &title,
            col(&m, &["notes", "comments"]),
            summary,
        );
        out.push(RawItem {
            kind: 1,
            title,
            a: user,
            b: pass,
            c: col(&m, &["url", "website"]),
            totp,
            notes,
            folder: col(&m, &["group"]),
            ..Default::default()
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::importer::ImportSummary;

    #[test]
    fn keepass_xml_groups_and_totp() {
        let data = br#"<?xml version="1.0"?><KeePassFile><Root><Group><Name>Mail</Name>
<Entry><String><Key>Title</Key><Value>Gmail</Value></String>
<String><Key>UserName</Key><Value>me</Value></String>
<String><Key>Password</Key><Value>pw</Value></String>
<String><Key>otp</Key><Value>SECRET</Value></String>
<History><Entry><String><Key>Title</Key><Value>OLD</Value></String></Entry></History>
</Entry></Group></Root></KeePassFile>"#;
        let mut s = ImportSummary::default();
        let items = parse_xml(data, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].folder, "Mail");
        assert_eq!(items[0].totp, "SECRET");
        assert_eq!(items[0].a, "me");
    }

    #[test]
    fn keepass_xml_custom_fields_survive() {
        let data = br#"<?xml version="1.0"?><KeePassFile><Root><Group><Name>G</Name>
<Entry><String><Key>Title</Key><Value>T</Value></String>
<String><Key>UserName</Key><Value>u</Value></String>
<String><Key>Password</Key><Value>p</Value></String>
<String><Key>SecurityQ</Key><Value>pet?</Value></String>
<String><Key>Empty</Key><Value></Value></String>
</Entry></Group></Root></KeePassFile>"#;
        let mut s = ImportSummary::default();
        let items = parse_xml(data, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        // Custom String field preserved; empty value dropped.
        assert!(items[0].custom_text.iter().any(|(n, v)| n == "SecurityQ" && v == "pet?"));
        assert!(!items[0].custom_text.iter().any(|(n, _)| n == "Empty"));
    }

    #[test]
    fn keepass_xml_unescapes_entities_in_secrets() {
        // Pins the 0.41 `xml_content(Explicit1_0)` path: predefined entities
        // in secret-bearing fields must decode exactly (no double-escaping,
        // no raw `&amp;` landing in the vault).
        let data = br#"<?xml version="1.0"?><KeePassFile><Root><Group><Name>G</Name>
<Entry><String><Key>Title</Key><Value>T</Value></String>
<String><Key>Password</Key><Value>a&amp;b&lt;c&gt;d&quot;e&apos;f</Value></String>
</Entry></Group></Root></KeePassFile>"#;
        let mut s = ImportSummary::default();
        let items = parse_xml(data, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].b, "a&b<c>d\"e'f");
    }

    #[test]
    fn keepass_xml_char_refs_resolve_unknown_refs_dropped() {
        let data = br#"<?xml version="1.0"?><KeePassFile><Root><Group><Name>G</Name>
<Entry><String><Key>Title</Key><Value>T</Value></String>
<String><Key>Password</Key><Value>&#65;&#x42;&foo;</Value></String>
</Entry></Group></Root></KeePassFile>"#;
        let mut s = ImportSummary::default();
        let items = parse_xml(data, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        // Decimal + hex char refs resolve; unknown `&foo;` contributes nothing.
        assert_eq!(items[0].b, "AB");
    }

    #[test]
    fn keepass_csv_totp_and_row_count() {
        let data = b"Title,Username,Password,TOTP\nT,u,p,ABC\n,,,\n";
        let mut s = ImportSummary::default();
        let items = parse_csv(data, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].totp, "ABC");
        assert_eq!(s.rows_failed, 1);
    }

    /// A13: build a real KDBX4 container with the crate's writer so the test
    /// exercises the full decrypt + map path (Argon2 KDF, HMAC blocks, inner
    /// stream), not a hand-written stub.
    fn make_kdbx4(password: &str) -> Vec<u8> {
        let mut db = keepass::Database::new();
        {
            let mut root = db.root_mut();
            root.name = "Root".to_string();
            let mut group = root.add_group();
            group.name = "Mail".to_string();
            let mut entry = group.add_entry();
            entry.set_unprotected("Title", "Gmail");
            entry.set_unprotected("UserName", "u@example.com");
            entry.set_protected("Password", "s3cret!");
            entry.set_unprotected("URL", "https://mail.example.com");
            entry.set_unprotected("Notes", "two-factor enabled");
            entry.set_unprotected("SecurityQ", "pet?");
            entry.set_unprotected("otp", "JBSWY3DPEHPK3PXP");
            // A truly empty entry exercises the rows_failed counter.
            let _empty = group.add_entry();
        }
        let mut out = Vec::new();
        let key = keepass::DatabaseKey::new().with_password(password);
        db.save(&mut out, key).unwrap();
        out
    }

    #[test]
    fn kdbx4_decrypts_and_maps_entries() {
        let bytes = make_kdbx4("correct horse battery");
        let pw = SecretString::new("correct horse battery".to_string());
        let mut s = ImportSummary::default();
        let items = parse_kdbx(&bytes, &pw, None, &mut s).unwrap();
        assert_eq!(items.len(), 1, "empty entry should not import");
        let it = &items[0];
        assert_eq!(it.title, "Gmail");
        assert_eq!(it.a, "u@example.com");
        assert_eq!(it.b, "s3cret!");
        assert_eq!(it.c, "https://mail.example.com");
        assert!(it.notes.contains("two-factor"));
        assert_eq!(it.folder, "Root / Mail");
        assert!(it
            .custom_text
            .iter()
            .any(|(k, v)| k == "SecurityQ" && v == "pet?"));
        assert!(!it.totp.is_empty(), "otp field should map to a TOTP secret");
    }

    #[test]
    fn kdbx4_wrong_password_is_a_clear_error() {
        let bytes = make_kdbx4("correct horse battery");
        let wrong = SecretString::new("wrong password".to_string());
        let mut s = ImportSummary::default();
        let err = parse_kdbx(&bytes, &wrong, None, &mut s).unwrap_err();
        assert!(
            err.to_string().contains("wrong password"),
            "unexpected: {err}"
        );
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/keepass")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
    }

    #[test]
    fn real_keepassxc_kdbx4_aes_argon2_imports() {
        let bytes = fixture("test_db_kdbx4_with_password_argon2.kdbx");
        let pw = SecretString::new("demopass".to_string());
        let mut s = ImportSummary::default();
        let rows = parse_kdbx(&bytes, &pw, None, &mut s).unwrap();
        assert_eq!(rows.len() + s.rows_failed, 2);
        assert!(rows.iter().all(|r| r.folder == "Root"));
        assert!(rows.iter().any(|r| !r.title.is_empty()));
        assert!(rows.iter().any(|r| !r.b.is_empty()));
    }

    #[test]
    fn real_keepassxc_kdbx4_chacha20_argon2id_imports() {
        let bytes = fixture("test_db_kdbx4_with_password_argon2id_chacha20.kdbx");
        let pw = SecretString::new("demopass".to_string());
        let mut s = ImportSummary::default();
        let rows = parse_kdbx(&bytes, &pw, None, &mut s).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].folder, "Root");
    }

    #[test]
    fn real_keepassxc_kdbx4_keyfile_requires_password_and_keyfile() {
        let bytes = fixture("test_db_kdbx4_with_keyfile_v2.kdbx");
        let keyfile = fixture("test_db_kdbx4_with_keyfile_v2.keyx");
        let pw = SecretString::new("demopass".to_string());
        let mut s = ImportSummary::default();
        let rows = parse_kdbx(&bytes, &pw, Some(&keyfile), &mut s).unwrap();
        assert_eq!(rows.len(), 1);
        // Both factors are mandatory.
        assert!(parse_kdbx(&bytes, &pw, None, &mut s).is_err());
        assert!(parse_kdbx(&bytes, &pw, Some(b"not a key file"), &mut s).is_err());
    }

    #[test]
    fn kdbx_dispatch_needs_the_file_password() {
        let bytes = make_kdbx4("kdbx-pass-123");
        let path = std::env::temp_dir().join(format!("pv-a13-{}.kdbx", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        // No password: explicit refusal, never "unrecognized format".
        let err = match crate::importer::parse_import_any(&path, None, None, None) {
            Ok(_) => panic!("expected a password refusal"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("needs its password"), "{err}");
        // With the file password: rows.
        let pw = SecretString::new("kdbx-pass-123".to_string());
        match crate::importer::parse_import_any(&path, None, None, Some(&pw)).unwrap() {
            crate::importer::ParsedImport::Rows(rows, summary) => {
                assert_eq!(summary.source, "KeePass KDBX");
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].title, "Gmail");
            }
            _ => panic!("expected rows"),
        }
        let _ = std::fs::remove_file(&path);
    }

    fn push_kdf_entry(d: &mut Vec<u8>, ty: u8, key: &str, val: &[u8]) {
        d.push(ty);
        d.extend_from_slice(&(key.len() as u32).to_le_bytes());
        d.extend_from_slice(key.as_bytes());
        d.extend_from_slice(&(val.len() as u32).to_le_bytes());
        d.extend_from_slice(val);
    }

    fn kdf_dict(uuid: [u8; 16], u64s: &[(&str, u64)], u32s: &[(&str, u32)]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&0x0100u16.to_le_bytes());
        push_kdf_entry(&mut d, 0x42, "$UUID", &uuid);
        for (k, v) in u64s {
            push_kdf_entry(&mut d, 0x05, k, &v.to_le_bytes());
        }
        for (k, v) in u32s {
            push_kdf_entry(&mut d, 0x04, k, &v.to_le_bytes());
        }
        d.push(0);
        d
    }

    #[test]
    fn kdbx_kdf_guard_caps_hostile_parameters() {
        const ARGON2: [u8; 16] = [
            0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3,
            0x0a, 0x0c,
        ];
        const AES4: [u8; 16] = [
            0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64,
            0x82, 0x38,
        ];
        let ok = kdf_dict(
            ARGON2,
            &[("M", 64 * 1024 * 1024), ("I", 50)],
            &[("P", 4)],
        );
        assert!(check_kdbx4_kdf(&ok).is_ok());
        let huge_mem = kdf_dict(
            ARGON2,
            &[("M", 64 * 1024 * 1024 * 1024), ("I", 50)],
            &[("P", 4)],
        );
        assert!(check_kdbx4_kdf(&huge_mem).is_err());
        let huge_iter = kdf_dict(
            ARGON2,
            &[("M", 64 * 1024 * 1024), ("I", 10_000_000)],
            &[("P", 4)],
        );
        assert!(check_kdbx4_kdf(&huge_iter).is_err());
        let bad_p = kdf_dict(ARGON2, &[("M", 1 << 20), ("I", 1)], &[("P", 0)]);
        assert!(check_kdbx4_kdf(&bad_p).is_err());
        let aes_ok = kdf_dict(AES4, &[("R", 60_000)], &[]);
        assert!(check_kdbx4_kdf(&aes_ok).is_ok());
        let aes_bomb = kdf_dict(AES4, &[("R", 1_000_000_000)], &[]);
        assert!(check_kdbx4_kdf(&aes_bomb).is_err());
        let unknown = kdf_dict([0u8; 16], &[], &[]);
        assert!(check_kdbx4_kdf(&unknown).is_err());
        assert!(kdbx_kdf_guard(b"short").is_err());
    }

    #[test]
    fn kdbx_export_roundtrips_logins_folder_totp_and_custom_fields() {
        use crate::models::{Credential, CustomField, CustomFieldType, LoginUrl};
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "c1".into(),
            title: "Gmail".into(),
            username: "u@example.com".into(),
            password: "s3cret!".into(),
            totp_secret: "JBSWY3DPEHPK3PXP".into(),
            urls: vec![LoginUrl::Plain("https://mail.example.com".into())],
            apps: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: vec![
                CustomField {
                    name: "SecurityQ".into(),
                    value: "pet?".into(),
                    field_type: CustomFieldType::Text,
                },
                CustomField {
                    name: "PIN".into(),
                    value: "9999".into(),
                    field_type: CustomFieldType::Hidden,
                },
            ],
            notes: "two-factor enabled".into(),
            folder: "Work / Mail".into(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: 0,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        });
        let pw = SecretString::new("kdbx-export-pass".to_string());
        let bytes = export_kdbx(&v, &pw).unwrap();
        let mut s = ImportSummary::default();
        let rows = parse_kdbx(&bytes, &pw, None, &mut s).unwrap();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.title, "Gmail");
        assert_eq!(r.a, "u@example.com");
        assert_eq!(r.b, "s3cret!");
        assert_eq!(r.c, "https://mail.example.com");
        assert_eq!(r.folder, "PhantomVault / Work / Mail");
        assert!(r.notes.contains("two-factor"));
        assert!(r.custom_text.iter().any(|(k, v)| k == "SecurityQ" && v == "pet?"));
        assert!(r.custom_text.iter().any(|(k, v)| k == "PIN" && v == "9999"));
        assert!(!r.totp.is_empty());
        // The exported file does not open with a different password.
        let wrong = SecretString::new("wrong".to_string());
        assert!(parse_kdbx(&bytes, &wrong, None, &mut s).is_err());
    }
}
