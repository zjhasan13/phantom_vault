//! Bitwarden JSON + CSV, and the generic-JSON fallback.

use super::{ImportSummary, RawItem};
use crate::error::{Result, VaultError};

fn s(v: &serde_json::Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn str_field(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    obj.get(key).map(s).unwrap_or_default()
}

/// Bitwarden unencrypted export: {folders, items[]}.
pub fn parse_json(bytes: &[u8], summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
    let text = super::sniffer::decode_text(bytes);
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| VaultError::Sync(format!("bad JSON: {e}")))?;
    let obj = v.as_object().ok_or_else(|| VaultError::Sync("bad Bitwarden JSON".into()))?;
    // folderId -> name.
    let mut folders = std::collections::HashMap::new();
    if let Some(arr) = obj.get("folders").and_then(|f| f.as_array()) {
        for f in arr {
            if let (Some(id), Some(name)) = (f.get("id").map(s), f.get("name").map(s)) {
                folders.insert(id, name);
            }
        }
    }
    let items = obj
        .get("items")
        .and_then(|i| i.as_array())
        .ok_or_else(|| VaultError::Sync("Bitwarden JSON has no items".into()))?;
    let mut out = Vec::new();
    for it in items {
        let Some(o) = it.as_object() else {
            summary.rows_failed += 1;
            continue;
        };
        let itype = o.get("type").and_then(|t| t.as_i64()).unwrap_or(1);
        let name = str_field(o, "name");
        let notes = str_field(o, "notes");
        let folder = o
            .get("folderId")
            .and_then(|f| f.as_str())
            .and_then(|id| folders.get(id))
            .cloned()
            .unwrap_or_default();
        match itype {
            2 => {
                // Secure note.
                out.push(RawItem { kind: 3, title: name, a: notes, folder, ..Default::default() });
            }
            3 => {
                // Card.
                let c = o.get("card").and_then(|c| c.as_object());
                let get = |k: &str| c.map(|c| str_field(c, k)).unwrap_or_default();
                out.push(RawItem {
                    kind: 4,
                    title: name,
                    a: get("cardholderName"),
                    b: get("number"),
                    c: format!("{}/{}", get("expMonth"), get("expYear")),
                    d: get("code"),
                    notes,
                    folder,
                    ..Default::default()
                });
            }
            4 => {
                // Identity.
                let i = o.get("identity").and_then(|i| i.as_object());
                let get = |k: &str| i.map(|i| str_field(i, k)).unwrap_or_default();
                let full = format!("{} {} {}", get("firstName"), get("middleName"), get("lastName"))
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut idnum = get("passportNumber");
                if idnum.is_empty() {
                    idnum = get("licenseNumber");
                }
                if idnum.is_empty() {
                    idnum = get("ssn");
                }
                out.push(RawItem {
                    kind: 5,
                    title: name,
                    a: full,
                    b: idnum,
                    d: get("phone"),
                    e: [&get("address1"), &get("address2"), &get("city"), &get("country")]
                        .iter()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    notes,
                    folder,
                    ..Default::default()
                });
            }
            _ => {
                // Login.
                let l = o.get("login").and_then(|l| l.as_object());
                let get = |k: &str| l.map(|l| str_field(l, k)).unwrap_or_default();
                let uris = l
                    .and_then(|l| l.get("uris"))
                    .and_then(|u| u.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|u| u.get("uri").map(s))
                            .filter(|u| !u.is_empty())
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default();
                let mut r = RawItem {
                    kind: 1,
                    title: name,
                    a: get("username"),
                    b: get("password"),
                    c: uris,
                    totp: get("totp"),
                    notes,
                    folder,
                    ..Default::default()
                };
                // Custom fields: type 0 text, 1 hidden, 2 boolean, 3 linked.
                if let Some(fields) = o.get("fields").and_then(|f| f.as_array()) {
                    for f in fields {
                        let (Some(fname), ftype) = (
                            f.get("name").map(s),
                            f.get("type").and_then(|t| t.as_i64()).unwrap_or(0),
                        ) else {
                            continue;
                        };
                        if fname.trim().is_empty() {
                            continue;
                        }
                        match ftype {
                            1 => r.custom_hidden.push((fname, f.get("value").map(s).unwrap_or_default())),
                            2 => {
                                let v = f.get("value").map(s).unwrap_or_default();
                                r.custom_check.push((fname, v == "true" || v == "1"));
                            }
                            3 => {
                                // Bitwarden linked ids: 100 username, 101 password.
                                let target = match f.get("linkedId").and_then(|i| i.as_i64()) {
                                    Some(100) => "username",
                                    _ => "password",
                                };
                                r.custom_linked.push((fname, target.to_string()));
                            }
                            _ => r.custom_text.push((fname, f.get("value").map(s).unwrap_or_default())),
                        }
                    }
                }
                out.push(r);
            }
        }
    }
    Ok(out)
}

/// Normalize one CSV record by lowercased header map.
fn rec_map(
    headers: &[String],
    record: &csv::StringRecord,
) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for (i, h) in headers.iter().enumerate() {
        if let Some(v) = record.get(i) {
            m.insert(h.clone(), v.trim().to_string());
        }
    }
    m
}

fn read_csv(bytes: &[u8], delim: u8) -> Result<(Vec<String>, Vec<csv::StringRecord>)> {
    let text = super::sniffer::decode_text(bytes);
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .trim(csv::Trim::None)
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
    let mut rows = Vec::new();
    for rec in rdr.records() {
        match rec {
            Ok(r) => rows.push(r),
            Err(_) => continue, // faulty row toll, never abort
        }
    }
    Ok((headers, rows))
}

pub fn parse_csv(bytes: &[u8], summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
    let text = super::sniffer::decode_text(bytes);
    let header = text.lines().next().unwrap_or("");
    let delim = super::sniffer::detect_delimiter(header);
    parse_csv_delim(bytes, delim, summary)
}

fn parse_csv_delim(bytes: &[u8], delim: u8, summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
    let (headers, rows) = read_csv(bytes, delim)?;
    let get = |m: &std::collections::HashMap<String, String>, k: &str| {
        m.get(k).cloned().unwrap_or_default()
    };
    let mut out = Vec::new();
    for rec in rows {
        let m = rec_map(&headers, &rec);
        // Bitwarden type col: 1 login, 2 note, 3 card, 4 identity.
        match get(&m, "type").as_str() {
            "2" => out.push(RawItem {
                kind: 3,
                title: get(&m, "name"),
                a: get(&m, "notes"),
                folder: get(&m, "folder"),
                ..Default::default()
            }),
            "3" => out.push(RawItem {
                kind: 4,
                title: get(&m, "name"),
                a: get(&m, "cardholdername"),
                b: get(&m, "number"),
                c: format!("{}/{}", get(&m, "expmonth"), get(&m, "expyear")),
                d: get(&m, "code"),
                notes: get(&m, "notes"),
                folder: get(&m, "folder"),
                ..Default::default()
            }),
            "4" => out.push(RawItem {
                kind: 5,
                title: get(&m, "name"),
                a: format!("{} {}", get(&m, "firstname"), get(&m, "lastname")).trim().to_string(),
                b: get(&m, "ssn"),
                c: get(&m, "email"),
                d: get(&m, "phone"),
                e: get(&m, "address1"),
                notes: get(&m, "notes"),
                folder: get(&m, "folder"),
                ..Default::default()
            }),
            _ => {
                if get(&m, "loginusername").is_empty() && get(&m, "loginpassword").is_empty() {
                    summary.rows_failed += 1;
                    continue;
                }
                out.push(RawItem {
                    kind: 1,
                    title: get(&m, "name"),
                    a: get(&m, "loginusername"),
                    b: get(&m, "loginpassword"),
                    c: get(&m, "loginuri"),
                    totp: get(&m, "logintotp"),
                    notes: get(&m, "notes"),
                    folder: get(&m, "folder"),
                    ..Default::default()
                });
            }
        }
    }
    Ok(out)
}

/// Generic JSON array: tolerant key variants, everything becomes a login/note.
pub fn parse_generic_json(bytes: &[u8], summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
    let text = super::sniffer::decode_text(bytes);
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| VaultError::Sync(format!("bad JSON: {e}")))?;
    let arr = v.as_array().ok_or_else(|| VaultError::Sync("bad generic JSON".into()))?;
    let mut out = Vec::new();
    for it in arr {
        let Some(o) = it.as_object() else {
            summary.rows_failed += 1;
            continue;
        };
        let pick = |keys: &[&str]| {
            keys.iter()
                .filter_map(|k| o.get(*k))
                .filter_map(|v| v.as_str())
                .map(str::trim)
                .find(|s| !s.is_empty())
                .unwrap_or("")
                .to_string()
        };
        let title = pick(&["title", "name", "site", "label"]);
        let user = pick(&["username", "user", "login", "email", "account"]);
        let pass = pick(&["password", "pass", "secret", "pwd"]);
        let url = pick(&["url", "uri", "website", "link", "hostname"]);
        let notes = pick(&["notes", "note", "extra", "comments", "description"]);
        if user.is_empty() && pass.is_empty() {
            summary.rows_failed += 1;
            continue;
        }
        out.push(RawItem {
            kind: 1, title, a: user, b: pass, c: url, notes, ..Default::default()
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::importer::ImportSummary;

    #[test]
    fn bitwarden_json_full() {
        let data = br#"{
            "encrypted": false,
            "folders": [{"id": "f1", "name": "Work"}],
            "items": [
                {"type": 1, "name": "GitHub", "notes": "n", "folderId": "f1",
                 "login": {"username": "u", "password": "p",
                           "uris": [{"uri": "https://github.com"}], "totp": "ABC"},
                 "fields": [{"name": "Pet", "value": "Cat", "type": 0},
                            {"name": "PIN", "value": "1", "type": 2},
                            {"name": "LinkedU", "type": 3, "linkedId": 100}]},
                {"type": 2, "name": "Memo", "notes": "hello"},
                {"type": 3, "name": "Visa", "card": {"cardholderName": "A", "number": "4111", "expMonth": "12", "expYear": "28", "code": "1"}}
            ]
        }"#;
        let mut s = ImportSummary::default();
        let items = parse_json(data, &mut s).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].a, "u");
        assert_eq!(items[0].totp, "ABC");
        assert_eq!(items[0].folder, "Work");
        assert_eq!(items[0].custom_text, vec![("Pet".to_string(), "Cat".to_string())]);
        assert_eq!(items[0].custom_check, vec![("PIN".to_string(), true)]);
        assert_eq!(items[0].custom_linked, vec![("LinkedU".to_string(), "username".to_string())]);
        assert_eq!(items[1].kind, 3);
        assert_eq!(items[2].kind, 4);
        assert_eq!(items[2].b, "4111");
    }

    #[test]
    fn generic_json_tolerant_keys() {
        let data = br#"[{"site": "X", "login": "me", "pwd": "pw", "link": "https://x"}]"#;
        let mut s = ImportSummary::default();
        let items = parse_generic_json(data, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "X");
        assert_eq!(items[0].b, "pw");
    }
}
