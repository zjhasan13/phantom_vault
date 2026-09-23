//! 1Password CSV + Proton Pass JSON.

use super::{ImportSummary, RawItem};
use crate::error::{Result, VaultError};

fn norm(h: &str) -> String {
    h.trim()
        .trim_matches(['"', '\''])
        .to_lowercase()
        .replace([' ', '-', '_'], "")
}

/// 1Password CSV: Title,Website,Username,Password + Vault,Notes,Tags + custom
/// section columns. Multi-line notes survive via the csv crate's quoting.
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
    let headers: Vec<String> = raw_headers.iter().map(norm).collect();
    // Custom (non-core) columns become Text custom fields.
    const CORE: &[&str] = &[
        "title", "website", "username", "password", "notes", "vault", "tags", "url",
    ];
    let custom_cols: Vec<(usize, String)> = headers
        .iter()
        .enumerate()
        .filter(|(_, h)| !CORE.contains(&h.as_str()) && !h.is_empty())
        .map(|(i, h)| (i, h.clone()))
        .collect();
    let get = |rec: &csv::StringRecord, want: &[&str]| {
        headers
            .iter()
            .position(|h| want.contains(&h.as_str()))
            .and_then(|i| rec.get(i))
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let mut out = Vec::new();
    for rec in rdr.records() {
        let Ok(rec) = rec else {
            summary.rows_failed += 1;
            continue;
        };
        let title = get(&rec, &["title"]);
        let user = get(&rec, &["username"]);
        let pass = get(&rec, &["password"]);
        if title.is_empty() && user.is_empty() && pass.is_empty() {
            summary.rows_failed += 1;
            continue;
        }
        let mut r = RawItem {
            kind: 1,
            title,
            a: user,
            b: pass,
            c: get(&rec, &["website", "url"]),
            notes: get(&rec, &["notes"]),
            folder: get(&rec, &["vault"]),
            ..Default::default()
        };
        let tags = get(&rec, &["tags"]);
        if !tags.is_empty() {
            r.notes = if r.notes.is_empty() {
                format!("tags: {tags}")
            } else {
                format!("{}\ntags: {tags}", r.notes)
            };
        }
        for (i, label) in &custom_cols {
            if let Some(v) = rec.get(*i) {
                let v = v.trim();
                if !v.is_empty() {
                    r.custom_text.push((label.clone(), v.to_string()));
                }
            }
        }
        out.push(r);
    }
    Ok(out)
}

fn s(v: &serde_json::Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// Proton Pass JSON: {vaults:[{ID,Name}], items:[{vaultID,title,item:{...}}]}.
/// Tolerant: missing vault table ⇒ folder from item.vaultName or blank.
pub fn parse_proton(bytes: &[u8], summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
    let text = super::sniffer::decode_text(bytes);
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| VaultError::Sync(format!("bad JSON: {e}")))?;
    let obj = v.as_object().ok_or_else(|| VaultError::Sync("bad Proton JSON".into()))?;
    let mut vaults = std::collections::HashMap::new();
    if let Some(arr) = obj.get("vaults").and_then(|x| x.as_array()) {
        for vv in arr {
            let id = vv.get("ID").or_else(|| vv.get("id")).map(s).unwrap_or_default();
            let name = vv.get("Name").or_else(|| vv.get("name")).map(s).unwrap_or_default();
            if !id.is_empty() {
                vaults.insert(id, name);
            }
        }
    }
    // Some exports nest under data.vaults / data.items.
    let items_val = obj.get("items").or_else(|| {
        obj.get("data")
            .and_then(|d| d.as_object())
            .and_then(|d| d.get("items"))
    });
    let items = items_val
        .and_then(|i| i.as_array())
        .ok_or_else(|| VaultError::Sync("Proton JSON has no items".into()))?;
    let mut out = Vec::new();
    for it in items {
        let Some(o) = it.as_object() else {
            summary.rows_failed += 1;
            continue;
        };
        let title = o
            .get("title")
            .or_else(|| o.get("name"))
            .map(s)
            .unwrap_or_default();
        let folder = o
            .get("vaultID")
            .and_then(|id| id.as_str())
            .and_then(|id| vaults.get(id))
            .cloned()
            .or_else(|| o.get("vaultName").map(s))
            .unwrap_or_default();
        let item = o.get("item").and_then(|i| i.as_object());
        let get = |k: &str| item.map(|i| i.get(k).map(s).unwrap_or_default()).unwrap_or_default();
        // Proton aliases: username/password/urls/note/totpUri.
        let urls = item
            .and_then(|i| i.get("urls"))
            .and_then(|u| u.as_array())
            .map(|arr| {
                arr.iter()
                    .map(s)
                    .filter(|u| !u.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let user = get("username");
        let pass = get("password");
        if title.is_empty() && user.is_empty() && pass.is_empty() {
            summary.rows_failed += 1;
            continue;
        }
        out.push(RawItem {
            kind: 1,
            title,
            a: user,
            b: pass,
            c: if urls.is_empty() { get("url") } else { urls },
            totp: get("totpUri"),
            notes: get("note"),
            folder,
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
    fn onepassword_csv_custom_columns() {
        let data = b"Title,Website,Username,Password,Vault,Notes,Security Q\nGitHub,https://github.com,me,pw,Personal,n,\"pet?\"\n";
        let mut s = ImportSummary::default();
        let items = parse_csv(data, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].a, "me");
        assert_eq!(items[0].folder, "Personal");
        assert!(items[0].custom_text.iter().any(|(n, v)| n == "securityq" && v == "pet?"));
    }

    #[test]
    fn proton_json_vaults() {
        let data = br#"{"vaults": [{"ID": "v1", "Name": "Family"}],
            "items": [{"title": "Bank", "vaultID": "v1",
                       "item": {"username": "u", "password": "p", "note": "n"}}]}"#;
        let mut s = ImportSummary::default();
        let items = parse_proton(data, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].folder, "Family");
        assert_eq!(items[0].b, "p");
    }
}
