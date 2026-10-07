//! KeePass 2.x XML (`<KeePassFile>`) + KeePass CSV.

use super::{ImportSummary, RawItem};
use crate::error::{Result, VaultError};
use quick_xml::events::Event;
use quick_xml::Reader;

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
}
