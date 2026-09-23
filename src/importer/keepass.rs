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
                let txt = e.unescape().unwrap_or_default().into_owned();
                if group_name_pending && !in_entry {
                    // Push every group level verbatim (Root DB name included):
                    // deterministic, never loses hierarchy info.
                    if !txt.trim().is_empty() {
                        group_stack.push(txt.trim().to_string());
                    }
                    group_name_pending = false;
                } else if in_string && !in_history {
                    if cur_key.is_empty() {
                        cur_key = txt;
                    } else {
                        cur_val = txt;
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
                                _ => {}
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
                                out.push(RawItem {
                                    kind: 1,
                                    title: cur.title.clone(),
                                    a: cur.user.clone(),
                                    b: cur.pass.clone(),
                                    c: cur.url.clone(),
                                    totp: cur.otp.clone(),
                                    notes: cur.notes.clone(),
                                    folder,
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
pub fn parse_csv(bytes: &[u8], _summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
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
            continue;
        }
        out.push(RawItem {
            kind: 1,
            title,
            a: user,
            b: pass,
            c: col(&m, &["url", "website"]),
            notes: col(&m, &["notes", "comments"]),
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
}
