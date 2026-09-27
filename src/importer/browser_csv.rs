//! Chrome / Safari / LastPass CSV engines.

use super::{sniffer::Format, ImportSummary, RawItem};
use crate::error::{Result, VaultError};

fn norm(h: &str) -> String {
    h.trim()
        .trim_matches(['"', '\''])
        .to_lowercase()
        .replace([' ', '-', '_'], "")
}

fn read(
    bytes: &[u8],
    summary: &mut ImportSummary,
) -> Result<(Vec<String>, Vec<csv::StringRecord>)> {
    let text = super::sniffer::decode_text(bytes);
    let header = text.lines().next().unwrap_or("");
    let delim = super::sniffer::detect_delimiter(header);
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .from_reader(text.as_bytes());
    let raw = rdr
        .headers()
        .map_err(|e| VaultError::Sync(format!("bad CSV: {e}")))?
        .clone();
    let headers: Vec<String> = raw.iter().map(norm).collect();
    let mut rows = Vec::new();
    for rec in rdr.records() {
        match rec {
            Ok(r) => rows.push(r),
            Err(_) => summary.rows_failed += 1,
        }
    }
    Ok((headers, rows))
}

fn col(
    headers: &[String],
    rec: &csv::StringRecord,
    keys: &[&str],
) -> String {
    headers
        .iter()
        .position(|h| keys.contains(&h.as_str()))
        .and_then(|i| rec.get(i))
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Chrome/Brave/Edge: name,url,username,password[,note].
/// Safari: Title,URL,User Name,Password,Notes,OTPAuth.
/// LastPass: url,username,password,totp,extra,name,grouping,fav.
pub fn parse(bytes: &[u8], format: &Format, summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
    let (headers, rows) = read(bytes, summary)?;
    let mut out = Vec::new();
    for rec in rows {
        let (title, url, user, pass, notes, folder, totp) = match format {
            Format::LastPassCsv => (
                col(&headers, &rec, &["name"]),
                col(&headers, &rec, &["url"]),
                col(&headers, &rec, &["username"]),
                col(&headers, &rec, &["password"]),
                col(&headers, &rec, &["extra"]),
                col(&headers, &rec, &["grouping"]),
                col(&headers, &rec, &["totp"]),
            ),
            Format::SafariCsv => (
                col(&headers, &rec, &["title"]),
                col(&headers, &rec, &["url"]),
                col(&headers, &rec, &["username"]),
                col(&headers, &rec, &["password"]),
                col(&headers, &rec, &["notes"]),
                String::new(),
                col(&headers, &rec, &["otpauth"]),
            ),
            _ => (
                col(&headers, &rec, &["name", "title"]),
                col(&headers, &rec, &["url"]),
                col(&headers, &rec, &["username"]),
                col(&headers, &rec, &["password"]),
                col(&headers, &rec, &["note", "notes"]),
                String::new(),
                String::new(),
            ),
        };
        if title.is_empty() && user.is_empty() && pass.is_empty() {
            summary.rows_failed += 1;
            continue;
        }
        out.push(RawItem {
            kind: 1,
            title,
            a: user,
            b: pass,
            c: url,
            totp: super::normalize_totp(&totp),
            notes,
            folder,
            ..Default::default()
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_csv() {
        let data = b"name,url,username,password,note\ngithub,https://github.com,me,pw,hi\n";
        let mut s = ImportSummary::default();
        let items = parse(data, &Format::ChromeCsv, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].c, "https://github.com");
        assert_eq!(items[0].notes, "hi");
    }

    #[test]
    fn lastpass_csv() {
        let data = b"url,username,password,totp,extra,name,grouping,fav\nhttps://x,u,p,,e,Bank,Work,0\n";
        let mut s = ImportSummary::default();
        let items = parse(data, &Format::LastPassCsv, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].folder, "Work");
        assert_eq!(items[0].notes, "e");
    }

    #[test]
    fn safari_csv_otpauth() {
        let data = b"Title,URL,Username,Password,Notes,OTPAuth\nMail,https://m,u,p,n,otpauth://x\n";
        let mut s = ImportSummary::default();
        let items = parse(data, &Format::SafariCsv, &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].totp, "otpauth://x");
    }
}
