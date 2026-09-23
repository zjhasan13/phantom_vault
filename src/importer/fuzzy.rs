//! Universal fuzzy fallback: column-role scoring for unknown CSV layouts.
//!
//! Each column is scored across all rows for url/email/secret/title signals;
//! the best column per role wins (with sanity thresholds). Row failures are
//! counted, never fatal.

use super::{ImportSummary, RawItem};
use crate::error::{Result, VaultError};

fn norm(h: &str) -> String {
    h.trim()
        .trim_matches(['"', '\''])
        .to_lowercase()
        .replace([' ', '-', '_'], "")
}

fn entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let b = s.as_bytes();
    if b.is_empty() {
        return 0.0;
    }
    for x in b {
        counts[*x as usize] += 1;
    }
    let n = b.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn is_url(v: &str) -> bool {
    let l = v.to_lowercase();
    l.starts_with("http://") || l.starts_with("https://") || l.starts_with("www.")
}

fn is_emailish(v: &str) -> bool {
    v.contains('@') && v.contains('.') && !v.contains(' ')
}

fn is_secretish(v: &str) -> bool {
    v.len() >= 6 && entropy(v) >= 3.2 && !v.contains(' ')
}

fn header_hint(header: &str) -> &'static str {
    let h = header;
    if ["title", "name", "site", "label", "service", "account", "app"]
        .iter()
        .any(|k| h.contains(k))
    {
        "title"
    } else if ["user", "login", "email", "mail", "account"].iter().any(|k| h.contains(k)) {
        "username"
    } else if ["pass", "secret", "pwd", "key", "token"].iter().any(|k| h.contains(k)) {
        "password"
    } else if ["url", "uri", "website", "link", "site"].iter().any(|k| h.contains(k)) {
        "url"
    } else if ["note", "comment", "extra", "desc"].iter().any(|k| h.contains(k)) {
        "notes"
    } else if ["folder", "group", "vault", "category"].iter().any(|k| h.contains(k)) {
        "folder"
    } else {
        ""
    }
}

pub fn parse(bytes: &[u8], delim: u8, summary: &mut ImportSummary) -> Result<Vec<RawItem>> {
    let text = super::sniffer::decode_text(bytes);
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .from_reader(text.as_bytes());
    let raw = rdr
        .headers()
        .map_err(|e| VaultError::Sync(format!("bad CSV: {e}")))?
        .clone();
    let headers: Vec<String> = raw.iter().map(norm).collect();
    let ncols = headers.len().max(1);
    let rows: Vec<csv::StringRecord> = rdr.records().flatten().collect();
    if rows.is_empty() {
        return Err(VaultError::Sync("CSV has no data rows".into()));
    }
    summary.warnings.push(
        "Universal fallback mapping used — spot-check the first imports".to_string(),
    );

    // Score columns.
    let mut url_s = vec![0usize; ncols];
    let mut user_s = vec![0usize; ncols];
    let mut pass_s = vec![0usize; ncols];
    let mut title_s = vec![0usize; ncols];
    for rec in &rows {
        for i in 0..ncols {
            let v = rec.get(i).unwrap_or("").trim();
            if v.is_empty() {
                continue;
            }
            if is_url(v) {
                url_s[i] += 2;
            }
            if is_emailish(v) || v.eq_ignore_ascii_case("admin") {
                user_s[i] += 1;
            }
            if is_secretish(v) {
                pass_s[i] += 1;
            }
            // Title = short human label that is NOT an email, URL, or secret.
            // (Without the exclusions every short cell ties and max_by_key
            // hands the title role to the wrong column.)
            if v.len() <= 40 && !is_emailish(v) && !is_url(v) && entropy(v) < 3.0 {
                title_s[i] += 1;
            }
        }
    }
    // Header hints weigh in (worth ~3 row-hits each).
    for (i, h) in headers.iter().enumerate() {
        match header_hint(h) {
            "title" => title_s[i] += 3,
            "username" => user_s[i] += 3,
            "password" => pass_s[i] += 3,
            "url" => url_s[i] += 3,
            _ => {}
        }
    }
    let best = |scores: &[usize], min: usize| {
        let (i, &v) = scores.iter().enumerate().max_by_key(|(_, &v)| v)?;
        if v >= min {
            Some(i)
        } else {
            None
        }
    };
    // Assign greedily in specificity order; a column serves one role.
    let mut taken = vec![false; ncols];
    let mut claim = |idx: Option<usize>| {
        if let Some(i) = idx {
            if !taken[i] {
                taken[i] = true;
                return Some(i);
            }
        }
        None
    };
    let url_c = claim(best(&url_s, 1));
    let user_c = claim(best(&user_s, 1));
    let pass_c = claim(best(&pass_s, 1));
    let title_c = claim(best(&title_s, 1));
    let notes_c = (0..ncols).find(|&i| !taken[i] && header_hint(&headers[i]) == "notes");
    if let Some(i) = notes_c {
        taken[i] = true;
    }
    let folder_c = (0..ncols).find(|&i| !taken[i] && header_hint(&headers[i]) == "folder");
    if let Some(i) = folder_c {
        taken[i] = true;
    }

    let cell = |rec: &csv::StringRecord, c: Option<usize>| {
        c.and_then(|i| rec.get(i)).unwrap_or("").trim().to_string()
    };
    let mut out = Vec::new();
    for rec in &rows {
        let title = cell(rec, title_c);
        let user = cell(rec, user_c);
        let pass = cell(rec, pass_c);
        if title.is_empty() && user.is_empty() && pass.is_empty() {
            summary.rows_failed += 1;
            continue;
        }
        out.push(RawItem {
            kind: 1,
            title,
            a: user,
            b: pass,
            c: cell(rec, url_c),
            notes: cell(rec, notes_c),
            folder: cell(rec, folder_c),
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
    fn fuzzy_maps_unknown_layout() {
        // Unknown (German) headers: email + high-entropy secret carry the row.
        let data = "Dienst;Benutzer;Geheimnis\nGitHub;me@example.com;kX9#mQ2$vL8z\n";
        let mut s = ImportSummary::default();
        let items = parse(data.as_bytes(), b';', &mut s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].a, "me@example.com");
        assert_eq!(items[0].b, "kX9#mQ2$vL8z");
        assert_eq!(items[0].title, "GitHub");
    }
}
