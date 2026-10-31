//! Content auto-sniffer: BOM/encoding-tolerant format detection.

use crate::error::{Result, VaultError};

#[derive(Debug, Clone, PartialEq)]
pub enum Format {
    BitwardenJson,
    BitwardenCsv,
    KeepassXml,
    KeepassCsv,
    OnePasswordCsv,
    ProtonJson,
    ChromeCsv,
    SafariCsv,
    LastPassCsv,
    PhantomNative,
    PhantomNativeEncrypted,
    /// A6: `PVBK1` envelope — sealed with its own backup passphrase.
    PhantomBackupV2,
    GenericJson,
    FuzzyCsv(u8), // delimiter byte
}

impl Format {
    pub fn label(&self) -> String {
        match self {
            Format::BitwardenJson => "Bitwarden JSON".to_string(),
            Format::BitwardenCsv => "Bitwarden CSV".to_string(),
            Format::KeepassXml => "KeePass XML".to_string(),
            Format::KeepassCsv => "KeePass CSV".to_string(),
            Format::OnePasswordCsv => "1Password CSV".to_string(),
            Format::ProtonJson => "Proton Pass JSON".to_string(),
            Format::ChromeCsv => "Chrome/Brave/Edge CSV".to_string(),
            Format::SafariCsv => "Safari CSV".to_string(),
            Format::LastPassCsv => "LastPass CSV".to_string(),
            Format::PhantomNative => "PhantomVault backup".to_string(),
            Format::PhantomNativeEncrypted => "PhantomVault encrypted backup".to_string(),
            Format::PhantomBackupV2 => "PhantomVault backup (backup passphrase)".to_string(),
            Format::GenericJson => "Generic JSON".to_string(),
            Format::FuzzyCsv(_) => "Universal CSV".to_string(),
        }
    }
}

/// Strip UTF-8 BOM, UTF-16 BOMs (decode LE/BE), else lossy UTF-8.
pub fn decode_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16_decode(rest, true);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16_decode(rest, false);
    }
    // Heuristic: heavy NUL presence ⇒ UTF-16LE without BOM.
    if !bytes.is_empty() && bytes.iter().filter(|&&b| b == 0).count() * 4 > bytes.len() {
        return utf16_decode(bytes, true);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn utf16_decode(bytes: &[u8], little: bool) -> String {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 2 <= bytes.len() {
        let u = if little {
            u16::from_le_bytes([bytes[i], bytes[i + 1]])
        } else {
            u16::from_be_bytes([bytes[i], bytes[i + 1]])
        };
        units.push(u);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

fn header_of(text: &str) -> &str {
    text.lines().next().unwrap_or("").trim()
}

fn norm_header(h: &str) -> Vec<String> {
    h.split([',', ';', '\t', '|'])
        .map(|c| {
            c.trim()
                .trim_matches(['"', '\''])
                .to_lowercase()
                .replace([' ', '-', '_'], "")
        })
        .collect()
}

fn has(cols: &[String], names: &[&str]) -> usize {
    names.iter().filter(|n| cols.iter().any(|c| c == *n)).count()
}

/// Detect the field delimiter by counting candidates on the header line.
pub fn detect_delimiter(header: &str) -> u8 {
    let mut best = (0usize, b',');
    for d in *b",;\t|" {
        let n = header.bytes().filter(|&b| b == d).count();
        if n > best.0 {
            best = (n, d);
        }
    }
    best.1
}

pub fn sniff(bytes: &[u8]) -> Result<Format> {
    if bytes.is_empty() {
        return Err(VaultError::Sync("import file is empty".into()));
    }
    // A6 `.pvx` v2: the tag says "sealed with a backup passphrase, not the
    // master". Check it before the plain portable magic — the tag is a strict
    // prefix wrapper around the same envelope.
    if bytes.len() >= 5 && &bytes[..5] == crate::importer::exporter::BACKUP_V2_MAGIC {
        return Ok(Format::PhantomBackupV2);
    }
    // Legacy `.pvx`: the portable envelope is BINARY, so the magic check must
    // run before text decoding (lossy UTF-8 would shred it into CSV noise).
    if bytes.len() >= 4 && &bytes[..4] == crate::crypto::V2_PORTABLE_MAGIC {
        return Ok(Format::PhantomNativeEncrypted);
    }
    let text = decode_text(bytes);
    let trimmed = text.trim_start().to_lowercase();

    // XML family.
    if trimmed.starts_with("<?xml") || trimmed.starts_with("<keepassfile") {
        if trimmed.contains("<keepassfile") || trimmed.contains("<group>") {
            return Ok(Format::KeepassXml);
        }
        return Err(VaultError::Sync(
            "XML is not a KeePass export — export KeePass 2.x XML instead".into(),
        ));
    }

    // JSON family.
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let v: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|_| VaultError::Sync("unrecognized file format".into()))?;
        return sniff_json(&v);
    }

    // Tabular family.
    let header = header_of(&text);
    if header.is_empty() {
        return Err(VaultError::Sync("unrecognized file format".into()));
    }
    Ok(sniff_csv_header(header))
}

fn sniff_json(v: &serde_json::Value) -> Result<Format> {
    if let Some(obj) = v.as_object() {
        // Native marker wins over every heuristic (it is unambiguous).
        if obj.get("format").and_then(|f| f.as_str())
            == Some(crate::importer::exporter::NATIVE_FORMAT)
        {
            return Ok(Format::PhantomNative);
        }
        if obj.get("encrypted").and_then(|e| e.as_bool()) == Some(true) {
            return Err(VaultError::Sync(
                "Encrypted Bitwarden export detected. Please export as unencrypted JSON.".into(),
            ));
        }
        if obj.contains_key("items") {
            return Ok(Format::BitwardenJson);
        }
        if obj.contains_key("vaults") {
            return Ok(Format::ProtonJson);
        }
        if obj.contains_key("accounts") {
            return Ok(Format::ProtonJson);
        }
        if obj.contains_key("logins") {
            return Err(VaultError::Sync(
                "Firefox logins are device-encrypted. Export Firefox CSV instead (about:logins → Export).".into(),
            ));
        }
    }
    if v.as_array().is_some() {
        return Ok(Format::GenericJson);
    }
    Err(VaultError::Sync("unrecognized JSON vault format".into()))
}

fn sniff_csv_header(header: &str) -> Format {
    let cols = norm_header(header);
    // Bitwarden: folder,favorite,type,name,login_username,...
    if has(&cols, &["loginusername", "loginpassword", "name"]) >= 3 {
        return Format::BitwardenCsv;
    }
    // KeePass: account,login name,password,web site,comments (or group,title,...)
    if (cols.iter().any(|c| c == "account") && cols.iter().any(|c| c == "loginname"))
        || (has(&cols, &["group", "title", "username", "password", "url", "notes"]) >= 4
            && cols.iter().any(|c| c == "group"))
    {
        return Format::KeepassCsv;
    }
    // 1Password: title,website,username,password (vault/notes/tags optional)
    if has(&cols, &["title", "username", "password"]) >= 3 && cols.iter().any(|c| c == "website") {
        return Format::OnePasswordCsv;
    }
    // LastPass: url,username,password,totp,extra,name,grouping,fav.
    // Keyed on its DISTINCTIVE columns (extra/grouping) — bare
    // name+url+username+password alone is Chrome, not LastPass.
    if has(&cols, &["url", "username", "password", "extra", "name", "grouping"]) >= 4
        && (cols.iter().any(|c| c == "extra") || cols.iter().any(|c| c == "grouping"))
    {
        return Format::LastPassCsv;
    }
    // Chrome: name,url,username,password (+note). Keyed on `name`.
    if has(&cols, &["name", "url", "username", "password"]) >= 4 {
        return Format::ChromeCsv;
    }
    // Safari: Title,URL,Username,Password,Notes,OTPAuth. Keyed on `title`/otpauth.
    if (has(&cols, &["title", "url", "username", "password"]) >= 4)
        || cols.iter().any(|c| c == "otpauth")
    {
        return Format::SafariCsv;
    }
    Format::FuzzyCsv(detect_delimiter(header))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_detected() {
        let f = sniff(b"<?xml version=\"1.0\"?><KeePassFile><Root><Group>").unwrap();
        assert_eq!(f, Format::KeepassXml);
    }

    #[test]
    fn bitwarden_json_detected() {
        let f = sniff(br#"{"encrypted": false, "items": []}"#).unwrap();
        assert_eq!(f, Format::BitwardenJson);
    }

    #[test]
    fn encrypted_bitwarden_guided() {
        assert!(sniff(br#"{"encrypted": true, "items": []}"#).is_err());
    }

    #[test]
    fn firefox_guided_to_csv() {
        assert!(sniff(br#"{"logins": []}"#).is_err());
    }

    #[test]
    fn chrome_csv_detected() {
        let f = sniff(b"name,url,username,password\na,https://x,u,p").unwrap();
        assert_eq!(f, Format::ChromeCsv);
    }

    #[test]
    fn lastpass_detected() {
        let f = sniff(b"url,username,password,totp,extra,name,grouping,fav\nu,u,p,,e,n,g,0").unwrap();
        assert_eq!(f, Format::LastPassCsv);
    }

    #[test]
    fn bom_stripped() {
        let mut b = vec![0xEF, 0xBB, 0xBF];
        b.extend_from_slice(b"name,url,username,password\na,https://x,u,p");
        assert_eq!(sniff(&b).unwrap(), Format::ChromeCsv);
    }

    #[test]
    fn semicolon_delimiter_fuzzy() {
        let f = sniff("service;login;secret\nGitHub;me;x".as_bytes()).unwrap();
        assert!(matches!(f, Format::FuzzyCsv(b';')));
    }
}
