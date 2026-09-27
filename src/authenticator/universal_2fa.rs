//! Ultra-deep universal 2FA ingestion: every mobile authenticator schema,
//! one sniffer. Encrypted exports fail LOUD with guidance (never silent
//! garbage); plaintext schemas merge with smart dedup.
//!
//! Supported: Google migration / otpauth URIs (single + multi-line),
//! 2FAS (.2fas/.json), Aegis (.json), Steam .maFile, andOTP + FreeOTP,
//! multi-QR images (ALL grids, one batch).

use crate::models::{TotpAccount, Vault};

/// Detected source (user-facing label + parse route).
#[derive(Debug, Clone, PartialEq)]
pub enum Source2fa {
    GoogleMigration,
    OtpauthLines,
    TwoFas,
    Aegis,
    SteamMaFile,
    AndOtp,
    FreeOtp,
    QrImage,
}

impl Source2fa {
    pub fn label(&self) -> &'static str {
        match self {
            Source2fa::GoogleMigration => "Google Migration",
            Source2fa::OtpauthLines => "otpauth:// lines",
            Source2fa::TwoFas => "2FAS Backup",
            Source2fa::Aegis => "Aegis JSON",
            Source2fa::SteamMaFile => "Steam maFile",
            Source2fa::AndOtp => "andOTP JSON",
            Source2fa::FreeOtp => "FreeOTP JSON",
            Source2fa::QrImage => "QR image",
        }
    }
}

#[derive(Debug, Default)]
pub struct Import2faSummary {
    pub accounts_imported: usize,
    pub duplicates_skipped: usize,
    pub source_detected: String,
    pub warnings: Vec<String>,
}

fn new_id(idx: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("2fa-{ms}-{idx}")
}

fn norm_secret(s: &str) -> String {
    s.replace([' ', '-'], "").to_uppercase()
}

fn norm_algo(a: &str) -> String {
    match a.trim().to_uppercase().as_str() {
        "SHA256" | "SHA-256" => "SHA256".to_string(),
        "SHA512" | "SHA-512" => "SHA512".to_string(),
        "MD5" => "MD5".to_string(),
        _ => "SHA1".to_string(),
    }
}

fn digits_or(d: Option<u32>, fallback: u32) -> u32 {
    match d {
        Some(8) => 8,
        Some(5) => 5,
        Some(6) => 6,
        _ => fallback,
    }
}

/// Test-only 9-arg constructor would trip `too_many_arguments`; the parser
/// call sites pass positionally and stay readable, so allow it here.
#[allow(clippy::too_many_arguments)]
fn mk_account(
    idx: usize,
    name: &str,
    issuer: &str,
    secret_b32: &str,
    digits: u32,
    period: u64,
    algorithm: &str,
    otp_type: &str,
    counter: u64,
) -> Option<TotpAccount> {
    let secret = norm_secret(secret_b32);
    if secret.is_empty() {
        return None;
    }
    // Validate base32 early — garbage never enters the vault.
    data_encoding::BASE32_NOPAD
        .decode(secret.as_bytes())
        .or_else(|_| data_encoding::BASE32.decode(secret.as_bytes()))
        .ok()?;
    let (otp_type, digits) = if otp_type.eq_ignore_ascii_case("steam")
        || issuer.to_lowercase().contains("steam")
    {
        // Steam is a TYPE, not a digit count: a plain 5-digit TOTP must NOT
        // be misrouted to the Steam alphabet renderer.
        ("steam".to_string(), 5)
    } else if otp_type.eq_ignore_ascii_case("hotp") {
        ("hotp".to_string(), digits_or(Some(digits), 6))
    } else {
        ("totp".to_string(), digits_or(Some(digits), 6))
    };
    let account_name = if name.trim().is_empty() { issuer.trim() } else { name.trim() };
    let account_name = if account_name.is_empty() { "Imported 2FA" } else { account_name };
    Some(TotpAccount {
        id: new_id(idx),
        account_name: account_name.to_string(),
        issuer: issuer.trim().to_string(),
        secret,
        digits,
        period: if period == 0 { 30 } else { period },
        algorithm: norm_algo(algorithm),
        otp_type,
        counter,
    })
}

fn s(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Per-schema parsers (each returns accounts + warnings)
// ---------------------------------------------------------------------------

fn parse_2fas(obj: &serde_json::Map<String, serde_json::Value>) -> Result<(Vec<TotpAccount>, Vec<String>), String> {
    // Encrypted 2FAS: services is a ciphertext string, not an array.
    if obj.get("servicesEncrypted").is_some()
        || matches!(obj.get("services"), Some(v) if !v.is_array())
    {
        return Err("🔒 Encrypted 2FAS backup — open it in 2FAS with your backup password and export unencrypted JSON.".into());
    }
    let arr = obj
        .get("services")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "2FAS backup has no services array".to_string())?;
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (i, sv) in arr.iter().enumerate() {
        let Some(o) = sv.as_object() else { continue };
        let otp = o.get("otp").and_then(|v| v.as_object());
        let get = |k: &str| otp.map(|o| o.get(k).map(s).unwrap_or_default()).unwrap_or_default();
        let token_type = get("tokenType");
        let otp_type = if token_type.eq_ignore_ascii_case("steam") {
            "steam"
        } else if token_type.eq_ignore_ascii_case("hotp") {
            "hotp"
        } else {
            "totp"
        };
        let digits: u32 = get("digits").parse().unwrap_or(6);
        let period: u64 = get("period").parse().unwrap_or(30);
        let counter: u64 = get("counter").parse().unwrap_or(0);
        let secret = o.get("secret").map(s).unwrap_or_default();
        let name = o.get("name").map(s).unwrap_or_default();
        match mk_account(i, &name, "", &secret, digits, period, &get("algorithm"), otp_type, counter) {
            Some(a) => out.push(a),
            None => warnings.push(format!("2FAS entry '{name}' skipped (bad secret)")),
        }
    }
    Ok((out, warnings))
}

fn parse_aegis(obj: &serde_json::Map<String, serde_json::Value>) -> Result<(Vec<TotpAccount>, Vec<String>), String> {
    // Encrypted Aegis: header.slots is a non-empty array.
    let encrypted = obj
        .get("header")
        .and_then(|h| h.as_object())
        .and_then(|h| h.get("slots"))
        .and_then(|s| s.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if encrypted {
        return Err("🔒 Encrypted Aegis vault — decrypt in Aegis (Settings → Transfer → Export plaintext JSON) and retry.".into());
    }
    let entries = obj
        .get("db")
        .and_then(|d| d.as_object())
        .and_then(|d| d.get("entries"))
        .and_then(|e| e.as_array())
        .ok_or_else(|| "Aegis backup has no db.entries".to_string())?;
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (i, ev) in entries.iter().enumerate() {
        let Some(o) = ev.as_object() else { continue };
        let etype = o.get("type").map(s).unwrap_or_default();
        let info = o.get("info").and_then(|v| v.as_object());
        let get = |k: &str| info.map(|o| o.get(k).map(s).unwrap_or_default()).unwrap_or_default();
        let digits: u32 = get("digits").parse().unwrap_or(6);
        let period: u64 = get("period").parse().unwrap_or(30);
        let counter: u64 = get("counter").parse().unwrap_or(0);
        let name = o.get("name").map(s).unwrap_or_default();
        let issuer = o.get("issuer").map(s).unwrap_or_default();
        match mk_account(i, &name, &issuer, &get("secret"), digits, period, &get("algo"), &etype, counter) {
            Some(a) => out.push(a),
            None => warnings.push(format!("Aegis entry '{name}' skipped (bad secret)")),
        }
    }
    Ok((out, warnings))
}

fn parse_steam(obj: &serde_json::Map<String, serde_json::Value>) -> Result<(Vec<TotpAccount>, Vec<String>), String> {
    let b64 = obj
        .get("shared_secret")
        .map(s)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "maFile has no shared_secret".to_string())?;
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64.trim()))
        .map_err(|_| "maFile shared_secret is not valid base64".to_string())?;
    if raw.is_empty() {
        return Err("maFile shared_secret is empty".to_string());
    }
    // SDA stores base64 bytes — vault stores base32.
    let secret_b32 = data_encoding::BASE32_NOPAD.encode(&raw);
    let name = obj.get("account_name").map(s).unwrap_or_default();
    let mut warnings = Vec::new();
    let acc = mk_account(0, &name, "Steam", &secret_b32, 5, 30, "SHA1", "steam", 0)
        .ok_or_else(|| "maFile secret rejected".to_string())?;
    if obj.get("server_time").is_none() {
        warnings.push("maFile has no server_time — phone clock skew may apply".to_string());
    }
    Ok((vec![acc], warnings))
}

fn parse_andotp(arr: &[serde_json::Value]) -> (Vec<TotpAccount>, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (i, ev) in arr.iter().enumerate() {
        let Some(o) = ev.as_object() else { continue };
        let get = |k: &str| o.get(k).map(s).unwrap_or_default();
        let digits: u32 = get("digits").parse().unwrap_or(6);
        let period: u64 = get("period").parse().unwrap_or(30);
        let counter: u64 = get("counter").parse().unwrap_or(0);
        match mk_account(i, &get("label"), &get("issuer"), &get("secret"), digits, period, &get("algorithm"), &get("type"), counter) {
            Some(a) => out.push(a),
            None => warnings.push(format!("andOTP entry {} skipped (bad secret)", i + 1)),
        }
    }
    (out, warnings)
}

fn parse_freeotp(obj: &serde_json::Map<String, serde_json::Value>) -> (Vec<TotpAccount>, Vec<String>) {
    // FreeOTP secret is a SIGNED BYTE ARRAY — convert to bytes first.
    let arr = obj.get("tokens").and_then(|t| t.as_array()).cloned().unwrap_or_default();
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (i, tv) in arr.iter().enumerate() {
        let Some(o) = tv.as_object() else { continue };
        let get = |k: &str| o.get(k).map(s).unwrap_or_default();
        let secret_b32 = match o.get("secret") {
            Some(serde_json::Value::Array(bytes)) => {
                let raw: Vec<u8> = bytes.iter().filter_map(|b| b.as_i64().map(|n| n as u8)).collect();
                if raw.is_empty() {
                    String::new()
                } else {
                    data_encoding::BASE32_NOPAD.encode(&raw)
                }
            }
            other => other.map(s).unwrap_or_default(),
        };
        let digits: u32 = get("digits").parse().unwrap_or(6);
        let period: u64 = get("period").parse().unwrap_or(30);
        let counter: u64 = get("counter").parse().unwrap_or(0);
        let etype = get("type");
        let otp_type = if etype.eq_ignore_ascii_case("hotp") || etype == "1" { "hotp" } else { "totp" };
        match mk_account(i, &get("label"), &get("issuer"), &secret_b32, digits, period, &get("algo"), otp_type, counter) {
            Some(a) => out.push(a),
            None => warnings.push(format!("FreeOTP entry {} skipped (bad secret)", i + 1)),
        }
    }
    (out, warnings)
}

/// Multi-line text: otpauth:// + otpauth-migration://, `#` comments + blanks
/// ignored, every line parsed independently (one bad line never kills rest).
pub fn parse_uri_lines(text: &str) -> (Vec<TotpAccount>, Vec<String>, bool) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let mut saw_migration = false;
    for (n, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("otpauth-migration://") || line.contains("data=") && line.contains("migration") {
            saw_migration = true;
            match crate::authenticator::google_migration::parse_google_migration_url(line) {
                Ok(mut accs) => {
                    // Fresh ids (parsed ids collide across pastes).
                    for (i, a) in accs.iter_mut().enumerate() {
                        a.id = new_id(out.len() + i);
                    }
                    out.extend(accs);
                }
                Err(e) => warnings.push(format!("line {} migration skipped: {e}", n + 1)),
            }
        } else if line.starts_with("otpauth://") {
            match crate::authenticator::google_migration::parse_otpauth_url(line) {
                Ok(mut a) => {
                    a.id = new_id(out.len());
                    out.push(a);
                }
                Err(e) => warnings.push(format!("line {} otpauth skipped: {e}", n + 1)),
            }
        } else {
            warnings.push(format!("line {} ignored (not a URI)", n + 1));
        }
    }
    (out, warnings, saw_migration)
}

/// Decode EVERY QR grid in an image (multi-QR export sheets import in one batch).
pub fn parse_qr_image_bytes(bytes: &[u8]) -> Result<(Vec<TotpAccount>, Vec<String>), String> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("image too large (32MB cap)".into());
    }
    let img = image::load_from_memory(bytes).map_err(|e| format!("image decode: {e}"))?;
    let gray = img.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err("No QR code found in image".into());
    }
    let mut blob = String::new();
    let mut decoded = 0usize;
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode() {
            decoded += 1;
            blob.push_str(&content);
            blob.push('\n');
        }
    }
    if decoded == 0 {
        return Err("QR decode failed for all detected grids".into());
    }
    let (accs, mut warnings, _) = parse_uri_lines(&blob);
    if accs.is_empty() {
        warnings.push("QR grids decoded but held no otpauth payloads".into());
    }
    Ok((accs, warnings))
}

// ---------------------------------------------------------------------------
// Sniff + dispatch
// ---------------------------------------------------------------------------

/// Route pasted/file text to the right parser. Returns (source, accounts, warnings).
pub fn sniff_and_parse_text(text: &str) -> Result<(Source2fa, Vec<TotpAccount>, Vec<String>), String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("Nothing to import — paste URIs or JSON first.".into());
    }
    // Fast path: URI lines (also catches a lone migration blob).
    let looks_uri = t.lines().any(|l| {
        let l = l.trim();
        l.starts_with("otpauth://") || l.starts_with("otpauth-migration://")
    });
    if looks_uri {
        let (accs, warnings, saw_migration) = parse_uri_lines(t);
        if accs.is_empty() {
            return Err(format!("No valid URIs found. {}", warnings.join(" ")));
        }
        let src = if saw_migration { Source2fa::GoogleMigration } else { Source2fa::OtpauthLines };
        return Ok((src, accs, warnings));
    }
    // JSON schemas.
    let v: serde_json::Value =
        serde_json::from_str(t).map_err(|_| "Unrecognized input — not otpauth URIs, not JSON. Encrypted exports must be decrypted in their app first.".to_string())?;
    sniff_and_parse_json(&v)
}

/// Route a parsed JSON document to the right schema parser.
pub fn sniff_and_parse_json(v: &serde_json::Value) -> Result<(Source2fa, Vec<TotpAccount>, Vec<String>), String> {
    // Steam maFile (also valid bare object, no array anywhere).
    if let Some(o) = v.as_object() {
        if o.contains_key("shared_secret") {
            let (a, w) = parse_steam(o)?;
            return Ok((Source2fa::SteamMaFile, a, w));
        }
    }
    // 2FAS: services array (or encrypted marker).
    if let Some(o) = v.as_object() {
        if o.contains_key("services") || o.contains_key("servicesEncrypted") {
            let (a, w) = parse_2fas(o)?;
            return Ok((Source2fa::TwoFas, a, w));
        }
    }
    // Aegis: db.entries.
    if v.get("db").and_then(|d| d.as_object()).and_then(|d| d.get("entries")).is_some() {
        let o = v.as_object().ok_or_else(|| "bad Aegis JSON".to_string())?;
        let (a, w) = parse_aegis(o)?;
        return Ok((Source2fa::Aegis, a, w));
    }
    // FreeOTP: tokens array.
    if let Some(o) = v.as_object() {
        if o.contains_key("tokens") {
            let (a, w) = parse_freeotp(o);
            if a.is_empty() && !w.is_empty() {
                return Err(format!("FreeOTP: nothing importable. {}", w.join(" ")));
            }
            return Ok((Source2fa::FreeOtp, a, w));
        }
    }
    // andOTP / generic array of secret-holders.
    if let Some(arr) = v.as_array() {
        if !arr.is_empty()
            && arr.iter().all(|e| {
                e.as_object().map(|o| o.contains_key("secret")).unwrap_or(false)
            })
        {
            let (a, w) = parse_andotp(arr);
            if a.is_empty() {
                return Err(format!("No valid andOTP entries. {}", w.join(" ")));
            }
            return Ok((Source2fa::AndOtp, a, w));
        }
    }
    Err("Unknown 2FA JSON schema (tried 2FAS, Aegis, Steam, andOTP, FreeOTP).".into())
}

/// Raw file bytes + extension → accounts. Images go multi-QR, text goes sniff.
pub fn parse_file_bytes(bytes: &[u8], ext: &str) -> Result<(Source2fa, Vec<TotpAccount>, Vec<String>), String> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("file too large (32MB cap)".into());
    }
    let e = ext.to_lowercase();
    if ["png", "jpg", "jpeg", "bmp", "webp", "gif"].iter().any(|x| e == *x) {
        let (a, w) = parse_qr_image_bytes(bytes)?;
        if a.is_empty() {
            return Err(format!("QR image: nothing importable. {}", w.join(" ")));
        }
        return Ok((Source2fa::QrImage, a, w));
    }
    let text = String::from_utf8_lossy(bytes);
    // BOM-tolerant decode (mirrors the vault importer).
    let text = text.trim_start_matches('\u{feff}');
    sniff_and_parse_text(text)
}

// ---------------------------------------------------------------------------
// Smart dedup merge
// ---------------------------------------------------------------------------

/// Merge into the vault: same (issuer, name) + same secret → skip; same
/// pair + different secret → keep both (`name [Imported]`). Fresh ids always.
pub fn merge_2fa(vault: &mut Vault, accounts: Vec<TotpAccount>) -> (usize, usize) {
    let mut imported = 0usize;
    let mut skipped = 0usize;
    for mut a in accounts {
        let same_pair = vault.totp_accounts.iter().find(|e| {
            e.issuer.to_lowercase() == a.issuer.to_lowercase()
                && e.account_name.to_lowercase() == a.account_name.to_lowercase()
        });
        match same_pair {
            Some(e) if norm_secret(&e.secret) == norm_secret(&a.secret) => {
                skipped += 1;
            }
            Some(_) => {
                a.id = new_id(vault.totp_accounts.len() + imported);
                a.account_name = format!("{} [Imported]", a.account_name);
                vault.totp_accounts.push(a);
                imported += 1;
            }
            None => {
                a.id = new_id(vault.totp_accounts.len() + imported);
                vault.totp_accounts.push(a);
                imported += 1;
            }
        }
    }
    (imported, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twofas_full_schema() {
        let doc = serde_json::json!({
            "schemaVersion": 2,
            "services": [
                {"name": "GitHub", "secret": "JBSWY3DPEHPK3PXP",
                 "otp": {"tokenType": "TOTP", "algorithm": "SHA1", "digits": 6, "period": 30}},
                {"name": "Bank", "secret": "JBSWY3DPEHPK3PXP",
                 "otp": {"tokenType": "HOTP", "algorithm": "SHA256", "digits": 8, "period": 30, "counter": 7}},
                {"name": "Bad", "secret": "!!!", "otp": {"tokenType": "TOTP"}}
            ]
        });
        let (src, accs, warns) = sniff_and_parse_json(&doc).unwrap();
        assert_eq!(src, Source2fa::TwoFas);
        assert_eq!(accs.len(), 2);
        assert_eq!(accs[1].otp_type, "hotp");
        assert_eq!(accs[1].counter, 7);
        assert_eq!(accs[1].algorithm, "SHA256");
        assert_eq!(accs[1].digits, 8);
        assert_eq!(warns.len(), 1);
    }

    #[test]
    fn twofas_encrypted_fails_loud() {
        let doc = serde_json::json!({"schemaVersion": 2, "servicesEncrypted": "aGVsbG8="});
        let err = sniff_and_parse_json(&doc).unwrap_err();
        assert!(err.contains("Encrypted 2FAS"));
    }

    #[test]
    fn aegis_full_and_encrypted() {
        let doc = serde_json::json!({
            "version": 1, "header": {"slots": null},
            "db": {"entries": [
                {"type": "totp", "name": "user@x.com", "issuer": "X",
                 "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA512", "digits": 6, "period": 60}},
                {"type": "steam", "name": "gamer", "issuer": "Steam",
                 "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 5, "period": 30}}
            ]}
        });
        let (src, accs, _) = sniff_and_parse_json(&doc).unwrap();
        assert_eq!(src, Source2fa::Aegis);
        assert_eq!(accs.len(), 2);
        assert_eq!(accs[0].period, 60);
        assert_eq!(accs[0].algorithm, "SHA512");
        assert_eq!(accs[1].otp_type, "steam");
        assert_eq!(accs[1].digits, 5);
        let enc = serde_json::json!({"header": {"slots": [{"type": 1}]}, "db": {"entries": []}});
        assert!(sniff_and_parse_json(&enc).unwrap_err().contains("Encrypted Aegis"));
    }

    #[test]
    fn steam_mafile_base64_to_base32() {
        // "Hello world!!" bytes as base64 (SDA stores base64, vault keeps base32).
        let doc = serde_json::json!({
            "account_name": "gamer123",
            "shared_secret": "SGVsbG8gd29ybGQhIQ==",
            "server_time": "1700000000"
        });
        let (src, accs, _) = sniff_and_parse_json(&doc).unwrap();
        assert_eq!(src, Source2fa::SteamMaFile);
        assert_eq!(accs.len(), 1);
        assert_eq!(accs[0].otp_type, "steam");
        assert_eq!(accs[0].digits, 5);
        assert_eq!(accs[0].account_name, "gamer123");
        // Roundtrip: base32 decodes back to the original bytes.
        let raw = data_encoding::BASE32_NOPAD.decode(accs[0].secret.as_bytes()).unwrap();
        assert_eq!(raw, b"Hello world!!");
    }

    #[test]
    fn andotp_and_freeotp() {
        let andotp = serde_json::json!([
            {"secret": "JBSWY3DPEHPK3PXP", "issuer": "A", "label": "a@x", "type": "TOTP",
             "algorithm": "SHA1", "digits": 6, "period": 30, "counter": 0}
        ]);
        let (src, accs, _) = sniff_and_parse_json(&andotp).unwrap();
        assert_eq!(src, Source2fa::AndOtp);
        assert_eq!(accs[0].account_name, "a@x");
        // FreeOTP signed-byte secret [-34,4,...] → bytes → base32.
        let free = serde_json::json!({"tokens": [
            {"algo": "SHA1", "counter": 0, "digits": 6, "issuer": "F", "label": "f@x",
             "period": 30, "type": "TOTP", "secret": [72, 101, 108, 108, 111, 33, 33, 33, 33, 33]}
        ]});
        let (src, accs, _) = sniff_and_parse_json(&free).unwrap();
        assert_eq!(src, Source2fa::FreeOtp);
        assert_eq!(accs.len(), 1);
        let raw = data_encoding::BASE32_NOPAD.decode(accs[0].secret.as_bytes()).unwrap();
        assert_eq!(raw, vec![72u8, 101, 108, 108, 111, 33, 33, 33, 33, 33]);
    }

    #[test]
    fn multiline_uris_skip_comments_and_blanks() {
        let text = "# my backup\n\notpauth://totp/X:a@x?secret=JBSWY3DPEHPK3PXP&issuer=X\n\n# end\n";
        let (accs, warns, saw) = parse_uri_lines(text);
        assert!(!saw);
        assert_eq!(accs.len(), 1);
        assert!(warns.is_empty());
        assert_eq!(accs[0].account_name, "a@x");
    }

    #[test]
    fn dedup_skips_same_secret_splits_diverged() {
        let mut v = Vault::new();
        v.totp_accounts.push(TotpAccount {
            id: "old".into(), account_name: "a@x".into(), issuer: "X".into(),
            secret: "JBSWY3DPEHPK3PXP".into(), digits: 6, period: 30,
            algorithm: "SHA1".into(), otp_type: "totp".into(), counter: 0,
        });
        let mk = |secret: &str| TotpAccount {
            id: "t".into(), account_name: "a@x".into(), issuer: "X".into(),
            secret: secret.into(), digits: 6, period: 30,
            algorithm: "SHA1".into(), otp_type: "totp".into(), counter: 0,
        };
        // Identical (case/padding-tolerant) → skip.
        let (imp, skip) = merge_2fa(&mut v, vec![mk("jbswy3dpehpk3pxp")]);
        assert_eq!((imp, skip), (0, 1));
        assert_eq!(v.totp_accounts.len(), 1);
        // Different secret → both kept, newcomer tagged.
        let (imp2, skip2) = merge_2fa(&mut v, vec![mk("AAAAAAAAAAAAAAAA")]);
        assert_eq!((imp2, skip2), (1, 0));
        assert_eq!(v.totp_accounts.len(), 2);
        assert!(v.totp_accounts[1].account_name.contains("[Imported]"));
    }
}
