use crate::models::TotpAccount;
use prost::Message;
use std::time::{SystemTime, UNIX_EPOCH};

/// Google Authenticator MigrationPayload — pure prost, no protoc
/// Proto definition: https://github.com/google/google-authenticator/wiki/Key-Uri-Format (otpauth-migration)
#[derive(Clone, PartialEq, Message)]
pub struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    pub otp_parameters: Vec<OtpParameters>,
    #[prost(int32, tag = "2")]
    pub version: i32,
    #[prost(int32, tag = "3")]
    pub batch_size: i32,
    #[prost(int32, tag = "4")]
    pub batch_index: i32,
    #[prost(int32, tag = "5")]
    pub batch_id: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct OtpParameters {
    #[prost(bytes, tag = "1")]
    pub secret: Vec<u8>,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub issuer: String,
    #[prost(enumeration = "Algorithm", tag = "4")]
    pub algorithm: i32,
    #[prost(enumeration = "Digit", tag = "5")]
    pub digit: i32,
    #[prost(enumeration = "OtpType", tag = "6")]
    pub r#type: i32,
    #[prost(int64, tag = "7")]
    pub counter: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Algorithm {
    Invalid = 0,
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
    Md5 = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Digit {
    Unspecified = 0,
    Six = 1,
    Eight = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum OtpType {
    Invalid = 0,
    Hotp = 1,
    Totp = 2,
}

fn new_id_with_idx(idx: usize) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("migration-{}-{}", millis, idx)
}

fn new_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    // Use thread id hash to avoid collisions without extra rand dep
    format!("{}-{}", millis, std::process::id())
}

#[allow(dead_code)]
fn map_otp_to_account(otp: &OtpParameters) -> Result<TotpAccount, String> {
    map_otp_to_account_with_idx(otp, 0)
}

fn map_otp_to_account_with_idx(otp: &OtpParameters, idx: usize) -> Result<TotpAccount, String> {
    if otp.secret.is_empty() {
        return Err("OTP secret is empty".to_string());
    }
    // Convert raw bytes -> standard Base32 NOPAD (upper)
    let secret_b32 = data_encoding::BASE32_NOPAD.encode(&otp.secret);

    // Digit mapping
    let digits = match Digit::try_from(otp.digit).unwrap_or(Digit::Unspecified) {
        Digit::Six => 6,
        Digit::Eight => 8,
        _ => 6,
    };

    // Algorithm mapping — preserved bit-for-bit (the old code dropped this,
    // silently forcing SHA1 and diverging from Google on SHA256/512).
    let algorithm = match Algorithm::try_from(otp.algorithm).unwrap_or(Algorithm::Invalid) {
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha512 => "SHA512",
        Algorithm::Md5 => "MD5",
        _ => "SHA1",
    }
    .to_string();

    // OTP type + counter — HOTP accounts keep their moving factor instead of
    // being misrouted into time-based generation.
    let otp_type_num = OtpType::try_from(otp.r#type).unwrap_or(OtpType::Invalid);
    let (otp_type, counter) = match otp_type_num {
        OtpType::Hotp => ("hotp".to_string(), otp.counter.max(0) as u64),
        _ => ("totp".to_string(), 0),
    };

    // Name may be "Issuer:Account" — split if issuer field empty
    let mut issuer = otp.issuer.clone();
    let mut account_name = otp.name.clone();
    if issuer.is_empty() && account_name.contains(':') {
        let parts: Vec<&str> = account_name.splitn(2, ':').collect();
        if parts.len() == 2 {
            issuer = parts[0].to_string();
            account_name = parts[1].to_string();
        }
    }
    if account_name.is_empty() {
        account_name = issuer.clone();
        if account_name.is_empty() {
            account_name = "Imported 2FA".to_string();
        }
    }
    if issuer.is_empty() {
        issuer = "Imported".to_string();
    }

    Ok(TotpAccount {
        id: new_id_with_idx(idx),
        account_name,
        issuer,
        secret: secret_b32,
        digits,
        period: 30,
        algorithm,
        otp_type,
        counter,
    })
}

/// Parse standard otpauth://totp/... URL into single TotpAccount.
/// `pub(crate)` so the importer can normalize full-URL TOTP exports down to
/// the bare secret the live renderer needs.
pub(crate) fn parse_otpauth_url(url_str: &str) -> Result<TotpAccount, String> {
    let url = url::Url::parse(url_str).map_err(|e| format!("Invalid otpauth URL: {}", e))?;
    if url.scheme() != "otpauth" {
        return Err("Not an otpauth URL".to_string());
    }
    let host = url.host_str().unwrap_or("");
    if host != "totp" && host != "hotp" {
        return Err(format!("Unsupported otpauth type: {}", host));
    }
    // Path is "/Issuer:Account" or "/Account"
    let label = urlencoding::decode(url.path().trim_start_matches('/'))
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| url.path().trim_start_matches('/').to_string());

    let mut secret_opt: Option<String> = None;
    let mut issuer_opt: Option<String> = None;
    let mut digits = 6u32;
    let mut period = 30u64;
    let mut algorithm = "SHA1".to_string();
    let mut counter = 0u64;

    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "secret" => secret_opt = Some(v.into_owned()),
            "issuer" => issuer_opt = Some(v.into_owned()),
            "digits" => {
                if let Ok(d) = v.parse::<u32>() {
                    digits = d;
                }
            }
            "period" => {
                if let Ok(p) = v.parse::<u64>() {
                    period = p;
                }
            }
            "algorithm" => {
                algorithm = match v.to_uppercase().as_str() {
                    "SHA256" => "SHA256",
                    "SHA512" => "SHA512",
                    "MD5" => "MD5",
                    _ => "SHA1",
                }
                .to_string();
            }
            "counter" => {
                if let Ok(c) = v.parse::<u64>() {
                    counter = c;
                }
            }
            _ => {}
        }
    }
    let secret = secret_opt.ok_or("Missing secret in otpauth URL")?;
    // Validate base32
    let clean = secret.replace([' ', '-'], "").to_uppercase();
    // Try decode to validate
    data_encoding::BASE32_NOPAD
        .decode(clean.as_bytes())
        .or_else(|_| data_encoding::BASE32.decode(clean.as_bytes()))
        .map_err(|e| format!("Invalid Base32 secret: {:?}", e))?;

    // Derive issuer/account from label if not in query
    let mut label_issuer = String::new();
    let mut label_account = label.clone();
    if label.contains(':') {
        let parts: Vec<&str> = label.splitn(2, ':').collect();
        label_issuer = parts[0].to_string();
        label_account = parts[1].to_string();
    }
    let issuer = issuer_opt.unwrap_or(label_issuer).trim().to_string();
    let account_name = label_account.trim().to_string();
    let issuer_final = if issuer.is_empty() {
        "Imported".to_string()
    } else {
        issuer
    };
    let account_final = if account_name.is_empty() {
        issuer_final.clone()
    } else {
        account_name
    };

    // Steam Guard links look like otpauth://totp/...&digits=5 — tag them so the
    // dispatcher renders the 5-char alphabet instead of decimal truncation.
    let is_steam = issuer_final.eq_ignore_ascii_case("steam")
        || label.to_lowercase().contains("steam");
    let otp_type = if host == "hotp" {
        "hotp".to_string()
    } else if is_steam || digits == 5 {
        "steam".to_string()
    } else {
        "totp".to_string()
    };

    Ok(TotpAccount {
        id: new_id(),
        account_name: account_final,
        issuer: issuer_final,
        secret: secret.replace([' ', '-'], "").to_uppercase(),
        digits,
        period,
        algorithm,
        otp_type,
        counter,
    })
}

/// Base64 decode helper — tries URL_SAFE, STANDARD, with/without padding
fn b64_decode_migration(data: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let cleaned = data.trim().replace([' ', '\n', '\r'], "");
    if let Ok(b) = base64::engine::general_purpose::URL_SAFE.decode(&cleaned) {
        return Ok(b);
    }
    if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&cleaned) {
        return Ok(b);
    }
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(&cleaned) {
        return Ok(b);
    }
    if let Ok(b) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(&cleaned) {
        return Ok(b);
    }
    // Try percent-decoded first
    if let Ok(decoded) = urlencoding::decode(&cleaned) {
        let s = decoded.into_owned();
        if let Ok(b) = base64::engine::general_purpose::URL_SAFE.decode(s.trim()) {
            return Ok(b);
        }
        if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s.trim()) {
            return Ok(b);
        }
        if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim()) {
            return Ok(b);
        }
        if let Ok(b) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim()) {
            return Ok(b);
        }
    }
    Err("Base64 decode failed for migration data".to_string())
}

/// Parse Google Authenticator migration URL or standard otpauth URL
/// Supports:
/// - otpauth-migration://offline?data=BASE64
/// - otpauth://totp/...?secret=...
/// - raw base64 migration payload (if passed directly)
pub fn parse_google_migration_url(migration_url: &str) -> Result<Vec<TotpAccount>, String> {
    let trimmed = migration_url.trim();
    if trimmed.is_empty() {
        return Err("Empty migration URL".to_string());
    }

    // Fast path: standard otpauth single account
    if trimmed.starts_with("otpauth://") {
        let acc = parse_otpauth_url(trimmed)?;
        return Ok(vec![acc]);
    }

    // Migration URL handling
    if trimmed.starts_with("otpauth-migration://") || trimmed.contains("data=") {
        // Use url crate to extract data param
        let parsed = url::Url::parse(trimmed).map_err(|e| format!("Invalid migration URL: {}", e))?;
        let data_param = parsed
            .query_pairs()
            .find(|(k, _)| k == "data")
            .map(|(_, v)| v.into_owned())
            .ok_or("Missing ?data= parameter in migration URL")?;
        // URL crate already percent-decodes, but handle plus/space
        let decoded_bytes = b64_decode_migration(&data_param)?;
        let payload = MigrationPayload::decode(decoded_bytes.as_slice())
            .map_err(|e| format!("Prost decode failed: {}", e))?;
        if payload.otp_parameters.is_empty() {
            return Err("Migration payload contains no OTP parameters".to_string());
        }
        let mut accounts = Vec::new();
        for (idx, otp) in payload.otp_parameters.iter().enumerate() {
            match map_otp_to_account_with_idx(otp, idx) {
                Ok(acc) => accounts.push(acc),
                Err(e) => {
                    eprintln!("Skipping invalid OTP entry: {}", e);
                    continue;
                }
            }
        }
        if accounts.is_empty() {
            return Err("No valid OTP accounts in payload".to_string());
        }
        return Ok(accounts);
    }

    // Fallback: treat as raw base64 blob (user pasted only data string)
    if let Ok(decoded) = b64_decode_migration(trimmed) {
        if let Ok(payload) = MigrationPayload::decode(decoded.as_slice()) {
            if !payload.otp_parameters.is_empty() {
                let mut accounts = Vec::new();
                for (idx, otp) in payload.otp_parameters.iter().enumerate() {
                    if let Ok(acc) = map_otp_to_account_with_idx(otp, idx) {
                        accounts.push(acc);
                    }
                }
                if !accounts.is_empty() {
                    return Ok(accounts);
                }
            }
        }
    }

    Err("Unrecognized migration URL format. Expected otpauth-migration://offline?data=... or otpauth://totp/...".to_string())
}

// Minimal urlencoding decode helper without extra crate — we use url crate's decode, but need fallback for otpauth label
mod urlencoding {
    pub fn decode(s: &str) -> Result<std::borrow::Cow<'_, str>, String> {
        url::form_urlencoded::parse(s.as_bytes())
            .next()
            .map(|(_k, v)| {
                // This is hack to reuse url crate's percent decode for path
                let _ = v;
                Ok(std::borrow::Cow::Owned(
                    percent_encoding::percent_decode_str(s)
                        .decode_utf8()
                        .map_err(|e| format!("Percent decode error: {}", e))?
                        .into_owned(),
                ))
            })
            .unwrap_or_else(|| {
                percent_encoding::percent_decode_str(s)
                    .decode_utf8()
                    .map(|s| std::borrow::Cow::Owned(s.into_owned()))
                    .map_err(|e| format!("Percent decode error: {}", e))
            })
    }
}

// ============================================================================
// ZERO-LOCKIN REVERSE EXPORTER: vault TotpAccounts -> Google Authenticator QR.
// ============================================================================

/// Accounts per QR: camera readability degrades past ~10 entries per payload.
pub const GA_BATCH_SIZE: usize = 10;

/// Reverse of `map_otp_to_account`: vault account -> GA OtpParameters.
/// Steam Guard has no GA representation — the SECRET is preserved as a
/// standard 6-digit TOTP (caller must warn: phone shows decimals, not the
/// 5-char Steam alphabet). Non-30s periods do not survive either (GA assumes
/// 30s); the secret still transfers, codes will drift — caller warns.
pub fn account_to_otp(acc: &TotpAccount) -> Result<OtpParameters, String> {
    let clean = acc.secret.replace([' ', '-'], "").to_uppercase();
    let raw = data_encoding::BASE32_NOPAD
        .decode(clean.as_bytes())
        .or_else(|_| data_encoding::BASE32.decode(clean.as_bytes()))
        .map_err(|e| format!("account '{}' has undecodable secret: {e:?}", acc.account_name))?;
    if raw.is_empty() {
        return Err(format!("account '{}' has empty secret", acc.account_name));
    }
    let steam = acc.otp_type.eq_ignore_ascii_case("steam");
    let algorithm = if steam {
        Algorithm::Sha1 as i32
    } else {
        match acc.algorithm.to_uppercase().as_str() {
            "SHA256" => Algorithm::Sha256 as i32,
            "SHA512" => Algorithm::Sha512 as i32,
            "MD5" => Algorithm::Md5 as i32,
            _ => Algorithm::Sha1 as i32,
        }
    };
    let digit = if steam {
        Digit::Six as i32
    } else {
        match acc.digits {
            8 => Digit::Eight as i32,
            _ => Digit::Six as i32,
        }
    };
    let (otp_type, counter) = if acc.otp_type.eq_ignore_ascii_case("hotp") {
        (OtpType::Hotp as i32, acc.counter as i64)
    } else {
        (OtpType::Totp as i32, 0)
    };
    Ok(OtpParameters {
        secret: raw,
        name: acc.account_name.clone(),
        issuer: acc.issuer.clone(),
        algorithm,
        digit,
        r#type: otp_type,
        counter,
    })
}

/// One export batch: (page URIs, skipped names, lossy-warning names).
pub type MigrationBatch = (Vec<String>, Vec<String>, Vec<String>);

/// Chunk accounts into `otpauth-migration://offline?data=…` URIs (≤10 each).
/// Skips undecodable accounts but reports their names; errors only when
/// NOTHING exportable remains. Lossy = steam/custom-period accounts needing
/// the caller warning.
pub fn build_migration_uris(accounts: &[TotpAccount]) -> Result<MigrationBatch, String> {
    use base64::Engine as _;
    let mut params = Vec::new();
    let mut skipped = Vec::new();
    let mut lossy = Vec::new();
    for acc in accounts {
        match account_to_otp(acc) {
            Ok(p) => {
                if acc.otp_type.eq_ignore_ascii_case("steam") || acc.period != 30 {
                    lossy.push(acc.account_name.clone());
                }
                params.push(p);
            }
            Err(_) => skipped.push(acc.account_name.clone()),
        }
    }
    if params.is_empty() {
        return Err("no exportable 2FA accounts (all secrets undecodable)".to_string());
    }
    let batch_id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
        % (i32::MAX as u64)) as i32;
    let chunks: Vec<&[OtpParameters]> = params.chunks(GA_BATCH_SIZE).collect();
    let total = chunks.len() as i32;
    let mut uris = Vec::with_capacity(chunks.len());
    // batch_index is 1-based per the reference format (1..=batch_size):
    // strict validators reject page 1 when it carries index 0.
    for (i, chunk) in chunks.iter().enumerate() {
        let payload = MigrationPayload {
            otp_parameters: chunk.to_vec(),
            version: 1,
            batch_size: total,
            batch_index: i as i32 + 1,
            batch_id,
        };
        let mut buf = Vec::new();
        payload
            .encode(&mut buf)
            .map_err(|e| format!("protobuf encode failed: {e}"))?;
        let b64 = base64::engine::general_purpose::URL_SAFE.encode(&buf);
        uris.push(format!("otpauth-migration://offline?data={b64}"));
    }
    Ok((uris, skipped, lossy))
}

/// Rasterize a migration URI to PNG bytes (grayscale, quiet zone included)
/// using the `qrcode` grid API + the `image` crate — no Qt, no browser.
pub fn render_migration_qr_png(uri: &str) -> Result<Vec<u8>, String> {
    let code =
        qrcode::QrCode::new(uri.as_bytes()).map_err(|e| format!("QR build failed: {e:?}"))?;
    let w = code.width() as u32;
    let quiet: u32 = 4;
    let scale: u32 = 8;
    let size = (w + quiet * 2) * scale;
    if size > 4096 {
        return Err("QR payload too large to render".to_string());
    }
    let mut img = image::GrayImage::from_pixel(size, size, image::Luma([255u8]));
    for y in 0..w {
        for x in 0..w {
            if code[(x as usize, y as usize)] == qrcode::Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        img.put_pixel((x + quiet) * scale + dx, (y + quiet) * scale + dy, image::Luma([0u8]));
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    image::DynamicImage::ImageLuma8(img)
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(|e| format!("PNG encode failed: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn otp(secret: &[u8], algorithm: Algorithm, digit: Digit, r#type: OtpType, counter: i64) -> OtpParameters {
        OtpParameters {
            secret: secret.to_vec(),
            name: "Test:user@example.com".into(),
            issuer: String::new(),
            algorithm: algorithm as i32,
            digit: digit as i32,
            r#type: r#type as i32,
            counter,
        }
    }

    #[test]
    fn sha256_import_preserved() {
        let acc = map_otp_to_account(&otp(b"12345678901234567890123456789012", Algorithm::Sha256, Digit::Six, OtpType::Totp, 0)).unwrap();
        assert_eq!(acc.algorithm, "SHA256");
        assert_eq!(acc.digits, 6);
        assert_eq!(acc.otp_type, "totp");
        assert_eq!(acc.counter, 0);
        assert_eq!(acc.issuer, "Test");
        assert_eq!(acc.account_name, "user@example.com");
    }

    #[test]
    fn eight_digits_imported() {
        let acc = map_otp_to_account(&otp(b"12345678901234567890", Algorithm::Sha1, Digit::Eight, OtpType::Totp, 0)).unwrap();
        assert_eq!(acc.digits, 8);
    }

    #[test]
    fn hotp_import_keeps_counter() {
        let acc = map_otp_to_account(&otp(b"12345678901234567890", Algorithm::Sha1, Digit::Six, OtpType::Hotp, 7)).unwrap();
        assert_eq!(acc.otp_type, "hotp");
        assert_eq!(acc.counter, 7);
    }

    #[test]
    fn end_to_end_protobuf_roundtrip() {
        // Build a real MigrationPayload, encode, wrap in migration URL, parse.
        let payload = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                secret: b"12345678901234567890".to_vec(),
                name: "GitHub:me".into(),
                issuer: "GitHub".into(),
                algorithm: Algorithm::Sha512 as i32,
                digit: Digit::Six as i32,
                r#type: OtpType::Totp as i32,
                counter: 0,
            }],
            version: 1,
            batch_size: 1,
            batch_index: 0,
            batch_id: 1,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE.encode(&buf);
        let url = format!("otpauth-migration://offline?data={b64}");
        let accs = parse_google_migration_url(&url).unwrap();
        assert_eq!(accs.len(), 1);
        assert_eq!(accs[0].algorithm, "SHA512");
        assert_eq!(accs[0].issuer, "GitHub");
        // Secret must be the exact Base32 of the raw bytes.
        assert_eq!(
            accs[0].secret,
            data_encoding::BASE32_NOPAD.encode(b"12345678901234567890")
        );
    }

    fn ga_account(name: &str, secret_b32: &str) -> TotpAccount {
        TotpAccount {
            id: "t1".into(),
            account_name: name.into(),
            issuer: "Test".into(),
            secret: secret_b32.into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
        }
    }

    #[test]
    fn reverse_export_roundtrips_secret_bit_exact() {
        let acc = ga_account("GitHub:me", "JBSWY3DPEHPK3PXP");
        let otp = account_to_otp(&acc).unwrap();
        assert_eq!(otp.name, "GitHub:me");
        assert_eq!(otp.r#type, OtpType::Totp as i32);
        // Raw bytes survive the round trip.
        let expect = data_encoding::BASE32_NOPAD.decode(b"JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(otp.secret, expect);
    }

    #[test]
    fn reverse_export_batches_and_renders_qr() {
        let accs: Vec<TotpAccount> = (0..12)
            .map(|i| ga_account(&format!("acc{i}"), "JBSWY3DPEHPK3PXP"))
            .collect();
        let (uris, skipped, lossy) = build_migration_uris(&accs).unwrap();
        // 12 accounts → 2 QR pages, nothing skipped or lossy.
        assert_eq!(uris.len(), 2);
        assert!(skipped.is_empty());
        assert!(lossy.is_empty());
        for u in &uris {
            assert!(u.starts_with("otpauth-migration://offline?data="));
            let png = render_migration_qr_png(u).unwrap();
            // PNG magic, non-trivial size.
            assert_eq!(&png[0..8], &[137, 80, 78, 71, 13, 10, 26, 10]);
            assert!(png.len() > 500);
        }
        // ...and page 1 parses back to the first 10 accounts.
        let back = parse_google_migration_url(&uris[0]).unwrap();
        assert_eq!(back.len(), 10);
        assert_eq!(back[0].account_name, "acc0");
    }

    #[test]
    fn reverse_export_flags_steam_and_bad_secrets() {
        let mut steam = ga_account("steam-acc", "JBSWY3DPEHPK3PXP");
        steam.otp_type = "steam".into();
        let bad = ga_account("bad", "!!!not-base32!!!");
        let ok = ga_account("ok", "JBSWY3DPEHPK3PXP");
        let (uris, skipped, lossy) = build_migration_uris(&[steam, bad, ok]).unwrap();
        assert_eq!(uris.len(), 1);
        assert_eq!(skipped, vec!["bad".to_string()]);
        assert_eq!(lossy, vec!["steam-acc".to_string()]);
    }
}
