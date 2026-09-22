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
    })
}

/// Parse standard otpauth://totp/... URL into single TotpAccount
fn parse_otpauth_url(url_str: &str) -> Result<TotpAccount, String> {
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

    Ok(TotpAccount {
        id: new_id(),
        account_name: account_final,
        issuer: issuer_final,
        secret: secret.replace([' ', '-'], "").to_uppercase(),
        digits,
        period,
    })
}

/// Base64 decode helper — tries URL_SAFE, STANDARD, with/without padding
fn b64_decode_migration(data: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let cleaned = data.trim().replace(' ', "").replace('\n', "").replace('\r', "");
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
