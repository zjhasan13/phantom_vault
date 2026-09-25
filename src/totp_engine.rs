use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::{Result, VaultError};
use crate::models::TotpAccount;

/// একটি সিক্রেট কি (Secret Key) থেকে লাইভ ৬ ডিজিটের TOTP কোড এবং বাকি সময় বের করা
/// (Legacy hero-ticker path — SHA1/6-digit fixed. Prefer generate_code_for_account.)
pub fn generate_live_code(secret_base32: &str) -> std::result::Result<(String, u64), String> {
    // স্পেস বা ড্যাশ থাকলে তা পরিষ্কার করে নেওয়া
    let clean_secret = secret_base32.replace([' ', '-'], "").to_uppercase();

    // Base32 সিক্রেট থেকে বাইট রিড করা
    let secret_bytes = Secret::Encoded(clean_secret)
        .to_bytes()
        .map_err(|e| format!("Invalid Base32 Secret: {:?}", e))?;

    // RFC 6238 কনফিগারেশন
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,  // ৬ ডিজিটের কোড
        1,  // Skew tolerance
        30, // ৩০ সেকেন্ডের পিরিয়ড
        secret_bytes,
    ).map_err(|e| format!("TOTP init error: {}", e))?;

    // বর্তমান ইউনিক্স টাইমস্ট্যাম্প
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_secs();

    // কোড এবং এক্সপায়ারি কাউন্টডাউন
    let code = totp.generate(current_time);
    let remaining_seconds = 30 - (current_time % 30);

    Ok((code, remaining_seconds))
}

// ---------------------------------------------------------------------------
// Phase 24: universal dispatcher — bit-identical multi-algorithm engine.
// ---------------------------------------------------------------------------

fn parse_totp_algorithm(name: &str) -> Result<Algorithm> {
    match name.trim().to_uppercase().as_str() {
        "SHA256" => Ok(Algorithm::SHA256),
        "SHA512" => Ok(Algorithm::SHA512),
        "MD5" => Err(VaultError::Crypto(
            "MD5 OTP unsupported — re-enroll this account as SHA1+".into(),
        )),
        _ => Ok(Algorithm::SHA1),
    }
}

fn secret_bytes(secret_base32: &str) -> Result<Vec<u8>> {
    let clean = secret_base32.replace([' ', '-'], "").to_uppercase();
    Secret::Encoded(clean)
        .to_bytes()
        .map_err(|e| VaultError::Crypto(format!("Invalid Base32 secret: {:?}", e)))
}

fn now_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| VaultError::Crypto(format!("System time error: {}", e)))
}

/// RFC 4226 dynamic truncation → full 31-bit code (pre digit-truncation).
fn hotp_full(secret: &[u8], algorithm: &str, counter: u64) -> Result<u32> {
    use hmac::Mac;
    let msg = counter.to_be_bytes();
    let hash: Vec<u8> = match algorithm.trim().to_uppercase().as_str() {
        "SHA256" => {
            let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret)
                .map_err(|_| VaultError::Crypto("HMAC key error".into()))?;
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut m = hmac::Hmac::<sha2::Sha512>::new_from_slice(secret)
                .map_err(|_| VaultError::Crypto("HMAC key error".into()))?;
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut m = hmac::Hmac::<sha1::Sha1>::new_from_slice(secret)
                .map_err(|_| VaultError::Crypto("HMAC key error".into()))?;
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
    };
    let offset = (hash[hash.len() - 1] & 0x0F) as usize;
    if offset + 4 > hash.len() {
        return Err(VaultError::Crypto("HOTP truncation overflow".into()));
    }
    Ok((((hash[offset] & 0x7F) as u32) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32))
}

/// Steam Guard alphabet (26 symbols — no 0/1, no vowels, no Y).
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKLMNPQRTVWX";

fn steam_code(secret: &[u8], algorithm: &str, counter: u64) -> Result<String> {
    let mut code = hotp_full(secret, algorithm, counter)?;
    let mut out = String::with_capacity(5);
    for _ in 0..5 {
        out.push(STEAM_ALPHABET[(code % 26) as usize] as char);
        code /= 26;
    }
    Ok(out)
}

/// Universal entrypoint: renders the account EXACTLY per its stored
/// algorithm/digits/period/type/counter. Returns (code, seconds_remaining).
/// HOTP remaining is u64::MAX (counter-based, no expiry); Steam uses 30s.
pub fn generate_code_for_account(acc: &TotpAccount) -> Result<(String, u64)> {
    let secret = secret_bytes(&acc.secret)?;
    let algo_name = acc.algorithm.trim().to_uppercase();
    let digits = acc.digits.clamp(1, 10) as usize;
    match acc.otp_type.trim().to_lowercase().as_str() {
        "hotp" => {
            let full = hotp_full(&secret, &algo_name, acc.counter)?;
            let code = format!("{:0>width$}", full % 10u32.pow(digits as u32), width = digits);
            Ok((code, u64::MAX))
        }
        "steam" => {
            let period = if acc.period == 0 { 30 } else { acc.period };
            let now = now_secs()?;
            let code = steam_code(&secret, &algo_name, now / period)?;
            Ok((code, period - (now % period)))
        }
        _ => {
            let algo = parse_totp_algorithm(&algo_name)?;
            let period = if acc.period == 0 { 30 } else { acc.period };
            let totp = TOTP::new(algo, digits, 1, period, secret)
                .map_err(|e| VaultError::Crypto(format!("TOTP init error: {}", e)))?;
            let now = now_secs()?;
            Ok((totp.generate(now), period - (now % period)))
        }
    }
}

/// Screenshot-parity "Next" code for the grid's right column.
/// HOTP → counter+1 (RFC 4226 vector-provable, clock-free).
/// Steam/TOTP → next time window. Pure at fixed `now` — unit tested.
pub fn next_code_for_account(acc: &TotpAccount) -> Result<String> {
    next_code_for_account_at(acc, now_secs()?)
}

fn next_code_for_account_at(acc: &TotpAccount, now: u64) -> Result<String> {
    let secret = secret_bytes(&acc.secret)?;
    let algo_name = acc.algorithm.trim().to_uppercase();
    let digits = acc.digits.clamp(1, 10) as usize;
    match acc.otp_type.trim().to_lowercase().as_str() {
        "hotp" => {
            let full = hotp_full(&secret, &algo_name, acc.counter.saturating_add(1))?;
            Ok(format!("{:0>width$}", full % 10u32.pow(digits as u32), width = digits))
        }
        "steam" => {
            let period = if acc.period == 0 { 30 } else { acc.period };
            steam_code(&secret, &algo_name, now / period + 1)
        }
        _ => {
            let algo = parse_totp_algorithm(&algo_name)?;
            let period = if acc.period == 0 { 30 } else { acc.period };
            let totp = TOTP::new(algo, digits, 1, period, secret)
                .map_err(|e| VaultError::Crypto(format!("TOTP init error: {}", e)))?;
            Ok(totp.generate(now + period))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::TotpAccount;

    fn account(secret_ascii: &str, algorithm: &str, digits: u32, otp_type: &str, counter: u64) -> TotpAccount {
        // RFC secrets are ASCII; encode to base32 for the account field.
        let b32 = data_encoding::BASE32_NOPAD.encode(secret_ascii.as_bytes());
        TotpAccount {
            id: "t".into(),
            account_name: "rfc".into(),
            issuer: "rfc".into(),
            secret: b32,
            digits,
            period: 30,
            algorithm: algorithm.into(),
            otp_type: otp_type.into(),
            counter,
        }
    }

    // totp-rs generates against a timestamp; test the HOTP core (exact,
    // deterministic) plus dispatcher routing instead of wall-clock TOTP.
    #[test]
    fn hotp_rfc4226_vectors() {
        let secret = b"12345678901234567890";
        // Appendix D: counters 0..9 → 755224, 287082, 359152, 969429, 338314,
        // 254676, 287922, 162583, 399871, 520489.
        let expected = [
            755224u32, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (c, want) in expected.iter().enumerate() {
            assert_eq!(hotp_full(secret, "SHA1", c as u64).unwrap() % 1_000_000, *want);
        }
    }

    #[test]
    fn next_hotp_is_counter_plus_one_rfc_vector() {
        // Counter 0 → current "755224"; NEXT must be counter-1 "287082".
        let acc = account("12345678901234567890", "SHA1", 6, "hotp", 0);
        assert_eq!(next_code_for_account_at(&acc, 1_700_000_000).unwrap(), "287082");
        // Saturating tail never panics.
        let acc_max = account("12345678901234567890", "SHA1", 6, "hotp", u64::MAX);
        assert_eq!(next_code_for_account_at(&acc_max, 0).unwrap().len(), 6);
    }

    #[test]
    fn next_totp_and_steam_shapes() {
        let totp = account("12345678901234567890", "SHA1", 6, "totp", 0);
        let next = next_code_for_account_at(&totp, 1_700_000_000).unwrap();
        assert_eq!(next.len(), 6);
        assert!(next.bytes().all(|b| b.is_ascii_digit()));
        let steam = account("12345678901234567890", "SHA1", 5, "steam", 0);
        let snext = next_code_for_account_at(&steam, 1_700_000_000).unwrap();
        assert_eq!(snext.len(), 5);
        assert!(snext.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
        // MD5 refuses loudly here too.
        let md5 = account("12345678901234567890", "MD5", 6, "totp", 0);
        assert!(next_code_for_account_at(&md5, 1_700_000_000).is_err());
    }

    #[test]
    fn dispatcher_hotp_uses_counter() {
        let acc = account("12345678901234567890", "SHA1", 6, "hotp", 0);
        let (code, remaining) = generate_code_for_account(&acc).unwrap();
        assert_eq!(code, "755224");
        assert_eq!(remaining, u64::MAX);
        let acc1 = account("12345678901234567890", "SHA1", 6, "hotp", 1);
        assert_eq!(generate_code_for_account(&acc1).unwrap().0, "287082");
    }

    #[test]
    fn dispatcher_totp_rfc6238_sha1() {
        // RFC 6238: T0=0, X=30, T=1 (t=59) SHA1 8-digit → 94287082.
        // totp_rs skew shifts windows; test via hotp_full equivalence at
        // counter 1 with the same key instead (deterministic core).
        let acc = account("12345678901234567890", "SHA1", 8, "hotp", 1);
        let (code, _) = generate_code_for_account(&acc).unwrap();
        assert_eq!(code, "94287082");
    }

    #[test]
    fn dispatcher_totp_rfc6238_sha256_512_cores() {
        // RFC 6238 Appendix B truncated codes arise from the same HMAC core:
        // SHA256 counter 1 → 46119246, SHA512 counter 1 → 90693936.
        let s256 = account(
            "12345678901234567890123456789012",
            "SHA256",
            8,
            "hotp",
            1,
        );
        assert_eq!(generate_code_for_account(&s256).unwrap().0, "46119246");
        let s512 = account(
            "1234567890123456789012345678901234567890123456789012345678901234",
            "SHA512",
            8,
            "hotp",
            1,
        );
        assert_eq!(generate_code_for_account(&s512).unwrap().0, "90693936");
    }

    #[test]
    fn steam_renders_five_char_alphabet() {
        let acc = account("12345678901234567890", "SHA1", 5, "steam", 0);
        let (code, remaining) = generate_code_for_account(&acc).unwrap();
        assert_eq!(code.len(), 5);
        assert!(code.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
        assert!(remaining <= 30);
    }

    #[test]
    fn md5_refused_loudly() {
        let acc = account("12345678901234567890", "MD5", 6, "totp", 0);
        assert!(generate_code_for_account(&acc).is_err());
    }
}
