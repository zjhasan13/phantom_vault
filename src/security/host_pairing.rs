//! A27 L2 — the pairing secret between the desktop app and the extension.
//!
//! Status: **core only, not wired**. The secret can be minted, DPAPI-sealed,
//! shown as a 32-character code, reloaded and used to MAC or verify a frame —
//! but nothing calls it yet. `serve_cli` still accepts unpaired frames (step 1
//! of the rollout in `docs/A27_HOST_PAIRING.md`) and the popup has no pairing
//! UI, so this module changes no behaviour on its own.
//!
//! Design notes that differ from the doc's first draft:
//! - the secret is **20 bytes (160 bits)**, not 32: 160 bits is exactly 32
//!   Crockford characters, which the user can retype as 8 groups of 4. A
//!   32-byte secret would need 52 characters.
//! - the MAC covers `cmd`, `seq`, `ts` and a SHA-256 of the canonical body, so
//!   the host never has to hash the JSON twice or trust key ordering.
//!
//! Not every entry point has a caller yet: `mint_at`/`clear_at` wait for the
//! Settings → Browser extension button, and `parse_code`/`display_code` for the
//! popup handshake. They are unit-tested now so wiring them in cannot change
//! their behaviour.
#![allow(dead_code)]

use crate::core::memory::DpapiGuard;
use crate::error::{Result, VaultError};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Sealed secret, beside the vault (survives host updates; not in the binary).
pub const PAIRING_FILE: &str = "host_pairing.dpapi";
/// 160 bits — exactly 32 Crockford characters.
pub const SECRET_LEN: usize = 20;
/// Crockford base32: no I, L, O or U, so a typed code cannot be misread.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

type HmacSha256 = Hmac<Sha256>;

/// Render a secret as 8 groups of 4 characters (`K7Q2-9F3M-…`).
pub fn display_code(secret: &[u8]) -> String {
    let mut out = String::with_capacity(secret.len() * 2 + 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut chars = 0;
    for byte in secret {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            let idx = ((acc >> (bits - 5)) & 0x1F) as usize;
            if chars > 0 && chars % 4 == 0 {
                out.push('-');
            }
            out.push(CROCKFORD[idx] as char);
            chars += 1;
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 0x1F) as usize;
        if chars > 0 && chars % 4 == 0 {
            out.push('-');
        }
        out.push(CROCKFORD[idx] as char);
    }
    out
}

/// Parse a typed code. Case-insensitive, hyphens/spaces ignored, Crockford's
/// I/L → 1 and O → 0 substitutions applied. Returns exactly `SECRET_LEN` bytes.
pub fn parse_code(code: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(SECRET_LEN);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for ch in code.chars() {
        let c = match ch {
            '-' | ' ' | '\t' | '\r' | '\n' => continue,
            _ => ch.to_ascii_uppercase(),
        };
        let c = match c {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        let idx = CROCKFORD.iter().position(|b| *b as char == c)?;
        acc = (acc << 5) | idx as u32;
        bits += 5;
        if bits >= 8 {
            out.push(((acc >> (bits - 8)) & 0xFF) as u8);
            bits -= 8;
        }
    }
    // Leftover bits must be zero padding, and the length must be exact.
    if bits >= 5 || (bits > 0 && (acc & ((1 << bits) - 1)) != 0) {
        return None;
    }
    if out.len() == SECRET_LEN { Some(out) } else { None }
}

/// Mint a fresh secret, seal it at `path`, and return the code to show the user.
/// The code is never logged; the caller displays it once and drops it.
pub fn mint_at(path: &Path) -> Result<String> {
    use rand::RngCore;
    let mut secret = [0u8; SECRET_LEN];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let sealed = DpapiGuard::protect(&secret)?;
    std::fs::write(path, sealed)
        .map_err(|e| VaultError::Security(format!("pairing seal write failed: {e}")))?;
    let code = display_code(&secret);
    // Best effort: do not leave the plaintext around in a dropped array.
    secret.fill(0);
    Ok(code)
}

/// Load the sealed secret, or `None` when the vault dir has never been paired.
pub fn load_at(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Err(_) => Ok(None),
        Ok(blob) => match DpapiGuard::unprotect(&blob) {
            Ok(secret) => {
                let bytes = secret.expose().to_vec();
                if bytes.len() != SECRET_LEN {
                    return Err(VaultError::Security("pairing secret wrong length".into()));
                }
                Ok(Some(bytes))
            }
            Err(_) => Err(VaultError::Security(
                "pairing seal unreadable (another machine or user?)".into(),
            )),
        },
    }
}

/// Unpair: wipe the sealed secret. Missing file is success.
pub fn clear_at(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(VaultError::Security(format!("pairing seal delete: {e}"))),
    }
}

/// The exact string both sides MAC. Order is fixed; the body is hashed, not
/// embedded, so JSON key order cannot change the result.
pub fn canonical(cmd: &str, seq: u64, ts: u64, body_hash_hex: &str) -> String {
    format!("pv1|{cmd}|{seq}|{ts}|{body_hash_hex}")
}

/// SHA-256 of the canonical JSON body, lower-case hex.
pub fn body_hash_hex(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Split a raw request line into (body without the `mac` field, mac bytes).
///
/// The extension stringifies `{...request, seq, ts}` for the MAC input and then
/// posts `{...request, seq, ts, mac}`; `JSON.stringify` keeps insertion order, so
/// the wire line is that body with `,"mac":"<64 hex>"` spliced in. Removing the
/// field (and its leading comma) reconstructs the exact MAC input. Accepts the
/// field anywhere in the object, not just last.
pub fn strip_mac_field(line: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
    let text = std::str::from_utf8(line).ok()?;
    let key_at = text.find("\"mac\":\"")?;
    let hex_at = key_at + "\"mac\":\"".len();
    let hex_end = text[hex_at..].find('"')? + hex_at;
    let hex = &text[hex_at..hex_end];
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut mac = [0u8; 32];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    // Cut the field and one adjacent comma: the one before it, or — when `mac`
    // is the first key — the one after it.
    let (head, tail) = match text[..key_at].rfind(',') {
        Some(comma) => (comma, hex_end + 1),
        None => {
            let comma = text[hex_end + 1..].find(',')? + hex_end + 1;
            (key_at, comma + 1)
        }
    };
    let mut body = Vec::with_capacity(line.len());
    body.extend_from_slice(&line[..head]);
    body.extend_from_slice(&line[tail..]);
    Some((body, mac))
}

/// What one frame looked like to the pairing guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameVerdict {
    /// MAC, seq and ts all good.
    Verified,
    /// No pairing secret on this machine — step 1 serves anyway.
    Unpaired,
    /// Something is wrong with the frame; the string says what, for the log.
    Rejected(&'static str),
}

/// Per-session verifier: holds the secret (if any) and the last accepted `seq`.
///
/// Step 1 of the rollout: `serve_cli` only logs the verdict. Step 2 turns
/// `Rejected` into a refusal, which is why this type never decides policy.
pub struct FrameGuard {
    secret: Option<Vec<u8>>,
    last_seq: u64,
}

impl FrameGuard {
    pub fn new(secret: Option<Vec<u8>>) -> Self {
        Self {
            secret,
            last_seq: 0,
        }
    }

    /// True when this machine has a pairing secret.
    pub fn is_paired(&self) -> bool {
        self.secret.is_some()
    }

    /// Check one raw request line. `now` is unix seconds.
    pub fn observe(&mut self, line: &[u8], now: u64) -> FrameVerdict {
        let Some(secret) = self.secret.as_deref() else {
            return FrameVerdict::Unpaired;
        };
        let Some((body, mac)) = strip_mac_field(line) else {
            return FrameVerdict::Rejected("no mac field");
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
            return FrameVerdict::Rejected("body is not json");
        };
        let Some(cmd) = value.get("cmd").and_then(|v| v.as_str()) else {
            return FrameVerdict::Rejected("no cmd");
        };
        let Some(seq) = value.get("seq").and_then(|v| v.as_u64()) else {
            return FrameVerdict::Rejected("no seq");
        };
        let Some(ts) = value.get("ts").and_then(|v| v.as_u64()) else {
            return FrameVerdict::Rejected("no ts");
        };
        if !ts_fresh(now, ts) {
            return FrameVerdict::Rejected("stale ts");
        }
        if seq <= self.last_seq {
            return FrameVerdict::Rejected("seq replay");
        }
        if !verify_frame(secret, cmd, seq, ts, &body, &mac) {
            return FrameVerdict::Rejected("bad mac");
        }
        self.last_seq = seq;
        FrameVerdict::Verified
    }
}

/// HMAC-SHA256 over [`canonical`].
pub fn frame_mac(secret: &[u8], cmd: &str, seq: u64, ts: u64, body: &[u8]) -> [u8; 32] {
    let msg = canonical(cmd, seq, ts, &body_hash_hex(body));
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Constant-time verify (`verify_slice` compares without early exit).
pub fn verify_frame(secret: &[u8], cmd: &str, seq: u64, ts: u64, body: &[u8], mac: &[u8]) -> bool {
    let msg = canonical(cmd, seq, ts, &body_hash_hex(body));
    let mut hmac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    hmac.update(msg.as_bytes());
    hmac.verify_slice(mac).is_ok()
}

/// Freshness window for `ts` (seconds, either direction).
pub const TS_SKEW_SECS: u64 = 60;

/// `|now - ts| <= TS_SKEW_SECS`, without an unsigned underflow.
pub fn ts_fresh(now: u64, ts: u64) -> bool {
    now.abs_diff(ts) <= TS_SKEW_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret() -> Vec<u8> {
        (0u8..SECRET_LEN as u8).collect()
    }

    #[test]
    fn code_roundtrips_and_has_the_documented_shape() {
        let secret = sample_secret();
        let code = display_code(&secret);
        assert_eq!(code.len(), 39, "32 chars + 7 hyphens: {code}");
        assert_eq!(code.split('-').count(), 8, "{code}");
        // Cross-language vector: the popup test decodes this exact string.
        assert_eq!(code, "000G-40R4-0M30-E209-185G-R38E-1W81-24GK");
        assert_eq!(parse_code(&code).as_deref(), Some(secret.as_slice()));
    }

    #[test]
    fn typed_code_tolerates_case_hyphens_and_crockford_lookalikes() {
        let secret = sample_secret();
        let code = display_code(&secret);
        let messy = format!(" {} ", code.to_lowercase().replace('-', " "));
        assert_eq!(parse_code(&messy).as_deref(), Some(secret.as_slice()));
        // Crockford maps I/L to 1 and O to 0; the canonical alphabet has neither.
        assert_eq!(parse_code(&code.replace('1', "I")).as_deref(), Some(secret.as_slice()));
        assert_eq!(parse_code(&code.replace('0', "O")).as_deref(), Some(secret.as_slice()));
    }

    #[test]
    fn short_or_corrupt_codes_are_refused() {
        let secret = sample_secret();
        let code = display_code(&secret);
        assert_eq!(parse_code(""), None);
        assert_eq!(parse_code(&code[..code.len() - 1]), None);
        assert_eq!(parse_code(&format!("{code}-0000")), None);
        assert_eq!(parse_code("UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU"), None);
    }

    #[test]
    fn mac_matches_a_known_answer_vector() {
        // Fixed vector so the extension can be checked against the same bytes.
        // Computed independently with .NET SHA256 + HMACSHA256 over the frame
        // without its `mac` field (see docs/A27_HOST_PAIRING.md §3 L2).
        let secret = sample_secret();
        let frame = br#"{"cmd":"list","seq":7,"ts":1763000000,"mac":"b80c4528331e4deb59ffd09a370fd61ede4779b7702425fe44da692cba12278d"}"#;
        let (body, mac) = strip_mac_field(frame).expect("mac field");
        assert_eq!(body, br#"{"cmd":"list","seq":7,"ts":1763000000}"#);
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "b80c4528331e4deb59ffd09a370fd61ede4779b7702425fe44da692cba12278d"
        );
        assert_eq!(
            body_hash_hex(&body),
            "8198cfede316ad1407846f9a3c080295f596d7ab6dfdca6390cb561af748567b"
        );
        assert!(verify_frame(
            &secret,
            "list",
            7,
            1_763_000_000,
            &body,
            &mac
        ));
    }

    #[test]
    fn strip_mac_field_finds_the_field_anywhere() {
        let mac = "00".repeat(32);
        let last = format!(r#"{{"cmd":"a","seq":1,"ts":2,"mac":"{mac}"}}"#);
        let middle = format!(r#"{{"cmd":"a","mac":"{mac}","seq":1,"ts":2}}"#);
        let first = format!(r#"{{"mac":"{mac}","cmd":"a","seq":1,"ts":2}}"#);
        for line in [last, middle, first] {
            let (body, parsed) = strip_mac_field(line.as_bytes()).expect("field found");
            assert_eq!(
                String::from_utf8(body).expect("utf8"),
                r#"{"cmd":"a","seq":1,"ts":2}"#,
                "line: {line}"
            );
            assert_eq!(parsed, [0u8; 32]);
        }
        // No field, bad length, non-hex, non-utf8: all None, never a panic.
        assert!(strip_mac_field(br#"{"cmd":"a"}"#).is_none());
        assert!(strip_mac_field(br#"{"cmd":"a","mac":"00"}"#).is_none());
        let short = "z".repeat(64);
        assert!(
            strip_mac_field(format!(r#"{{"cmd":"a","mac":"{short}"}}"#).as_bytes()).is_none()
        );
        assert!(strip_mac_field(&[0xff, 0xfe]).is_none());
    }

    #[test]
    fn guard_accepts_a_fresh_frame_and_refuses_replays() {
        let secret = sample_secret();
        let now = 1_763_000_000u64;
        let mac = frame_mac(&secret, "list", 7, now, br#"{"cmd":"list","seq":7,"ts":1763000000}"#);
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        let line = format!(r#"{{"cmd":"list","seq":7,"ts":1763000000,"mac":"{hex}"}}"#);

        let mut guard = FrameGuard::new(Some(secret.clone()));
        assert_eq!(guard.observe(line.as_bytes(), now), FrameVerdict::Verified);
        // Same seq again: replay, even though the MAC is valid.
        assert_eq!(
            guard.observe(line.as_bytes(), now),
            FrameVerdict::Rejected("seq replay")
        );
        // Out-of-window ts: refused before the MAC check.
        let mut fresh = FrameGuard::new(Some(secret.clone()));
        assert_eq!(
            fresh.observe(line.as_bytes(), now + 61),
            FrameVerdict::Rejected("stale ts")
        );
        // Tampered body keeps the old MAC: refused.
        let mut tampered = FrameGuard::new(Some(secret));
        let bad = line.replace("\"list\",\"seq\"", "\"get\",\"seq\"");
        assert_eq!(
            tampered.observe(bad.as_bytes(), now),
            FrameVerdict::Rejected("bad mac")
        );
        // No secret: unpaired, and nothing is remembered.
        let mut unpaired = FrameGuard::new(None);
        assert!(!unpaired.is_paired());
        assert_eq!(unpaired.observe(line.as_bytes(), now), FrameVerdict::Unpaired);
    }

    #[test]
    fn mac_binds_every_field() {
        let secret = sample_secret();
        let base = frame_mac(&secret, "list", 7, 1_763_000_000, b"{}");
        assert!(verify_frame(&secret, "list", 7, 1_763_000_000, b"{}", &base));
        assert!(!verify_frame(&secret, "get", 7, 1_763_000_000, b"{}", &base));
        assert!(!verify_frame(&secret, "list", 8, 1_763_000_000, b"{}", &base));
        assert!(!verify_frame(&secret, "list", 7, 1_763_000_001, b"{}", &base));
        assert!(!verify_frame(&secret, "list", 7, 1_763_000_000, b"{\"x\":1}", &base));
        let mut other = secret.clone();
        other[0] ^= 1;
        assert!(!verify_frame(&other, "list", 7, 1_763_000_000, b"{}", &base));
    }

    #[test]
    fn ts_window_is_symmetric_and_bounded() {
        assert!(ts_fresh(1_000, 1_000));
        assert!(ts_fresh(1_000, 1_060));
        assert!(ts_fresh(1_060, 1_000));
        assert!(!ts_fresh(1_000, 1_061));
        assert!(!ts_fresh(1_061, 1_000));
        // A far-past ts must not underflow.
        assert!(!ts_fresh(5, 1_000_000));
    }

    #[test]
    fn mint_load_clear_roundtrip() {
        let path = std::env::temp_dir().join(format!("pv-pair-{}.dpapi", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let code = mint_at(&path).expect("mint");
        let loaded = load_at(&path).expect("load").expect("present");
        assert_eq!(parse_code(&code).as_deref(), Some(loaded.as_slice()));
        clear_at(&path).expect("clear");
        assert!(load_at(&path).expect("load after clear").is_none());
        // Clearing twice is not an error.
        clear_at(&path).expect("clear twice");
    }

    #[test]
    fn corrupt_seal_is_an_error_not_a_panic() {
        let path = std::env::temp_dir().join(format!("pv-pair-bad-{}.dpapi", std::process::id()));
        std::fs::write(&path, b"not-dpapi").unwrap();
        assert!(load_at(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
