//! Phase 17 (Option 3 combo) — Shamir's Secret Sharing 3-of-5 recovery.
//!
//! Splits the master password into 5 printable word-shards; any 3 rebuild it.
//! Math: GF(2^8) with AES polynomial 0x11B, one random degree-2 polynomial per
//! secret byte (classic byte-wise SSS). Coefficients from `OsRng` only.
//! Word layer: EFF wordlist (7776 words) as 13-bit groups, bit-packed.
//!
//! Honest limits: shards authenticate NOTHING — a tampered shard yields a
//! wrong password, which the vault then rejects as "Wrong Password". Shards
//! must be stored on paper / offline media, never all on one disk.

use crate::error::{Result, VaultError};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::sync::OnceLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const THRESHOLD: usize = 3;
pub const SHARES: usize = 5;
pub const MAX_SECRET_LEN: usize = 128;
/// Word-shard path caps passwords at 64 bytes → fixed 82-word sheets.
pub const WORD_SECRET_MAX: usize = 64;

const EFF_WORDLIST: &str = include_str!("../../assets/eff_large_wordlist.txt");

fn word_list() -> &'static Vec<&'static str> {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        EFF_WORDLIST
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect()
    })
}

fn word_index() -> &'static HashMap<&'static str, usize> {
    static INDEX: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
    INDEX.get_or_init(|| {
        word_list()
            .iter()
            .enumerate()
            .map(|(i, w)| (*w, i))
            .collect()
    })
}

// ---- GF(2^8) ----

fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B; // AES polynomial x^8+x^4+x^3+x+1 (low byte)
        }
        b >>= 1;
    }
    p
}

fn gf_pow(mut a: u8, mut e: u8) -> u8 {
    let mut r = 1u8;
    while e != 0 {
        if e & 1 != 0 {
            r = gf_mul(r, a);
        }
        a = gf_mul(a, a);
        e >>= 1;
    }
    r
}

fn gf_inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    Some(gf_pow(a, 254))
}

// ---- sharing ----

/// Split `secret` into 5 shards (x=1..=5). Each shard: [x][len_lo][len_hi][data].
fn split_bytes(secret: &[u8]) -> Result<Vec<Vec<u8>>> {
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(VaultError::Security("secret length out of range".into()));
    }
    let mut rng = OsRng;
    let mut shards: Vec<Vec<u8>> = (1u8..=SHARES as u8)
        .map(|x| {
            let mut v = Vec::with_capacity(3 + secret.len());
            v.push(x);
            v.push(secret.len() as u8);
            v.push((secret.len() >> 8) as u8);
            v
        })
        .collect();
    let mut coeff = [0u8; 2];
    for &s in secret.iter() {
        rng.fill_bytes(&mut coeff);
        for (x, shard) in (1u8..).zip(shards.iter_mut()) {
            // y = s + c1*x + c2*x^2
            let y = gf_add(
                s,
                gf_add(gf_mul(coeff[0], x), gf_mul(coeff[1], gf_mul(x, x))),
            );
            shard.push(y);
        }
    }
    coeff.zeroize();
    Ok(shards)
}

/// Rebuild from ≥3 shards. Verifies distinct x, matching lengths.
fn combine_bytes(shards: &[Vec<u8>]) -> Result<Vec<u8>> {
    if shards.len() < THRESHOLD {
        return Err(VaultError::Security("need at least 3 shards".into()));
    }
    let mut xs: Vec<u8> = Vec::new();
    let mut len: Option<usize> = None;
    // Use exactly the first THRESHOLD shards (extras ignored deterministically).
    let use_shards = &shards[..THRESHOLD.min(shards.len())];
    if use_shards.len() < THRESHOLD {
        return Err(VaultError::Security("need at least 3 shards".into()));
    }
    for sh in use_shards {
        if sh.len() < 3 || sh[0] == 0 {
            return Err(VaultError::Security("malformed shard".into()));
        }
        let l = (sh[1] as usize) | ((sh[2] as usize) << 8);
        if l == 0 || l > MAX_SECRET_LEN || sh.len() != 3 + l {
            return Err(VaultError::Security("malformed shard".into()));
        }
        if xs.contains(&sh[0]) {
            return Err(VaultError::Security("duplicate shard".into()));
        }
        xs.push(sh[0]);
        match len {
            Some(prev) if prev != l => {
                return Err(VaultError::Security("shard length mismatch".into()))
            }
            _ => len = Some(l),
        }
    }
    let len = len.ok_or_else(|| VaultError::Security("no shards".into()))?;
    let mut secret = vec![0u8; len];
    for i in 0..len {
        // Lagrange at x=0: s = Σ y_j * Π_{m≠j} x_m/(x_m - x_j)
        let mut acc = 0u8;
        for (j, &xj) in xs.iter().enumerate() {
            let yj = use_shards[j][3 + i];
            let mut num = 1u8;
            let mut den = 1u8;
            for (m, &xm) in xs.iter().enumerate() {
                if m == j {
                    continue;
                }
                num = gf_mul(num, xm);
                den = gf_mul(den, gf_add(xm, xj));
            }
            let den_inv = gf_inv(den)
                .ok_or_else(|| VaultError::Security("singular shard set".into()))?;
            acc = gf_add(acc, gf_mul(yj, gf_mul(num, den_inv)));
        }
        secret[i] = acc;
    }
    Ok(secret)
}

// ---- word layer (fixed-width base-7776 over the EFF list) ----
//
// 13-bit groups can't address a 7776-word list without overflow, so shards
// are converted as whole big-endian numbers: 67 bytes ([x][len_lo][len_hi]
// + up to 64 secret bytes) <-> exactly 82 base-7776 words. Fixed width
// keeps encode/decode perfectly reversible with zero length ambiguity.

/// Fixed shard byte length on the word path: 3 header + 64 secret.
const WORD_BYTES: usize = 3 + WORD_SECRET_MAX;
/// Fixed word count: 256^67 needs ceil(67*8/log2(7776)) = 42… but leading-zero
/// preservation demands the full width that always fits: 82 words carry 1060
/// bits ≥ 536 bits. Verified by `fixed_width_capacity` test below.
const WORD_COUNT: usize = 82;
const WORD_BASE: u32 = 7776;

fn words_encode(data: &[u8]) -> Result<String> {
    let words = word_list();
    if words.len() < 7776 {
        return Err(VaultError::Security("wordlist corrupted".into()));
    }
    if data.len() > WORD_BYTES {
        return Err(VaultError::Security("shard too long for word sheet".into()));
    }
    // Left-pad to fixed width (preserves leading zeros exactly).
    let mut num = vec![0u8; WORD_BYTES - data.len()];
    num.extend_from_slice(data);
    let mut digits = Vec::with_capacity(WORD_COUNT);
    for _ in 0..WORD_COUNT {
        digits.push(divmod_base(&mut num, WORD_BASE) as usize);
    }
    if num.iter().any(|&b| b != 0) {
        return Err(VaultError::Security("word encode overflow".into()));
    }
    digits.reverse();
    Ok(digits.iter().map(|&d| words[d]).collect::<Vec<_>>().join(" "))
}

/// In-place big-endian long division of `num` by `div`; returns remainder.
fn divmod_base(num: &mut [u8], div: u32) -> u32 {
    let mut rem: u32 = 0;
    for b in num.iter_mut() {
        let cur = (rem << 8) | (*b as u32);
        *b = (cur / div) as u8;
        rem = cur % div;
    }
    rem
}

fn words_decode(text: &str) -> Result<Vec<u8>> {
    let index = word_index();
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() != WORD_COUNT {
        return Err(VaultError::Security("shard must be 82 words".into()));
    }
    // Horner: num = num*7776 + digit, base-256 bytes big-endian.
    let mut num = [0u8; WORD_BYTES];
    for w in parts {
        let digit = *index
            .get(w.to_lowercase().as_str())
            .ok_or_else(|| VaultError::Security(format!("unknown recovery word: {w}")))?
            as u32;
        let mut carry = digit;
        for b in num.iter_mut().rev() {
            let cur = (*b as u32) * WORD_BASE + carry;
            *b = (cur & 0xFF) as u8;
            carry = cur >> 8;
        }
        if carry != 0 {
            return Err(VaultError::Security("shard value overflow".into()));
        }
    }
    // Strip the left-pad zeros, then validate the header length.
    let first = num.iter().position(|&b| b != 0).unwrap_or(num.len());
    let out = num[first..].to_vec();
    if out.is_empty() {
        return Err(VaultError::Security("malformed shard".into()));
    }
    // Header [x][len_lo][len_hi] must agree with the remaining length.
    if out.len() >= 3 {
        let l = (out[1] as usize) | ((out[2] as usize) << 8);
        if l <= WORD_SECRET_MAX && out.len() == 3 + l {
            return Ok(out);
        }
    }
    // Fallback: accept raw (combine_bytes re-validates strictly).
    Ok(out)
}

/// Zeroizing recovered secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveredSecret(pub Vec<u8>);

impl RecoveredSecret {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

pub struct Shamir;

impl Shamir {
    /// Split a master password into 5 printable word-shards (82 words each).
    /// Passwords up to 64 bytes; longer ones are rejected with guidance.
    pub fn split(password: &str) -> Result<Vec<String>> {
        let bytes = password.as_bytes();
        if bytes.is_empty() || bytes.len() > WORD_SECRET_MAX {
            return Err(VaultError::Security(
                "password must be 1..=64 bytes for word shards".into(),
            ));
        }
        split_bytes(bytes)?
            .iter()
            .map(|sh| {
                let words = words_encode(sh)?;
                Ok(format!("PHANTOM-{} {}", sh[0], words))
            })
            .collect()
    }

    /// Rebuild the password from any ≥3 word-shards.
    pub fn combine(shard_texts: &[&str]) -> Result<RecoveredSecret> {        if shard_texts.len() < THRESHOLD {
            return Err(VaultError::Security("need at least 3 shards".into()));
        }
        let mut shards = Vec::new();
        for text in shard_texts.iter().take(SHARES) {
            let t = text.trim();
            let body = t.strip_prefix("PHANTOM-").unwrap_or(t);
            // First token is the shard number; the rest are the 82 words.
            let mut parts = body.split_whitespace();
            let _num: u8 = parts
                .next()
                .ok_or_else(|| VaultError::Security("malformed shard".into()))?
                .parse()
                .map_err(|_| VaultError::Security("malformed shard".into()))?;
            let words: String = parts.collect::<Vec<_>>().join(" ");
            shards.push(words_decode(&words)?);
        }
        Ok(RecoveredSecret(combine_bytes(&shards)?))
    }

    /// Recovery drill: shard text is `PHANTOM-n w1 w2 w3 …` — verify the
    /// 2nd and 4th WORDS (1-indexed past the prefix). Pure — unit tested.
    pub fn check_drill(shard: &str, w2: &str, w4: &str) -> bool {
        let words: Vec<&str> = shard.split_whitespace().skip(1).collect();
        if words.len() < 4 {
            return false;
        }
        words[1].eq_ignore_ascii_case(w2.trim()) && words[3].eq_ignore_ascii_case(w4.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_arithmetic_sane() {
        assert_eq!(gf_add(0x53, 0xCA), 0x99);
        assert_eq!(gf_mul(0x57, 0x13), 0xFE); // AES spec vector
        for a in [1u8, 7, 42, 200] {
            assert_eq!(gf_mul(a, gf_inv(a).unwrap()), 1);
        }
        assert!(gf_inv(0).is_none());
    }

    #[test]
    fn split_combine_any_three_of_five() {
        let shards = split_bytes(b"correct-horse-battery").unwrap();
        assert_eq!(shards.len(), 5);
        // Every 3-subset rebuilds (C(5,3) = 10 combos).
        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let got =
                        combine_bytes(&[shards[a].clone(), shards[b].clone(), shards[c].clone()])
                            .unwrap();
                    assert_eq!(got, b"correct-horse-battery");
                }
            }
        }
    }

    #[test]
    fn two_shards_fail() {
        let shards = split_bytes(b"abc").unwrap();
        assert!(combine_bytes(&shards[..2]).is_err());
    }

    #[test]
    fn word_roundtrip() {
        let texts = Shamir::split("my-master-pass-123!").unwrap();
        assert_eq!(texts.len(), 5);
        assert!(texts[0].starts_with("PHANTOM-1 "));
        assert_eq!(texts[0].split_whitespace().count(), 1 + WORD_COUNT);
        let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
        // First three…
        let rec = Shamir::combine(&refs[..3]).unwrap();
        assert_eq!(rec.expose(), b"my-master-pass-123!");
        // …and a different three (shards 2,4,5).
        let rec2 = Shamir::combine(&[refs[1], refs[3], refs[4]]).unwrap();
        assert_eq!(rec2.expose(), b"my-master-pass-123!");
    }

    #[test]
    fn fixed_width_capacity() {
        // 82 base-7776 digits must swallow the longest word-path shard.
        let long = "p".repeat(WORD_SECRET_MAX);
        let texts = Shamir::split(&long).unwrap();
        let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
        let rec = Shamir::combine(&refs[..3]).unwrap();
        assert_eq!(rec.expose(), long.as_bytes());
        // Over-long passwords are refused with guidance, not truncated.
        assert!(Shamir::split(&"p".repeat(WORD_SECRET_MAX + 1)).is_err());
    }

    #[test]
    fn tampered_shard_reconstructs_wrong() {
        let texts = Shamir::split("secret123").unwrap();
        // Flip the last word of shard 1 to a valid-but-wrong word.
        let mut bad_words: Vec<&str> = texts[0].split_whitespace().collect();
        let last = bad_words.len() - 1;
        if bad_words[last] != "abacus" {
            bad_words[last] = "abacus";
        } else {
            bad_words[last] = "abdomen";
        }
        let bad = bad_words.join(" ");
        let refs: Vec<&str> = texts[1..].iter().map(|s| s.as_str()).collect();
        let rec = Shamir::combine(&[bad.as_str(), refs[0], refs[1]]);
        // Either a hard error or a WRONG secret (vault rejects it as bad password).
        match rec {
            Err(_) => {}
            Ok(r) => assert_ne!(r.expose(), b"secret123"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(Shamir::combine(&["hello world"]).is_err());
        assert!(Shamir::combine(&["PHANTOM-1 abacus", "PHANTOM-1 abacus", "nope nope"]).is_err());
    }

    #[test]
    fn drill_checks_words_two_and_four() {
        let texts = Shamir::split("secret123").unwrap();
        let words: Vec<&str> = texts[0].split_whitespace().skip(1).collect();
        assert!(Shamir::check_drill(&texts[0], words[1], words[3]));
        assert!(Shamir::check_drill(&texts[0], &words[1].to_uppercase(), words[3]));
        assert!(!Shamir::check_drill(&texts[0], "nope", words[3]));
        assert!(!Shamir::check_drill(&texts[0], words[1], ""));
        assert!(!Shamir::check_drill("PHANTOM-1 only", "a", "b"));
    }
}
