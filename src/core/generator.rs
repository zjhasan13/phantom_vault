use rand::seq::SliceRandom;
use rand_core::OsRng;
use secrecy::SecretString;
use std::str::FromStr;

use crate::error::{Result, VaultError};

const EFF_WORDLIST: &str = include_str!("../../assets/eff_large_wordlist.txt");
/// Offline Bengali diceware list (everyday memorable words, one per line).
const BN_WORDLIST: &str = include_str!("../../assets/bengali_words.txt");
/// Bengali digits for the 2-digit diceware suffix (০–৯).
const BN_DIGITS: &[char] = &['০', '১', '২', '৩', '৪', '৫', '৬', '৭', '৮', '৯'];
const AMBIGUOUS: &[char] = &['0', 'O', 'o', 'l', '1', 'I', '|'];
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/";

fn strip_ambiguous(s: &str) -> String {
    s.chars().filter(|c| !AMBIGUOUS.contains(c)).collect()
}

pub struct PasswordPolicy {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self { length: 20, uppercase: true, lowercase: true, digits: true, symbols: true, exclude_ambiguous: true }
    }
}

impl PasswordPolicy {
    fn charsets(&self) -> Result<Vec<Vec<char>>> {
        if self.length < 8 || self.length > 128 {
            return Err(VaultError::GeneratorInvalidParams("length out of range".into()));
        }
        let mut sets: Vec<Vec<char>> = Vec::new();
        let mut push = |s: &str, on: bool| {
            if on {
                let mut v: String = s.into();
                if self.exclude_ambiguous {
                    v = strip_ambiguous(&v);
                }
                if !v.is_empty() {
                    sets.push(v.chars().collect());
                }
            }
        };
        push("ABCDEFGHIJKLMNOPQRSTUVWXYZ", self.uppercase);
        push("abcdefghijklmnopqrstuvwxyz", self.lowercase);
        push("0123456789", self.digits);
        push(SYMBOLS, self.symbols);
        if sets.is_empty() {
            return Err(VaultError::GeneratorInvalidParams("no charset selected".into()));
        }
        Ok(sets)
    }

    fn union_size(&self) -> Result<usize> {
        Ok(self.charsets()?.iter().map(|s| s.len()).sum())
    }
}

pub struct PasswordGenerator;

impl PasswordGenerator {
    pub fn generate_complex(policy: &PasswordPolicy) -> Result<SecretString> {
        let sets = policy.charsets()?;
        let union: Vec<char> = sets.iter().flatten().copied().collect();
        if policy.length < sets.len() {
            return Err(VaultError::GeneratorInvalidParams("length out of range".into()));
        }
        let mut rng = OsRng;
        let mut buf: Vec<char> = sets
            .iter()
            .map(|s| {
                s.choose(&mut rng).copied().ok_or_else(|| {
                    VaultError::GeneratorInvalidParams("no charset selected".into())
                })
            })
            .collect::<Result<Vec<char>>>()?;
        while buf.len() < policy.length {
            let c = union.choose(&mut rng).ok_or_else(|| {
                VaultError::GeneratorInvalidParams("no charset selected".into())
            })?;
            buf.push(*c);
        }
        // Fisher-Yates via shuffle (uses uniform distribution over OsRng)
        buf.shuffle(&mut rng);
        let s: String = buf.iter().collect();
        SecretString::from_str(&s).map_err(|_| {
            VaultError::GeneratorInvalidParams("failed to wrap secret".into())
        })
    }

    pub fn generate_diceware(word_count: usize, separator: char) -> Result<SecretString> {
        if !(4..=12).contains(&word_count) {
            return Err(VaultError::GeneratorInvalidParams("word count out of range".into()));
        }
        let words: Vec<&str> = EFF_WORDLIST.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        if words.len() < 7776 {
            return Err(VaultError::GeneratorInvalidParams("wordlist corrupted".into()));
        }
        let mut rng = OsRng;
        let picked: Vec<&str> = (0..word_count)
            .map(|_| {
                words.choose(&mut rng).copied().ok_or_else(|| {
                    VaultError::GeneratorInvalidParams("wordlist corrupted".into())
                })
            })
            .collect::<Result<Vec<&str>>>()?;
        let sep = separator.to_string();
        let s = picked.join(&sep);
        SecretString::from_str(&s)
            .map_err(|_| VaultError::GeneratorInvalidParams("failed to wrap secret".into()))
    }

    pub fn entropy_bits_complex(policy: &PasswordPolicy) -> f64 {
        match policy.union_size() {
            Ok(n) if n > 0 => policy.length as f64 * (n as f64).log2(),
            _ => 0.0,
        }
    }

    pub fn entropy_bits_diceware(word_count: usize) -> f64 {
        word_count as f64 * 7776f64.log2()
    }

    /// Bengali diceware: 4–8 everyday words + a 2-digit Bengali suffix
    /// (e.g. `মেঘ-বৃষ্টি-পাহাড়-নদী-২৬`). Words via OsRng uniform sampling.
    pub fn generate_diceware_bn(word_count: usize, separator: char) -> Result<SecretString> {
        if !(4..=8).contains(&word_count) {
            return Err(VaultError::GeneratorInvalidParams("word count out of range".into()));
        }
        let words: Vec<&str> = BN_WORDLIST.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        if words.len() < 100 {
            return Err(VaultError::GeneratorInvalidParams("wordlist corrupted".into()));
        }
        let mut rng = OsRng;
        let picked: Vec<&str> = (0..word_count)
            .map(|_| {
                words.choose(&mut rng).copied().ok_or_else(|| {
                    VaultError::GeneratorInvalidParams("wordlist corrupted".into())
                })
            })
            .collect::<Result<Vec<&str>>>()?;
        // 2-digit suffix in Bengali numerals (00–99).
        let mut suffix = String::new();
        for _ in 0..2 {
            let mut b = [0u8; 4];
            use rand_core::RngCore as _;
            rng.fill_bytes(&mut b);
            suffix.push(BN_DIGITS[(u32::from_le_bytes(b) % 10) as usize]);
        }
        // Join words, then append separator + suffix.
        let mut s = picked.join(&separator.to_string());
        s.push(separator);
        s.push_str(&suffix);
        SecretString::from_str(&s)
            .map_err(|_| VaultError::GeneratorInvalidParams("failed to wrap secret".into()))
    }

    /// True Shannon bits: words × log2(list) + log2(100) for the suffix.
    pub fn entropy_bits_diceware_bn(word_count: usize) -> f64 {
        let n = BN_WORDLIST.lines().map(str::trim).filter(|l| !l.is_empty()).count().max(1) as f64;
        word_count as f64 * n.log2() + 100f64.log2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn complex_respects_length() {
        let policy = PasswordPolicy { length: 32, ..Default::default() };
        let pwd = PasswordGenerator::generate_complex(&policy).unwrap();
        assert_eq!(pwd.expose_secret().len(), 32);
    }

    #[test]
    fn complex_rejects_all_disabled() {
        let policy = PasswordPolicy {
            length: 20, uppercase: false, lowercase: false,
            digits: false, symbols: false, exclude_ambiguous: true,
        };
        assert!(PasswordGenerator::generate_complex(&policy).is_err());
    }

    #[test]
    fn complex_rejects_short_length() {
        let policy = PasswordPolicy { length: 4, ..Default::default() };
        assert!(PasswordGenerator::generate_complex(&policy).is_err());
    }

    #[test]
    fn diceware_produces_correct_word_count() {
        // '_' never appears in the EFF list (unlike '-' in drop-down,
        // felt-tip, t-shirt, yo-yo) — exact split count, zero flake.
        let pwd = PasswordGenerator::generate_diceware(6, '_').unwrap();
        assert_eq!(pwd.expose_secret().split('_').count(), 6);
    }

    #[test]
    fn diceware_rejects_out_of_range() {
        assert!(PasswordGenerator::generate_diceware(2, '-').is_err());
        assert!(PasswordGenerator::generate_diceware(20, '-').is_err());
    }

    #[test]
    fn entropy_calculation_reasonable() {
        let policy = PasswordPolicy::default();
        let bits = PasswordGenerator::entropy_bits_complex(&policy);
        assert!(bits > 100.0);
    }

    #[test]
    fn diceware_entropy_matches_formula() {
        let bits = PasswordGenerator::entropy_bits_diceware(6);
        assert!((bits - 77.5).abs() < 0.5);
    }

    #[test]
    fn uniqueness_check() {
        let policy = PasswordPolicy::default();
        let a = PasswordGenerator::generate_complex(&policy).unwrap();
        let b = PasswordGenerator::generate_complex(&policy).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn bengali_wordlist_is_healthy() {
        let words: Vec<&str> = BN_WORDLIST.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        assert!(words.len() >= 100, "need 100+ words, got {}", words.len());
        let mut seen = std::collections::HashSet::new();
        for w in &words {
            assert!(seen.insert(*w), "duplicate word: {w}");
        }
    }

    #[test]
    fn bengali_diceware_shape_and_entropy() {
        let pwd = PasswordGenerator::generate_diceware_bn(4, '-').unwrap();
        let s = pwd.expose_secret();
        // 4 words + 2-digit suffix = 5 dash-separated parts.
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts[4].chars().all(|c| ('০'..='৯').contains(&c)));
        assert_eq!(parts[4].chars().count(), 2);
        assert!(PasswordGenerator::generate_diceware_bn(3, '-').is_err());
        assert!(PasswordGenerator::generate_diceware_bn(9, '-').is_err());
        let bits = PasswordGenerator::entropy_bits_diceware_bn(4);
        let n = BN_WORDLIST.lines().map(str::trim).filter(|l| !l.is_empty()).count() as f64;
        assert!((bits - (4.0 * n.log2() + 100f64.log2())).abs() < 1e-9);
        assert!(bits > 30.0);
    }
}
