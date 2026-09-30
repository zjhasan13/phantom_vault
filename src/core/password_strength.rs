//! Per-item password strength meter (local only, no network).
//!
//! Pure estimator: length + charset variety + entropy + pattern penalties.
//! Returns a level 0..=3 (Weak/Fair/Strong/Excellent), a 0.0..=1.0 bar
//! fraction, and a one-line label (`Strong • 14 char • unique`).
//! Reuse/age signals are appended by the caller (it owns the vault).

/// Strength level: 0 Weak, 1 Fair, 2 Strong, 3 Excellent.
pub fn level(password: &str) -> u8 {
    let len = password.chars().count();
    if len == 0 {
        return 0;
    }
    let (mut lower, mut upper, mut digit, mut symbol) = (false, false, false, false);
    for ch in password.chars() {
        if ch.is_ascii_lowercase() {
            lower = true;
        } else if ch.is_ascii_uppercase() {
            upper = true;
        } else if ch.is_ascii_digit() {
            digit = true;
        } else {
            symbol = true;
        }
    }
    let classes = [lower, upper, digit, symbol].iter().filter(|&&b| b).count() as u8;

    // Entropy estimate: len * log2(pool). Pool from observed classes.
    let pool: f64 = (if lower { 26.0 } else { 0.0 })
        + (if upper { 26.0 } else { 0.0 })
        + (if digit { 10.0 } else { 0.0 })
        + (if symbol { 33.0 } else { 0.0 });
    let bits = if pool > 1.0 {
        len as f64 * pool.log2()
    } else {
        0.0
    };
    // Pattern penalties: all-one-class, repeated char, sequence.
    let penalty: u8 = if classes <= 1 && len < 12 {
        1
    } else if has_repeat_run(password, 4) || has_sequence(password) {
        1
    } else {
        0
    };
    let score: u8 = if bits >= 80.0 && len >= 14 && classes >= 3 {
        3
    } else if bits >= 55.0 && len >= 11 && classes >= 3 {
        2
    } else if bits >= 35.0 && len >= 8 && classes >= 2 {
        1
    } else {
        0
    };
    score.saturating_sub(penalty)
}

/// Bar fraction for the meter: level mapped to 0.25/0.5/0.75/1.0.
pub fn fraction(password: &str) -> f32 {
    match level(password) {
        0 => 0.25,
        1 => 0.5,
        2 => 0.75,
        _ => 1.0,
    }
}

/// Short label for the meter row.
pub fn label(password: &str) -> String {
    let name = match level(password) {
        0 => "Weak",
        1 => "Fair",
        2 => "Strong",
        _ => "Excellent",
    };
    format!("{name} • {} char", password.chars().count())
}

/// Full one-liner with reuse/age appended by the detail renderer.
/// `reused_n`: other items sharing the exact password. `stale`: 180d+.
pub fn detail(password: &str, reused_n: usize, stale: bool) -> String {
    let mut s = label(password);
    if reused_n > 0 {
        s.push_str(&format!(
            " • reused in {} item{}",
            reused_n,
            if reused_n == 1 { "" } else { "s" }
        ));
    } else {
        s.push_str(" • unique");
    }
    if stale {
        s.push_str(" • rotate me");
    }
    s
}

fn has_repeat_run(s: &str, n: usize) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < n {
        return false;
    }
    chars.windows(n).any(|w| w.iter().all(|&c| c == w[0]))
}

fn has_sequence(s: &str) -> bool {
    let lower: String = s.to_lowercase();
    for seq in ["1234", "abcd", "qwer", "password", "1111", "0000"] {
        if lower.contains(seq) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_weak() {
        assert_eq!(level(""), 0);
        assert_eq!(fraction(""), 0.25);
    }

    #[test]
    fn short_single_class_is_weak() {
        assert_eq!(level("abc123"), 0);
        assert_eq!(level("password"), 0);
    }

    #[test]
    fn long_mixed_is_strong_or_better() {
        assert!(level("zahid2zahidZ#") >= 2);
        assert!(level("Tr7$kQ9!mZ2@pXw4#vB8n") == 3);
    }

    #[test]
    fn patterns_penalized() {
        assert_eq!(level("Aaaa1111"), 0);
        // "Abcd1234!" looks mixed but trips the sequence rule → Weak.
        assert_eq!(level("Abcd1234!"), 0);
        // Same shape, no sequence → Fair.
        assert_eq!(level("Tr7kqm9x"), 1);
    }

    #[test]
    fn detail_appends_reuse_and_stale() {
        let d = detail("Tr7$kQ9!mZ2@pXw4#vB8n", 0, false);
        assert!(d.contains("unique"), "{d}");
        let d = detail("abc123", 3, true);
        assert!(d.contains("reused in 3 items"), "{d}");
        assert!(d.contains("rotate me"), "{d}");
    }

    #[test]
    fn fraction_steps() {
        assert_eq!(fraction("abc"), 0.25);
        assert_eq!(fraction("Tr7$kQ9!mZ2@pXw4#vB8n"), 1.0);
    }
}
