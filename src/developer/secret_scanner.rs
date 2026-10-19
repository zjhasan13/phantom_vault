//! Phase 16 (Option 2a) — Git secret-leak pre-commit scanner.
//!
//! Hand-rolled matchers (no regex dependency): prefix + alphabet + length
//! checks per provider, plus a Shannon-entropy tripwire for generic tokens.
//! Scans working-tree files (respects skip dirs), binary-safe (NUL = skip),
//! and never prints matched secrets — only file:line + rule id.

use std::path::Path;

pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule: &'static str,
}

struct Rule {
    id: &'static str,
    prefix: &'static str,
    /// extra required total length AFTER the prefix (0 = any)
    min_tail: usize,
    /// allowed tail alphabet classes
    tail: TailKind,
    /// true = prefix presence alone is a hit (no tail validation)
    bare: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum TailKind {
    Any,
    Base64ish,
    AwsKey,
    AnyNoSpace,
}

fn is_base64ish(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '_' || c == '-' || c == '='
}

fn tail_ok(kind: TailKind, tail: &str, min_tail: usize) -> bool {
    if tail.len() < min_tail {
        return false;
    }
    if tail.is_empty() {
        return false;
    }
    match kind {
        TailKind::Any => true,
        TailKind::AnyNoSpace => !tail.chars().any(|c| c.is_whitespace()),
        TailKind::Base64ish => tail.chars().all(is_base64ish),
        TailKind::AwsKey => tail
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
    }
}

const RULES: &[Rule] = &[
    Rule { id: "openai", prefix: "sk-", min_tail: 20, tail: TailKind::Base64ish, bare: false },
    Rule { id: "openai-project", prefix: "sk-proj-", min_tail: 20, tail: TailKind::Base64ish, bare: false },
    Rule { id: "aws-access", prefix: "AKIA", min_tail: 16, tail: TailKind::AwsKey, bare: false },
    Rule { id: "github-pat", prefix: "ghp_", min_tail: 20, tail: TailKind::Base64ish, bare: false },
    Rule { id: "github-oauth", prefix: "gho_", min_tail: 20, tail: TailKind::Base64ish, bare: false },
    Rule { id: "stripe-live", prefix: "sk_live_", min_tail: 10, tail: TailKind::Base64ish, bare: false },
    Rule { id: "stripe-test", prefix: "sk_test_", min_tail: 10, tail: TailKind::Base64ish, bare: false },
    Rule { id: "slack", prefix: "xox", min_tail: 10, tail: TailKind::AnyNoSpace, bare: false },
    Rule { id: "private-key", prefix: "-----BEGIN", min_tail: 0, tail: TailKind::Any, bare: true },
    Rule { id: "generic-password-assign", prefix: "password=", min_tail: 4, tail: TailKind::AnyNoSpace, bare: false },
    Rule { id: "generic-secret-assign", prefix: "secret=", min_tail: 4, tail: TailKind::AnyNoSpace, bare: false },
    Rule { id: "generic-api-key-assign", prefix: "api_key=", min_tail: 4, tail: TailKind::AnyNoSpace, bare: false },
    Rule { id: "generic-apikey-assign", prefix: "apikey=", min_tail: 4, tail: TailKind::AnyNoSpace, bare: false },
];

/// Shannon entropy per char; flags random-looking tokens.
fn entropy_per_char(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Scan one line for provider rules + entropy tripwire (len>=24, entropy>=3.5,
/// only on assigned values, URL-shaped values skipped).
fn scan_line(line: &str) -> Vec<&'static str> {
    let mut hits = Vec::new();
    // ASCII-only lowercasing preserves byte length and char boundaries, so
    // offsets found in `lowered` stay valid in `line`. Full `to_lowercase()`
    // can change byte length (e.g. 'İ' → "i̇"), which used to make the
    // `line[abs + prefix.len()..]` slice panic on multi-byte input.
    let lowered = line.to_ascii_lowercase();
    for rule in RULES {
        let needle = rule.prefix.to_ascii_lowercase();
        if needle.is_empty() {
            continue;
        }
        let mut start = 0;
        while let Some(pos) = lowered.get(start..).and_then(|s| s.find(&needle)) {
            let abs = start + pos;
            if rule.bare {
                hits.push(rule.id);
                break;
            }
            // tail = run of non-space, non-quote, non-comma chars after prefix
            let Some(rest) = line.get(abs + rule.prefix.len()..) else {
                break;
            };
            let tail: String = rest
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'' && *c != ',' && *c != ';')
                .collect();
            if tail_ok(rule.tail, &tail, rule.min_tail) {
                hits.push(rule.id);
                break;
            }
            start = abs + needle.len();
        }
    }
    // Generic entropy tripwire on long `=`/`:` assigned values.
    // Threshold 3.5 catches hex (max 4.0) and base64 tokens; URL-looking
    // values (slashes / scheme) are skipped to avoid flagging links.
    for sep in ['=', ':'] {
        for chunk in line.split(sep).skip(1) {
            let tok: String = chunk
                .trim_start_matches([' ', '"', '\u{27}'])
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'' && *c != ',' && *c != ';')
                .collect();
            if tok.contains("://") || tok.starts_with('/') {
                continue;
            }
            if tok.len() >= 24 && entropy_per_char(&tok) >= 3.5 {
                hits.push("high-entropy-token");
                break;
            }
        }
    }
    hits
}

/// Scan text content. Returns findings (secret values never included).
pub fn scan_text(file_label: &str, text: &str) -> Vec<Finding> {
    // Binary guard: NUL byte ⇒ skip silently.
    if text.contains('\0') {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for rule in scan_line(line) {
            out.push(Finding {
                file: file_label.to_string(),
                line: i + 1,
                rule,
            });
        }
    }
    out
}

const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".idea", ".vscode"];
const SKIP_EXTS: &[&str] = &["png", "jpg", "jpeg", "gif", "ico", "exe", "dll", "zip", "enc", "dpapi", "log"];

fn should_skip(path: &Path) -> bool {
    if path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| SKIP_DIRS.contains(&s))
    }) {
        return true;
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if SKIP_EXTS.contains(&ext.to_lowercase().as_str()) {
            return true;
        }
    }
    false
}

/// Recursively scan a directory (working tree). Caps file size at 2MB.
pub fn scan_dir(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if should_skip(&path) {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                if let Ok(meta) = std::fs::metadata(&path) {
                    if meta.len() > 2 * 1024 * 1024 {
                        continue;
                    }
                }
                if let Ok(text) = std::fs::read_to_string(&path) {
                    out.extend(scan_text(&path.to_string_lossy(), &text));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_openai_key() {
        let f = scan_text("a.py", "KEY = \"sk-abcdefghij1234567890XYZ+/_-=\"");
        assert!(f.iter().any(|x| x.rule == "openai"));
    }

    #[test]
    fn catches_aws_key() {
        let f = scan_text("b.tf", "aws = \"AKIAIOSFODNN7EXAMPLE\"");
        assert!(f.iter().any(|x| x.rule == "aws-access"));
    }

    #[test]
    fn catches_private_key_header() {
        let f = scan_text("k.pem", "-----BEGIN RSA PRIVATE KEY-----");
        assert!(f.iter().any(|x| x.rule == "private-key"));
    }

    #[test]
    fn catches_entropy_token() {
        let f = scan_text("c.env", "TOKEN=9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c");
        assert!(!f.is_empty());
    }

    #[test]
    fn clean_code_is_quiet() {
        let f = scan_text(
            "ok.rs",
            "fn main() {\n    println!(\"hello world\");\n}\n",
        );
        assert!(f.is_empty());
    }

    #[test]
    fn binary_is_skipped() {
        let f = scan_text("a.bin", "ab\0cd ghp_fakesecretvalue1234567890");
        assert!(f.is_empty());
    }

    #[test]
    fn no_secret_values_in_findings() {
        let secret = "sk-abcdefghij1234567890XYZ";
        let f = scan_text("a.py", &format!("k={secret}"));
        assert!(!f.is_empty());
        let dump = format!("{:?}", f.iter().map(|x| (&x.file, x.line, x.rule)).collect::<Vec<_>>());
        assert!(!dump.contains(secret));
    }

    #[test]
    fn unicode_lines_never_panic_and_still_scan() {
        // Multi-byte chars around a prefix used to break byte-offset slicing
        // (`to_lowercase()` can change a string's byte length).
        let f = scan_text("u.py", "মন্তব্য sk-abcdefghij1234567890XYZ+/_-=");
        assert!(f.iter().any(|x| x.rule == "openai"));
        let f2 = scan_text("ü.txt", "İİİ password=hunter2");
        assert!(f2.iter().any(|x| x.rule == "generic-password-assign"));
    }
}
