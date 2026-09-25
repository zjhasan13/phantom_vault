//! Tamper-evident access log (rules Cat 8).
//!
//! Append-only JSONL beside the vault: every security-relevant event
//! (unlock, lock, copy, export, sync, audit) lands here with a SHA-256
//! chain hash over `prev_hash + timestamp + event + detail`. Metadata only
//! — passwords, secrets, and tokens NEVER enter the log. `verify()` replays
//! the chain; a single edited line breaks every later hash, exposing
//! coercion-time tampering or sneak-access cover-ups.

use std::path::Path;

const LOG_FILE: &str = "access.log";

fn sha256_hex(input: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(input);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Append one event. Best effort — logging must never break the action.
pub fn log_event(event: &str, detail: &str) {
    log_event_at(Path::new(LOG_FILE), event, detail);
}

fn last_hash(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| {
            text.lines().rev().find_map(|line| {
                line.split("\"hash\":\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    .map(str::to_string)
            })
        })
        .unwrap_or_else(|| "GENESIS".to_string())
}

fn log_event_at(path: &Path, event: &str, detail: &str) {
    let clean = |s: &str| {
        s.replace('\\', "")
            .replace('"', "")
            .replace(['\r', '\n'], " ")
            .chars()
            .take(160)
            .collect::<String>()
    };
    let prev = last_hash(path);
    let t = now_unix();
    let (event, detail) = (clean(event), clean(detail));
    let hash = sha256_hex(format!("{prev}{t}{event}{detail}").as_bytes());
    let line = format!(
        "{{\"t\":{t},\"event\":\"{event}\",\"detail\":\"{detail}\",\"prev\":\"{prev}\",\"hash\":\"{hash}\"}}\n"
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        let _ = f.write_all(line.as_bytes());
    }
}

/// Verify the whole chain. Returns (entries, valid).
pub fn verify_at(path: &Path) -> (usize, bool) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return (0, true), // no log yet = vacuously valid
    };
    let field = |line: &str, key: &str| {
        line.split(&format!("\"{key}\":"))
            .nth(1)
            .and_then(|rest| {
                let rest = rest.trim_start();
                if rest.starts_with('"') {
                    rest[1..].split('"').next().map(str::to_string)
                } else {
                    rest.split([',', '}']).next().map(str::to_string)
                }
            })
    };
    let mut prev = "GENESIS".to_string();
    let mut count = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (Some(t), Some(event), Some(detail), Some(p), Some(hash)) = (
            field(line, "t"),
            field(line, "event"),
            field(line, "detail"),
            field(line, "prev"),
            field(line, "hash"),
        ) else {
            return (count, false);
        };
        if p != prev {
            return (count, false);
        }
        if sha256_hex(format!("{p}{t}{event}{detail}").as_bytes()) != hash {
            return (count, false);
        }
        prev = hash;
        count += 1;
    }
    (count, true)
}

/// Verify the default log.
pub fn verify() -> (usize, bool) {
    verify_at(Path::new(LOG_FILE))
}

/// Newest-first human-readable tail for the Settings viewer.
pub fn recent(n: usize) -> Vec<String> {
    recent_at(Path::new(LOG_FILE), n)
}

fn recent_at(path: &Path, n: usize) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let field = |line: &str, key: &str| {
        line.split(&format!("\"{key}\":"))
            .nth(1)
            .and_then(|rest| {
                let rest = rest.trim_start();
                if rest.starts_with('"') {
                    rest[1..].split('"').next().map(str::to_string)
                } else {
                    rest.split([',', '}']).next().map(str::to_string)
                }
            })
            .unwrap_or_default()
    };
    text.lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(n.max(1))
        .map(|line| format!("{} · {} {}", field(line, "t"), field(line, "event"), field(line, "detail")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("pv-access-{name}-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn chain_verifies_and_tamper_breaks() {
        let p = tmp("ok");
        log_event_at(&p, "unlock", "ok");
        log_event_at(&p, "copy", "login");
        let (n, valid) = verify_at(&p);
        assert_eq!(n, 2);
        assert!(valid);
        // Tamper with one line → chain breaks from there.
        let text = std::fs::read_to_string(&p).unwrap().replacen("unlock", "hacked", 1);
        std::fs::write(&p, text).unwrap();
        let (_, valid) = verify_at(&p);
        assert!(!valid);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn secrets_never_touch_the_log() {
        let p = tmp("clean");
        log_event_at(&p, "copy", "user typed \"quoted\" pass\nword\\x");
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("\"quoted"), "quotes must be stripped");
        assert!(!text.contains("\nword"), "newlines must not leak structure");
        assert_eq!(text.lines().count(), 1, "one event = exactly one line");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn recent_is_newest_first() {
        let p = tmp("recent");
        log_event_at(&p, "a", "1");
        log_event_at(&p, "b", "2");
        let rows = recent_at(&p, 5);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].contains('b'));
        let _ = std::fs::remove_file(&p);
    }
}
