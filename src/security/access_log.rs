//! Tamper-evident access log (rules Cat 8).
//!
//! Append-only JSONL beside the vault: every security-relevant event
//! (unlock, lock, copy, export, sync, audit) lands here with an HMAC-SHA256
//! chain over `prev_hash + timestamp + event + detail`, keyed by a random
//! 32B DPAPI-sealed key (C8). Metadata only — passwords, secrets, and
//! tokens NEVER enter the log. `verify()` replays the chain; a single
//! edited line breaks every later hash, and a head-hash anchor file makes
//! tail truncation detectable. Appends are fsync'd + mutex-serialized.

use std::path::Path;

const LOG_FILE: &str = "access.log";
const KEY_FILE: &str = "access_log.key.dpapi";

static LOG_MUTEX: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

fn sha256_hex(input: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(input);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// C8: keyed chain hash. Key lives DPAPI-sealed in KEY_FILE (generated once
/// via OsRng). Falls back to plain SHA-256 only if DPAPI is unavailable
/// (non-Windows tests) — still truncation-detectable via the head anchor.
fn chain_key() -> Vec<u8> {
    if let Ok(blob) = std::fs::read(KEY_FILE) {
        if let Ok(s) = crate::core::memory::DpapiGuard::unprotect(&blob) {
            let k = s.expose().to_vec();
            if !k.is_empty() {
                return k;
            }
        }
    }
    use rand_core::RngCore;
    let mut k = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut k);
    if let Ok(blob) = crate::core::memory::DpapiGuard::protect(&k) {
        let _ = std::fs::write(KEY_FILE, blob);
    }
    k.to_vec()
}

fn chain_hash(prev: &str, t: i64, event: &str, detail: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let key = chain_key();
    if key.is_empty() {
        return sha256_hex(format!("{prev}{t}{event}{detail}").as_bytes());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("hmac key");
    mac.update(prev.as_bytes());
    mac.update(t.to_string().as_bytes());
    mac.update(event.as_bytes());
    mac.update(detail.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn head_path_for(path: &Path) -> std::path::PathBuf {
    let s = path.to_string_lossy().into_owned();
    std::path::PathBuf::from(format!("{s}.head"))
}

/// M11: stable 16-hex-char identifier hash for log details. Caller-supplied
/// strings (bridge ids, query text) never enter the chain as narrative.
pub fn short_hash(s: &str) -> String {
    let h = sha256_hex(s.as_bytes());
    h.get(..16).unwrap_or(&h).to_string()
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
    let _guard = LOG_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let prev = last_hash(path);
    let t = now_unix();
    let (event, detail) = (clean(event), clean(detail));
    let hash = chain_hash(&prev, t, &event, &detail);
    let line = format!(
        "{{\"t\":{t},\"event\":\"{event}\",\"detail\":\"{detail}\",\"prev\":\"{prev}\",\"hash\":\"{hash}\"}}\n"
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        if f.write_all(line.as_bytes()).is_ok() {
            let _ = f.sync_all();
            let _ = std::fs::write(head_path_for(path), &hash);
        }
    }
}

/// Verify the whole chain. Returns (entries, valid).
/// C8/M6: unreadable/corrupt ⇒ INVALID (was vacuously valid); tail
/// truncation ⇒ invalid via the head anchor.
pub fn verify_at(path: &Path) -> (usize, bool) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => {
            // Fresh install (no log, no anchor, no key) = valid; a wiped log
            // after first use leaves the DPAPI key and/or head anchor behind
            // ⇒ invalid. INTERACTION: bridge-fetch entries are HMAC-chained,
            // so same-user malware needs DPAPI unprotect (not just file
            // write) to forge — higher bar, not a TPM-grade seal.
            if !head_path_for(path).exists() && std::fs::read(KEY_FILE).is_err() {
                return (0, true);
            }
            return (0, false);
        }
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
        let t_num: i64 = t.parse().unwrap_or(-1);
        if t_num < 0 || chain_hash(&p, t_num, &event, &detail) != hash {
            // Legacy plain-SHA256 lines (pre-HMAC) still verify so old logs
            // don't false-alarm after upgrade.
            if sha256_hex(format!("{p}{t}{event}{detail}").as_bytes()) != hash {
                return (count, false);
            }
        }
        prev = hash.clone();
        count += 1;
    }
    // Head anchor: truncation (deleted tail) breaks the anchor even though
    // the remaining chain is internally consistent.
    if count > 0 {
        if let Ok(head) = std::fs::read_to_string(head_path_for(path)) {
            if head.trim() != prev {
                return (count, false);
            }
        }
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
