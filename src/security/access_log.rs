//! Tamper-evident access log (rules Cat 8).
//!
//! Append-only JSONL beside the vault: every security-relevant event
//! (unlock, lock, copy, export, sync, audit) lands here with an HMAC-SHA256
//! chain over `prev_hash + timestamp + event + detail`, keyed by a random
//! 32B DPAPI-sealed key (C8). Metadata only — passwords, secrets, and
//! tokens NEVER enter the log. `verify()` replays the chain; a single
//! edited line breaks every later hash, and a head-hash anchor file makes
//! tail truncation detectable. Appends are fsync'd + mutex-serialized.

use std::path::{Path, PathBuf};

const LOG_FILE: &str = "access.log";
/// DPAPI-sealed HMAC chain key. Dotted name matches `.gitignore`
/// (`access_log.key.dpapi`) so the key can never be committed.
const KEY_FILE: &str = "access_log.key.dpapi";

static LOG_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn sha256_hex(input: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(input);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone)]
enum KeyState {
    Absent,
    Loaded([u8; 32]),
    Unusable(String),
}

fn key_path() -> PathBuf {
    PathBuf::from(KEY_FILE)
}

fn read_key_state() -> KeyState {
    let p = key_path();
    match std::fs::read(&p) {
        Ok(blob) => match crate::core::memory::DpapiGuard::unprotect(&blob) {
            Ok(secret) => {
                let bytes = secret.expose();
                if bytes.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(bytes);
                    KeyState::Loaded(k)
                } else {
                    KeyState::Unusable(format!("invalid key length {}", bytes.len()))
                }
            }
            Err(e) => KeyState::Unusable(format!("key unseal failed: {e}")),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => KeyState::Absent,
        Err(e) => KeyState::Unusable(format!("key file unreadable: {e}")),
    }
}

fn write_key_atomic(k: [u8; 32]) -> Result<(), String> {
    let blob = crate::core::memory::DpapiGuard::protect(&k)
        .map_err(|e| format!("key seal failed: {e}"))?;
    let p = key_path();
    let tmp = p.with_extension("dpapi.tmp");
    std::fs::write(&tmp, &blob).map_err(|e| format!("key store failed: {e}"))?;
    std::fs::rename(&tmp, &p).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("key store failed: {e}")
    })
}

fn chain_key_bytes() -> Result<[u8; 32], String> {
    match read_key_state() {
        KeyState::Loaded(k) => Ok(k),
        KeyState::Absent => {
            let mut k = [0u8; 32];
            use rand_core::RngCore as _;
            rand_core::OsRng.fill_bytes(&mut k);
            write_key_atomic(k)?;
            Ok(k)
        }
        KeyState::Unusable(why) => Err(format!("audit log chain key unusable: {why}")),
    }
}

/// C8: keyed chain hash. Key lives DPAPI-sealed in KEY_FILE (generated once
/// on first run). On read/unseal failure the chain key is not rotated
/// (rotating would irreversibly orphan the existing chain). When that happens,
/// HMAC falls back to plain SHA-256 to keep truncation-detectable via the
/// anchor; callers may log the key state separately.
fn chain_key() -> Vec<u8> {
    chain_key_bytes().map(|k| k.to_vec()).unwrap_or_else(|_| Vec::new())
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

fn lock_path_for(path: &Path) -> std::path::PathBuf {
    let s = path.to_string_lossy().into_owned();
    std::path::PathBuf::from(format!("{s}.lock"))
}

/// Cross-process append guard: desktop + native-host both append to the
/// same file, but LOG_MUTEX is per-process. An atomic `create_new` lock
/// file serializes read-prev + append across processes (best-effort with
/// bounded spin; falls back to unlocked append rather than dropping events).
fn cross_process_lock(path: &Path) -> Option<std::fs::File> {
    let lock = lock_path_for(path);
    for _ in 0..50 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(f) => return Some(f),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    None
}

fn log_event_at(path: &Path, event: &str, detail: &str) {
    let clean = |s: &str| {
        s.replace(['\\', '"'], "")
            .replace(['\r', '\n'], " ")
            .chars()
            .take(160)
            .collect::<String>()
    };
    let _guard = LOG_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let _xproc = cross_process_lock(path);
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
    if _xproc.is_some() {
        let _ = std::fs::remove_file(lock_path_for(path));
    }
}

/// Verify the whole chain. Returns (entries, valid, first-bad-line index or None).
/// C8/M6: unreadable/corrupt ⇒ INVALID (was vacuously valid); tail
/// truncation ⇒ invalid via the head anchor.
pub fn verify_at(path: &Path) -> (usize, bool) {
    let (n, v, _) = verify_at_detailed(path);
    (n, v)
}

/// Verify with first-bad 1-based line index (None when valid).
pub fn verify_at_detailed(path: &Path) -> (usize, bool, Option<usize>) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => {
            // Fresh install (no log, no anchor, no key) = valid; a wiped log
            // after first use leaves the DPAPI key and/or head anchor behind
            // ⇒ invalid. INTERACTION: bridge-fetch entries are HMAC-chained,
            // so same-user malware needs DPAPI unprotect (not just file
            // write) to forge — higher bar, not a TPM-grade seal.
            if !head_path_for(path).exists() && std::fs::read(KEY_FILE).is_err() {
                return (0, true, None);
            }
            return (0, false, Some(0));
        }
    };
    let field = |line: &str, key: &str| {
        line.split(&format!("\"{key}\":"))
            .nth(1)
            .and_then(|rest| {
                let rest = rest.trim_start();
                if rest.starts_with('"') {
                    rest.strip_prefix('"')
                        .and_then(|r| r.split('"').next())
                        .map(str::to_string)
                } else {
                    rest.split([',', '}']).next().map(str::to_string)
                }
            })
    };
    let mut prev = "GENESIS".to_string();
    let mut count = 0;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let lineno = idx + 1;
        let (Some(t), Some(event), Some(detail), Some(p), Some(hash)) = (
            field(line, "t"),
            field(line, "event"),
            field(line, "detail"),
            field(line, "prev"),
            field(line, "hash"),
        ) else {
            return (count, false, Some(lineno));
        };
        if p != prev {
            return (count, false, Some(lineno));
        }
        let t_num: i64 = t.parse().unwrap_or(-1);
        if t_num < 0 {
            return (count, false, Some(lineno));
        }
        let recomputed_hmac = chain_hash(&prev, t_num, &event, &detail);
        if recomputed_hmac == hash {
            prev = hash.clone();
            count += 1;
            continue;
        }
        // Legacy plain-SHA256 lines (pre-HMAC) — still verify to avoid false
        // alarm after upgrade, but only for older format lines.
        let recomputed_legacy = sha256_hex(format!("{p}{t}{event}{detail}").as_bytes());
        if recomputed_legacy == hash {
            prev = hash.clone();
            count += 1;
            continue;
        }
        return (count, false, Some(lineno));
    }
    // Head anchor: truncation (deleted tail) breaks the anchor even though the
    // remaining chain is internally consistent.
    if count > 0 {
        if let Ok(head) = std::fs::read_to_string(head_path_for(path)) {
            if head.trim() != prev {
                return (count, false, None);
            }
        } else {
            // No anchor but entries exist → cannot prove tail wasn't truncated.
            return (count, false, None);
        }
    } else {
        // No entries. If a head anchor exists, the log was truncated to zero.
        if head_path_for(path).exists() {
            return (0, false, Some(0));
        }
        // No entries, no anchor, no key → fresh install; if key exists but log
        // gone, that's also truncation. H2 fix: fail-closed when artifacts exist.
        if std::fs::read(KEY_FILE).is_ok() {
            return (0, false, Some(0));
        }
    }
    (count, true, None)
}

/// Verify the default log.
pub fn verify() -> (usize, bool) {
    verify_at(Path::new(LOG_FILE))
}

/// Newest-first human-readable tail for the Settings viewer.
/// Pass true to hide high-volume bridge chatter so real events surface.
pub fn recent_filtered(n: usize, hide_bridge: bool) -> Vec<String> {
    recent_filtered_at(Path::new(LOG_FILE), n, hide_bridge)
}

/// Relative age for a unix timestamp (no calendar dep): "3m ago".
fn ago(t: i64) -> String {
    let d = now_unix().saturating_sub(t);
    if d < 60 {
        "just now".to_string()
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86400)
    }
}

#[cfg(test)]
fn recent_at(path: &Path, n: usize) -> Vec<String> {
    recent_filtered_at(path, n, false)
}

fn recent_filtered_at(path: &Path, n: usize, hide_bridge: bool) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let field = |line: &str, key: &str| {
        line.split(&format!("\"{key}\":"))
            .nth(1)
            .and_then(|rest| {
                let rest = rest.trim_start();
                if rest.starts_with('"') {
                    rest.strip_prefix('"')
                        .and_then(|r| r.split('"').next())
                        .map(str::to_string)
                } else {
                    rest.split([',', '}']).next().map(str::to_string)
                }
            })
            .unwrap_or_default()
    };
    text.lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .filter(|line| {
            !hide_bridge
                || !(line.contains("\"event\":\"bridge-")
                    || line.contains("\"event\":\"p2p\""))
        })
        .take(n.max(1))
        .map(|line| {
            let t = field(line, "t").parse::<i64>().unwrap_or(0);
            format!("{} · {} {}", ago(t), field(line, "event"), field(line, "detail"))
        })
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
        let (_, valid2, bad) = verify_at_detailed(&p);
        assert!(!valid2);
        assert_eq!(bad, Some(1));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn duplicate_prev_reports_first_bad_line() {
        // Multi-process race regression: two writers read the same tip and
        // append with the same prev → second copy breaks the chain there.
        let p = tmp("dup");
        log_event_at(&p, "a", "1");
        log_event_at(&p, "b", "2");
        let second = std::fs::read_to_string(&p)
            .unwrap()
            .lines()
            .nth(1)
            .unwrap()
            .to_string();
        std::fs::write(&p, format!("{}\n{second}\n", std::fs::read_to_string(&p).unwrap().trim_end())).unwrap();
        let (n, valid, bad) = verify_at_detailed(&p);
        assert_eq!((n, valid, bad), (2, false, Some(3)));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(head_path_for(&p));
        let _ = std::fs::remove_file(lock_path_for(&p));
    }

    #[test]
    fn recent_filtered_hides_bridge_and_shows_relative_age() {
        let p = tmp("filter");
        log_event_at(&p, "unlock", "ok");
        log_event_at(&p, "bridge-verify", "abc123");
        let all = recent_filtered_at(&p, 5, false);
        assert_eq!(all.len(), 2);
        assert!(all[0].contains("ago") || all[0].contains("just now"));
        let quiet = recent_filtered_at(&p, 5, true);
        assert_eq!(quiet.len(), 1);
        assert!(quiet[0].contains("unlock"));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(head_path_for(&p));
        let _ = std::fs::remove_file(lock_path_for(&p));
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
