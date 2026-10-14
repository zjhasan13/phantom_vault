//! Phase 7 (limited): direct browser-profile discovery.
//!
//! HONEST SCOPE: this build cannot safely decrypt live browser credential
//! stores — Chromium `Login Data` needs a locked-profile copy + SQLite +
//! AES-GCM (new deps, AV-heuristic risk), and Firefox `logins.json` needs
//! the NSS `key4.db` key. So this module does READ-ONLY profile discovery
//! (path-existence checks only — credential files are never opened, read,
//! or decrypted) and returns per-browser guidance pointing at the existing
//! file-import pipeline (`parse_import_file` + dry-run preview + Confirm).
//! No writes, no process spawn, no network. Base-dir override via
//! `PV_BROWSER_BASE` keeps tests hermetic.

/// One detected browser profile slot.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedBrowser {
    pub name: String,
    pub profile_path: String,
    /// Always false in this phase: direct store decrypt is NOT attempted.
    pub direct_supported: bool,
    pub guidance: String,
}

/// Search roots: test override wins; otherwise the two real Windows roots.
/// (Opera lives under Roaming, the rest under Local.)
fn bases() -> Vec<std::path::PathBuf> {
    if let Ok(o) = std::env::var("PV_BROWSER_BASE") {
        if !o.trim().is_empty() {
            return vec![std::path::PathBuf::from(o)];
        }
    }
    let mut out = Vec::new();
    if let Ok(l) = std::env::var("LOCALAPPDATA") {
        if !l.trim().is_empty() {
            out.push(std::path::PathBuf::from(l));
        }
    }
    if let Ok(a) = std::env::var("APPDATA") {
        if !a.trim().is_empty() {
            out.push(std::path::PathBuf::from(a));
        }
    }
    out
}

const CHROMIUM_GUIDANCE: &str = "Settings → Passwords → Export (.csv), then Browse & Import ANY File. Encrypted exports are refused with guidance.";
const FIREFOX_GUIDANCE: &str = "Settings → Privacy → Passwords → Export (.csv), then Browse & Import. Primary-password-locked stores are refused loud.";

/// (display name, path relative to a base root, is it a dir probe?)
fn candidates() -> Vec<(&'static str, &'static str, bool, &'static str)> {
    vec![
        ("Chrome", "Google\\Chrome\\User Data\\Default\\Login Data", false, CHROMIUM_GUIDANCE),
        ("Brave", "BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data", false, CHROMIUM_GUIDANCE),
        ("Edge", "Microsoft\\Edge\\User Data\\Default\\Login Data", false, CHROMIUM_GUIDANCE),
        ("Opera", "Opera Software\\Opera Stable\\Login Data", false, CHROMIUM_GUIDANCE),
        ("Firefox", "Mozilla\\Firefox\\Profiles", true, FIREFOX_GUIDANCE),
    ]
}

/// Read-only discovery: which known browser profiles exist on this machine.
pub fn detect() -> Vec<DetectedBrowser> {
    let mut out = Vec::new();
    for base in bases() {
        for (name, rel, _is_dir, guidance) in candidates() {
            // Join with '/' separators — PathBuf handles both on Windows.
            let rel_norm = rel.replace('\\', "/");
            let p = base.join(rel_norm);
            if p.exists() && !out.iter().any(|d: &DetectedBrowser| d.name == *name) {
                out.push(DetectedBrowser {
                    name: name.to_string(),
                    profile_path: p.to_string_lossy().into_owned(),
                    direct_supported: false,
                    guidance: guidance.to_string(),
                });
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// One-block UI text for the Importer view (no secrets — paths only).
pub fn summarize(list: &[DetectedBrowser]) -> String {
    if list.is_empty() {
        return "No browser profiles found under the usual Windows locations. Export a CSV from your browser, then use Browse & Import ANY File.".to_string();
    }
    let mut s = format!("Found {} browser profile(s) — direct decrypt OFF this build; export CSV, then import:", list.len());
    for d in list {
        s.push_str(&format!("\n• {} — {}\n  ↳ {}", d.name, d.profile_path, d.guidance));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // All three tests below mutate the process-global PV_BROWSER_BASE, so
    // they must never run concurrently (parallel harness races set/remove).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fixture_base(tag: &str) -> std::path::PathBuf {
        let mut b = std::env::temp_dir();
        b.push(format!("pv_browser_direct_{tag}"));
        let _ = std::fs::remove_dir_all(&b);
        std::fs::create_dir_all(&b).unwrap();
        b
    }

    #[test]
    fn empty_base_finds_nothing() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let b = fixture_base("empty");
        std::env::set_var("PV_BROWSER_BASE", &b);
        let found = detect();
        std::env::remove_var("PV_BROWSER_BASE");
        assert!(found.is_empty());
        assert!(summarize(&found).contains("No browser profiles found"));
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn detects_chromium_file_and_firefox_dir() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let b = fixture_base("mixed");
        let chrome = b.join("Google/Chrome/User Data/Default");
        std::fs::create_dir_all(&chrome).unwrap();
        std::fs::write(chrome.join("Login Data"), b"fake").unwrap();
        let ff = b.join("Mozilla/Firefox/Profiles");
        std::fs::create_dir_all(&ff).unwrap();
        std::env::set_var("PV_BROWSER_BASE", &b);
        let found = detect();
        std::env::remove_var("PV_BROWSER_BASE");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "Chrome");
        assert_eq!(found[1].name, "Firefox");
        // Phase scope: discovery only, never direct decrypt.
        assert!(found.iter().all(|d| !d.direct_supported));
        assert!(!found[0].guidance.is_empty());
        let text = summarize(&found);
        assert!(text.contains("Found 2 browser profile(s)"));
        assert!(text.contains("direct decrypt OFF"));
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn no_duplicate_when_both_roots_overlap() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let b = fixture_base("dup");
        let edge = b.join("Microsoft/Edge/User Data/Default");
        std::fs::create_dir_all(&edge).unwrap();
        std::fs::write(edge.join("Login Data"), b"fake").unwrap();
        std::env::set_var("PV_BROWSER_BASE", &b);
        // Same base twice must not duplicate (dedupe by browser name).
        let found = detect();
        std::env::remove_var("PV_BROWSER_BASE");
        assert_eq!(found.iter().filter(|d| d.name == "Edge").count(), 1);
        let _ = std::fs::remove_dir_all(&b);
    }
}
