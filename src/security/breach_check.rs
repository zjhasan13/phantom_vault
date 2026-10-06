//! Phase 25 — HaveIBeenPwned k-anonymity breach + health audit.
//!
//! Privacy: only the first 5 SHA-1 hex chars ever leave the device (the
#![allow(dead_code)]
//! official HIBP range protocol). Full hashes and passwords never touch the
//! network. Plaintext copies are zeroized immediately after hashing.

use crate::error::{Result, VaultError};
use crate::models::Credential;
use std::collections::{HashMap, HashSet};
use zeroize::Zeroize;

const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const MIN_HEALTHY_LEN: usize = 10;

/// SHA-1 hex (uppercase) split into k-anon prefix/suffix. Input scrubbed.
fn split_hash(password: &str) -> (String, String) {
    use sha1::Digest;
    let mut pw = password.to_string();
    let digest = sha1::Sha1::digest(pw.as_bytes());
    pw.zeroize();
    let hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();
    (hex[..5].to_string(), hex[5..].to_string())
}

/// HTTP client with EXPLICIT proxy routing (HTTPS_PROXY → HTTP_PROXY →
/// ALL_PROXY, Tor-friendly). reqwest defaults already auto-route, but pinning
/// it here keeps the privacy contract visible, tested, and immune to
/// default changes. `Proxy::all` still honors NO_PROXY from the environment.
fn hibp_client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15));
    if let Some(proxy_url) = crate::sync::github_sync::effective_proxy() {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| VaultError::Sync(format!("invalid proxy URL: {e}")))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| VaultError::Sync(format!("HTTP client init failed: {e}")))
}

/// Query one password. Ok(Some(n)) = seen n times, Ok(None) = clean.
pub async fn check_password(password: &str) -> Result<Option<u64>> {
    if password.is_empty() {
        return Ok(None);
    }
    let (prefix, suffix) = split_hash(password);
    let url = format!("{RANGE_URL}{prefix}");
    let body = hibp_client()?
        .get(&url)
        .send()
        .await
        .map_err(|e| VaultError::Sync(format!("breach API unreachable: {e}")))?
        .text()
        .await
        .map_err(|e| VaultError::Sync(format!("breach API read failed: {e}")))?;
    for line in body.lines() {
        let mut parts = line.splitn(2, ':');
        if let (Some(s), Some(n)) = (parts.next(), parts.next()) {
            if s.trim().eq_ignore_ascii_case(suffix.trim()) {
                let count = n.trim().parse::<u64>().unwrap_or(1);
                return Ok(Some(count));
            }
        }
    }
    Ok(None)
}

fn entropy_per_char(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let b = s.as_bytes();
    if b.is_empty() {
        return 0.0;
    }
    for x in b {
        counts[*x as usize] += 1;
    }
    let n = b.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

pub fn is_weak(password: &str) -> bool {
    password.len() < MIN_HEALTHY_LEN || entropy_per_char(password) < 3.0
}

#[derive(Debug, Default, Clone)]
pub struct BreachResult {
    pub credential_id: String,
    pub title: String,
    pub breached: Option<u64>,
    pub reused: bool,
    pub weak: bool,
    pub stale: bool,
}

#[derive(Debug, Default)]
pub struct HealthReport {
    pub results: Vec<BreachResult>,
    pub audited: usize,
    pub breached: usize,
    pub reused: usize,
    pub weak: usize,
    pub stale: usize,
    /// M15: passwords whose breach check ERRORED (network/timeout) — NOT
    /// clean. Without this bucket a failed check reads as "not breached".
    pub indeterminate: usize,
    /// Distinct non-empty passwords shared by 2+ accounts.
    pub reused_groups: usize,
    /// Audited logins carrying an embedded TOTP secret.
    pub with_totp: usize,
}

impl HealthReport {
    /// 2FA coverage % over audited logins.
    pub fn coverage_pct(&self) -> u32 {
        if self.audited == 0 {
            return 0;
        }
        ((self.with_totp as u64 * 100) / self.audited as u64).min(100) as u32
    }

    /// 0–100 score: −25/breached, −10/reused group, −5/weak, −2/stale,
    /// +10 bonus when 2FA coverage exceeds 50%. Clamped, pure.
    pub fn score(&self) -> i64 {
        let mut s: i64 = 100
            - (self.breached as i64) * 25
            - (self.reused_groups as i64) * 10
            - (self.weak as i64) * 5
            - (self.stale as i64) * 2;
        if self.coverage_pct() > 50 {
            s += 10;
        }
        s.clamp(0, 100)
    }

    /// Dashboard headline for the current score.
    pub fn health_line(&self) -> String {
        let s = self.score();
        if s >= 90 {
            "Good Security Health".to_string()
        } else if self.breached > 0 {
            format!(
                "Action Required: {} Breached Password{} Found!",
                self.breached,
                if self.breached == 1 { "" } else { "s" }
            )
        } else if s >= 70 {
            "Fair — rotate reused and weak passwords".to_string()
        } else {
            "Action Required: rotate weak, reused and stale passwords!".to_string()
        }
    }
    pub fn headline(&self) -> String {
        format!(
            "🛡️ Audited {} passwords — 🚨 {} breached, ⚠️ {} reused, ⚠️ {} weak, 🕰️ {} stale",
            self.audited, self.breached, self.reused, self.weak, self.stale
        )
    }

    /// Row badge per credential id (breach > reuse > weak > stale).
    pub fn badges(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for r in &self.results {
            let badge = if let Some(n) = r.breached {
                format!("🚨 Leaked in {} breaches! Change now", fmt_count(n))
            } else if r.reused {
                "⚠️ Reused password".to_string()
            } else if r.weak {
                "⚠️ Weak password".to_string()
            } else if r.stale {
                "🕰️ Over 6 months old".to_string()
            } else {
                continue;
            };
            map.insert(r.credential_id.clone(), badge);
        }
        map
    }

    /// Metric category per credential id, same priority as badges.
    /// Drives click-to-filter on the dashboard ("", breached/reused/weak/stale).
    pub fn kinds(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for r in &self.results {
            let kind = if r.breached.is_some() {
                "breached"
            } else if r.reused {
                "reused"
            } else if r.weak {
                "weak"
            } else if r.stale {
                "stale"
            } else {
                continue;
            };
            map.insert(r.credential_id.clone(), kind.to_string());
        }
        map
    }
}

fn fmt_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Batch scan: dedups identical passwords (one API call each), flags reuse
/// (2+ accounts sharing a password) and weakness locally (no network).
/// Network failures are counted per-password as `indeterminate` (unknown,
/// never clean) without aborting the batch.
pub async fn scan_vault_health(credentials: &[Credential]) -> HealthReport {
    // Frequency map for reuse detection (no network needed).
    let mut freq: HashMap<String, usize> = HashMap::new();
    for c in credentials {
        *freq.entry(c.password.clone()).or_insert(0) += 1;
    }
    // Unique non-empty passwords → one range query each, concurrently.
    let mut unique: Vec<String> = HashSet::<String>::from_iter(
        credentials.iter().map(|c| c.password.clone()).filter(|p| !p.is_empty()),
    )
    .into_iter()
    .collect();
    unique.sort();
    let mut set = tokio::task::JoinSet::new();
    for pw in unique {
        set.spawn(async move {
            // Borrow-then-move: the check borrows the captured password;
            // only afterwards does the tuple take ownership for the return.
            let r = check_password(&pw).await;
            (pw, r)
        });
    }
    let mut breached: HashMap<String, Option<u64>> = HashMap::new();
    let mut failed: HashSet<String> = HashSet::new();
    while let Some(done) = set.join_next().await {
        match done {
            Ok((pw, Ok(r))) => {
                breached.insert(pw, r);
            }
            // Check error (not "clean"): counted as indeterminate below.
            // JoinError carries no password — uncountable, logged by caller.
            Ok((pw, Err(_))) => {
                failed.insert(pw);
            }
            Err(_) => {}
        }
    }
    let mut report = HealthReport::default();
    let mut seen_ids = HashSet::new();
    for c in credentials {
        if !seen_ids.insert(c.id.clone()) {
            continue;
        }
        let b = breached.get(&c.password).copied().flatten();
        let reused = freq.get(&c.password).copied().unwrap_or(0) > 1;
        let weak = is_weak(&c.password);
        let stale = crate::models::is_stale(c.last_changed, crate::models::current_timestamp());
        if b.is_some() {
            report.breached += 1;
        } else if failed.contains(&c.password) {
            // Checked but errored: unknown, never "clean".
            report.indeterminate += 1;
        }
        if reused {
            report.reused += 1;
        }
        if weak {
            report.weak += 1;
        }
        if stale {
            report.stale += 1;
        }
        if !c.totp_secret.trim().is_empty() {
            report.with_totp += 1;
        }
        report.results.push(BreachResult {
            credential_id: c.id.clone(),
            title: c.title.clone(),
            breached: b,
            reused,
            weak,
            stale,
        });
    }
    report.audited = report.results.len();
    report.reused_groups = freq
        .iter()
        .filter(|(pw, n)| !pw.is_empty() && **n > 1)
        .count();
    report
}

/// Fully offline audit: reuse + weakness + staleness, zero network calls.
/// Breach verdicts stay `None` (unknown) — badges surface reuse/weak/stale.
/// Pure except for no I/O at all; safe for air-gapped machines.
pub fn scan_vault_health_offline(credentials: &[Credential]) -> HealthReport {
    let now = crate::models::current_timestamp();
    let mut freq: HashMap<String, usize> = HashMap::new();
    for c in credentials {
        *freq.entry(c.password.clone()).or_insert(0) += 1;
    }
    let mut report = HealthReport::default();
    let mut seen_ids = HashSet::new();
    for c in credentials {
        if !seen_ids.insert(c.id.clone()) {
            continue;
        }
        let reused = freq.get(&c.password).copied().unwrap_or(0) > 1;
        let weak = is_weak(&c.password);
        let stale = crate::models::is_stale(c.last_changed, now);
        if reused {
            report.reused += 1;
        }
        if weak {
            report.weak += 1;
        }
        if stale {
            report.stale += 1;
        }
        report.results.push(BreachResult {
            credential_id: c.id.clone(),
            title: c.title.clone(),
            breached: None,
            reused,
            weak,
            stale,
        });
        if !c.totp_secret.trim().is_empty() {
            report.with_totp += 1;
        }
    }
    report.audited = report.results.len();
    report.reused_groups = freq
        .iter()
        .filter(|(pw, n)| !pw.is_empty() && **n > 1)
        .count();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_hash_shape() {
        let (pre, suf) = split_hash("password");
        // SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(pre, "5BAA6");
        assert_eq!(suf.len(), 35);
        assert_eq!(&suf[..5], "1E4C9");
    }

    #[test]
    fn weak_rules() {
        assert!(is_weak("12345678"));
        assert!(is_weak("password"));
        assert!(!is_weak("9f#ZmQ2$vL8x!qW4z"));
    }

    #[test]
    fn score_math_and_headline() {
        let mut r = HealthReport::default();
        assert_eq!(r.score(), 100);
        assert_eq!(r.coverage_pct(), 0);
        assert_eq!(r.health_line(), "Good Security Health");
        r.audited = 4;
        r.breached = 1;
        r.reused_groups = 1;
        r.weak = 1;
        r.stale = 2;
        r.with_totp = 1; // 25% — no bonus
        assert_eq!(r.score(), 100 - 25 - 10 - 5 - 4);
        assert_eq!(r.coverage_pct(), 25);
        assert!(r.health_line().contains("1 Breached Password Found"));
        r.with_totp = 3; // 75% — +10 bonus
        assert_eq!(r.coverage_pct(), 75);
        assert_eq!(r.score(), 100 - 25 - 10 - 5 - 4 + 10);
        // Floor at zero, never negative.
        r.breached = 10;
        assert_eq!(r.score(), 0);
    }

    #[test]
    fn offline_audit_never_marks_breach() {
        use crate::models::{Credential, current_timestamp};
        let creds = vec![
            Credential {
                id: "a".into(),
                title: "A".into(),
                username: "u".into(),
                password: "password".into(),
                totp_secret: String::new(),
                urls: Vec::new(),
                backup_codes: Vec::new(),
                custom_fields: Vec::new(),
                notes: String::new(),
                folder: "General".into(),
                reprompt: false,
                attachments: Vec::new(),
                travel_safe: false,
                last_changed: 1, // ancient → stale
                password_history: Vec::new(),
                favorite: false,
                deleted_at: None,
            },
            Credential {
                id: "b".into(),
                title: "B".into(),
                username: "u".into(),
                password: "password".into(),
                totp_secret: String::new(),
                urls: Vec::new(),
                backup_codes: Vec::new(),
                custom_fields: Vec::new(),
                notes: String::new(),
                folder: "General".into(),
                reprompt: false,
                attachments: Vec::new(),
                travel_safe: false,
                last_changed: current_timestamp(),
                password_history: Vec::new(),
                favorite: false,
                deleted_at: None,
            },
        ];
        let r = scan_vault_health_offline(&creds);
        assert_eq!(r.audited, 2);
        assert_eq!(r.breached, 0);
        assert_eq!(r.reused, 2);
        assert_eq!(r.weak, 2);
        assert_eq!(r.stale, 1);
        assert!(r.results.iter().all(|x| x.breached.is_none()));
        assert!(r.headline().contains("stale"));
    }

    #[test]
    fn badges_prefer_breach() {
        let r = HealthReport {
            results: vec![BreachResult {
                credential_id: "a".into(),
                title: "X".into(),
                breached: Some(3_200_000),
                reused: true,
                weak: true,
                stale: true,
            }],
            audited: 1,
            breached: 1,
            reused: 1,
            weak: 1,
            stale: 1,
            indeterminate: 0,
            reused_groups: 1,
            with_totp: 0,
        };
        let b = r.badges();
        assert_eq!(b["a"], "🚨 Leaked in 3.2M breaches! Change now");
        assert!(r.headline().contains('1'));
    }

    #[test]
    fn stale_only_gets_time_badge() {
        let r = HealthReport {
            results: vec![BreachResult {
                credential_id: "s".into(),
                title: "Old".into(),
                breached: None,
                reused: false,
                weak: false,
                stale: true,
            }],
            audited: 1,
            breached: 0,
            reused: 0,
            weak: 0,
            stale: 1,
            indeterminate: 0,
            reused_groups: 0,
            with_totp: 0,
        };
        assert_eq!(r.badges()["s"], "🕰️ Over 6 months old");
    }

    // Live-API test, ignored by default (needs network).
    #[test]
    #[ignore]
    fn live_api_marks_password_breached() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let hit = rt.block_on(check_password("password")).unwrap();
        assert!(hit.unwrap_or(0) > 1_000_000);
        let clean = rt
            .block_on(check_password("9f#ZmQ2$vL8x!qW4z-UNIQUE-99"))
            .unwrap();
        assert_eq!(clean, None);
    }
}
