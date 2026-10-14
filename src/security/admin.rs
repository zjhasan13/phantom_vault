//! Phase 5 — Business SSO/admin (desktop-only, no mobile).
//!
//! - Audit export: master-gated, chain-verified JSON of the tamper-evident
//!   access log (metadata only — the log never holds secrets by design).
//! - SCIM-lite: member CSV import → machine-local sidecar (NOT synced —
//!   admin is per-device by design; factory reset shreds it). Deprovision
//!   flips the member off AND auto-revokes their key-bound share grants.
//! - OIDC email-verify: access token → provider userinfo → verified email,
//!   bindable to a grantee key fingerprint for member-scoped sharing.
//!
//! Explicitly NOT: IdP-gated unlock (breaks zero-knowledge), server-side
//! SCIM endpoints, SAML (dependency + complexity — OIDC only).

use serde::{Deserialize, Serialize};

/// String-error result (admin IO/parse failures are user-facing messages,
/// never VaultError variants — the roster and OIDC paths stay decoupled).
type StdResult<T> = std::result::Result<T, String>;

/// Machine-local org roster. Override path via env for hermetic tests.
pub const ORG_FILE: &str = "org_members.json";
/// Roster sanity caps (a 10k-line "CSV" is an attack, not an org).
const MAX_MEMBERS: usize = 1_000;
const MAX_CSV_BYTES: usize = 256 * 1024;

fn org_path() -> std::path::PathBuf {
    if let Ok(o) = std::env::var("PV_ORG_FILE") {
        if !o.trim().is_empty() {
            return std::path::PathBuf::from(o);
        }
    }
    std::path::PathBuf::from(ORG_FILE)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrgMember {
    pub email: String,
    pub name: String,
    /// sha256 hex of the member's grantee PQ key ("" = keyless member —
    /// deprovision then only flips the flag, never grants).
    pub grantee_fp: String,
    pub enrolled_at: u64,
    pub active: bool,
}

fn valid_email(s: &str) -> bool {
    let s = s.trim().to_lowercase();
    let mut parts = s.split('@');
    let (user, domain) = match (parts.next(), parts.next(), parts.next()) {
        (Some(u), Some(d), None) => (u, d),
        _ => return false,
    };
    !user.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

fn valid_fp(s: &str) -> bool {
    let s = s.trim().to_lowercase();
    (s.is_empty() || s.len() == 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn load_members() -> Vec<OrgMember> {
    std::fs::read(org_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save_members(members: &[OrgMember]) -> StdResult<()> {
    let bytes =
        serde_json::to_vec_pretty(members).map_err(|e| format!("roster encode failed: {e}"))?;
    // Tmp+rename so a crash never leaves a half-written roster.
    let target = org_path();
    let tmp = target.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes).map_err(|e| format!("roster store failed: {e}"))?;
    std::fs::rename(&tmp, &target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("roster store failed: {e}")
    })?;
    Ok(())
}

/// Parse `email[,name[,grantee_fp_hex]]` lines. Returns (added, skipped).
/// Duplicates (case-insensitive email) and malformed lines skip LOUD via
/// the skipped count — never silently, never aborting the batch.
pub fn parse_members_csv(text: &str, now: u64) -> (Vec<OrgMember>, usize) {
    if text.len() > MAX_CSV_BYTES {
        return (Vec::new(), text.lines().count());
    }
    let mut out = Vec::new();
    let mut skipped = 0usize;
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut cols = line.split(',').map(|c| c.trim());
        let (email, name, fp) = (
            cols.next().unwrap_or("").to_lowercase(),
            cols.next().unwrap_or("").to_string(),
            cols.next().unwrap_or("").to_lowercase(),
        );
        if !valid_email(&email) || !valid_fp(&fp) || !seen.insert(email.clone()) {
            skipped += 1;
            continue;
        }
        if out.len() >= MAX_MEMBERS {
            skipped += 1;
            continue;
        }
        out.push(OrgMember {
            email,
            name,
            grantee_fp: fp,
            enrolled_at: now,
            active: true,
        });
    }
    (out, skipped)
}

/// Deprovision: flip the member off; revoke every share grant bound to
/// their recorded key. Returns revoked grant ids (empty when the member
/// has no key-bound grants — the flag flip still lands).
pub fn deprovision(
    members: &mut [OrgMember],
    vault: &mut crate::models::Vault,
    email: &str,
) -> Vec<String> {
    let want = email.trim().to_lowercase();
    let mut revoked = Vec::new();
    for m in members.iter_mut() {
        if m.email == want {
            m.active = false;
            if !m.grantee_fp.is_empty() {
                for g in vault.shared_grants.iter_mut() {
                    if g.grantee_fp == m.grantee_fp && !g.revoked {
                        g.revoked = true;
                        revoked.push(g.grant_id.clone());
                    }
                }
            }
        }
    }
    revoked
}

// ---------------------------------------------------------------------------
// Audit export: chain-verified JSON envelope (entries + validity flag).
// ---------------------------------------------------------------------------

/// Build the export bytes. Refuses ONLY when the log is unreadable.
/// A broken chain still exports (with chain_valid=false) — the admin most
/// needs the evidence exactly when tampering is suspected.
pub fn export_audit() -> StdResult<Vec<u8>> {
    let (n, valid) = crate::security::access_log::verify();
    let entries = crate::security::access_log::recent_filtered(usize::MAX, false);
    let v = serde_json::json!({
        "app": "phantom_vault",
        "exported_at": crate::models::current_timestamp(),
        "chain_valid": valid,
        "entry_count": n,
        "entries": entries,
    });
    serde_json::to_vec_pretty(&v).map_err(|e| format!("audit encode failed: {e}"))
}

// ---------------------------------------------------------------------------
// OIDC email-verify: access token → provider userinfo → verified email.
// No JWT/id_token verification dependency — the token is redeemed live
// against the provider (standard userinfo pattern), never trusted blind.
// ---------------------------------------------------------------------------

fn oidc_base(issuer: &str) -> StdResult<String> {
    let u = url::Url::parse(issuer.trim()).map_err(|_| "bad issuer URL".to_string())?;
    if u.scheme() != "https" {
        return Err("issuer must be https".to_string());
    }
    Ok(u.origin().ascii_serialization().trim_end_matches('/').to_string())
}

/// Pure half: parse a userinfo response. email_verified MUST be true —
/// unverified addresses never bind (fail-closed).
pub fn parse_userinfo(body: &[u8]) -> StdResult<String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "userinfo unreadable".to_string())?;
    if v.get("email_verified").and_then(|x| x.as_bool()) != Some(true) {
        return Err("email not verified by provider".to_string());
    }
    let email = v
        .get("email")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if !valid_email(&email) {
        return Err("provider returned a bad email".to_string());
    }
    Ok(email)
}

fn oidc_client() -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15));
    if let Some(proxy_url) = crate::sync::github_sync::effective_proxy() {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| format!("invalid proxy URL: {e}"))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| format!("HTTP client init failed: {e}"))
}

/// Redeem `access_token` at the issuer's userinfo endpoint. Returns the
/// verified email. Network errors fail LOUD (never a default email).
pub async fn verify_email(issuer: &str, access_token: &str) -> StdResult<String> {
    if access_token.trim().is_empty() {
        return Err("access token required".to_string());
    }
    let base = oidc_base(issuer)?;
    let client = oidc_client()?;
    let disc: serde_json::Value = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .map_err(|e| format!("discovery unreachable: {e}"))?
        .text()
        .await
        .map_err(|e| format!("discovery read failed: {e}"))?
        .parse::<serde_json::Value>()
        .map_err(|_| "discovery unreadable".to_string())?;
    let userinfo = disc
        .get("userinfo_endpoint")
        .and_then(|x| x.as_str())
        .ok_or("no userinfo endpoint".to_string())?;
    let body = client
        .get(userinfo)
        .bearer_auth(access_token.trim())
        .send()
        .await
        .map_err(|e| format!("userinfo unreachable: {e}"))?
        .text()
        .await
        .map_err(|e| format!("userinfo read failed: {e}"))?;
    parse_userinfo(body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_parses_dedupes_and_skips_loud() {
        let (members, skipped) = parse_members_csv(
            "# org roster\nALICE@corp.com,Alice,\n  bob@corp.com ,Bob,ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789\nbad-line\nno-at-sign,Nope,\nalice@corp.com,Dup,\n",
            1_000,
        );
        assert_eq!(members.len(), 2);
        assert_eq!(skipped, 3);
        assert_eq!(members[0].email, "alice@corp.com");
        assert_eq!(members[1].grantee_fp.len(), 64);
        assert!(members.iter().all(|m| m.active));
        // Oversize input refuses as a batch (counted, never parsed).
        let big = "a@b.co,\n".repeat(100_000);
        let (m2, s2) = parse_members_csv(&big, 1_000);
        assert!(m2.is_empty());
        assert!(s2 > 0);
    }

    #[test]
    fn roster_roundtrips_via_env_override() {
        let dir = std::env::temp_dir().join(format!("pv-org-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("org.json");
        std::env::set_var("PV_ORG_FILE", &path);
        let members = vec![OrgMember {
            email: "a@corp.com".into(),
            name: "A".into(),
            grantee_fp: "f".repeat(64),
            enrolled_at: 7,
            active: true,
        }];
        save_members(&members).unwrap();
        assert_eq!(load_members(), members);
        std::env::remove_var("PV_ORG_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deprovision_flips_and_revokes_keybound_grants() {
        use crate::models::{SharedGrant, Vault};
        let mut members = vec![
            OrgMember { email: "a@corp.com".into(), name: "".into(), grantee_fp: "k".repeat(64), enrolled_at: 1, active: true },
            OrgMember { email: "b@corp.com".into(), name: "".into(), grantee_fp: "".into(), enrolled_at: 1, active: true },
        ];
        let mut v = Vault::new();
        v.shared_grants.push(SharedGrant {
            grant_id: "g1".into(), item_kind: "login".into(), item_id: "x".into(),
            grantee_fp: "k".repeat(64), granted_at: 1, revoked: false,
        });
        let revoked = deprovision(&mut members, &mut v, "A@corp.com");
        assert_eq!(revoked, vec!["g1".to_string()]);
        assert!(v.shared_grants[0].revoked);
        assert!(!members[0].active);
        // Keyless member: flag flips, nothing to revoke.
        let revoked2 = deprovision(&mut members, &mut v, "b@corp.com");
        assert!(revoked2.is_empty());
        assert!(!members[1].active);
        // Unknown email: no-op.
        assert!(deprovision(&mut members, &mut v, "zzz@corp.com").is_empty());
    }

    #[test]
    fn userinfo_requires_verified_email() {
        let ok = parse_userinfo(br#"{"email":"A@Corp.com","email_verified":true}"#).unwrap();
        assert_eq!(ok, "a@corp.com");
        assert!(parse_userinfo(br#"{"email":"a@corp.com","email_verified":false}"#).is_err());
        assert!(parse_userinfo(br#"{"email":"a@corp.com"}"#).is_err());
        assert!(parse_userinfo(br#"{"email":"not-an-email","email_verified":true}"#).is_err());
        assert!(parse_userinfo(b"garbage").is_err());
        assert!(oidc_base("https://accounts.example.com/").unwrap() == "https://accounts.example.com");
        assert!(oidc_base("http://accounts.example.com/").is_err());
        assert!(oidc_base("not a url").is_err());
    }
}
