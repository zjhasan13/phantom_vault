//! Browser-extension Native Messaging bridge (`vault native-host`).
//!
//! Chrome/Firefox framing: u32-LE length + UTF-8 JSON, 1 MiB cap each way.
//! Request schema (all responses carry `"ok"`):
//! - `{"cmd":"ping"}` → `{"ok":true,"pong":true,"unlocked":bool}`
//! - `{"cmd":"query","app"|"url":"..."}` → matching logins
//!   `[{id,title,username,password,totp(live or "")}]`. Empty query never
//!   dumps the vault. Requires an unlocked vault.
//! - `{"cmd":"assert","rp_id":"...","challenge":"<b64>","credential_id"?}`
//!   → Ed25519 assertion `{credential_id, signature, sign_count}` with an
//!   in-memory counter bump the serve loop persists (RP clone detection).
//!
//! Security contract: the host unlocks ONLY via the Hello-cached DPAPI
//! passphrase (stdin IS the protocol pipe — no TTY prompt possible, and none
//! is attempted). No cached credential ⇒ one error frame, exit 2. Every
//! query/assertion is access-logged (metadata only). Extension allow-listing
//! stays where the platform enforces it: the registry manifest — print one
//! with `vault native-host --print-manifest <allowed-origin>`.

use crate::models::Vault;
use std::io::{Read, Write};

/// Native Messaging per-message cap (Chrome enforces 1 MiB; we match it).
pub const MAX_MSG_BYTES: usize = 1024 * 1024;

/// Hello-cached passphrase sidecar (canonical const lives in `main.rs`).
const HELLO_TOKEN_FILE: &str = "vault_hello.dpapi";

/// Length-prefixed frame for one JSON value.
pub fn encode_frame(msg: &serde_json::Value) -> Vec<u8> {
    let body = serde_json::to_vec(msg).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Read one frame: 4-byte LE length, cap enforced, exact JSON body.
pub fn decode_frame<R: Read>(r: &mut R) -> Result<serde_json::Value, String> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .map_err(|e| format!("frame read: {e}"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_MSG_BYTES {
        return Err(format!("frame size {len} rejected"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)
        .map_err(|e| format!("frame body: {e}"))?;
    serde_json::from_slice(&body).map_err(|e| format!("frame JSON: {e}"))
}

fn err(msg: impl Into<String>) -> serde_json::Value {
    serde_json::json!({"ok": false, "error": msg.into()})
}

/// Answer + whether the caller must re-seal the vault (assert bump).
pub struct Answer {
    pub reply: serde_json::Value,
    pub persist: bool,
}

fn b64_any(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let t = s.trim();
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(t))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t))
        .ok()
}

fn live_totp(secret: &str) -> String {
    if secret.trim().is_empty() {
        return String::new();
    }
    crate::totp_engine::generate_live_code(secret)
        .map(|(code, _)| code)
        .unwrap_or_default()
}

/// Pure request router (vault mutation limited to the assert counter bump).
pub fn answer(vault: &mut Vault, unlocked: bool, req: &serde_json::Value) -> Answer {
    let no = |s: &str| Answer {
        reply: err(s),
        persist: false,
    };
    let cmd = req.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
    match cmd {
        "ping" => Answer {
            reply: serde_json::json!({"ok": true, "pong": true, "unlocked": unlocked}),
            persist: false,
        },
        "query" => {
            if !unlocked {
                return no("vault locked");
            }
            let q = req
                .get("app")
                .or_else(|| req.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if q.is_empty() {
                return no("empty query (refusing vault dump)");
            }
            let entries: Vec<serde_json::Value> = vault
                .credentials
                .iter()
                .filter(|c| {
                    c.title.to_lowercase().contains(&q)
                        || c.username.to_lowercase().contains(&q)
                        || c.urls.iter().any(|u| u.to_lowercase().contains(&q))
                })
                .map(|c| {
                    serde_json::json!({
                        "id": c.id,
                        "title": c.title,
                        "username": c.username,
                        "password": c.password,
                        "totp": live_totp(&c.totp_secret),
                        "urls": c.urls,
                        "reprompt": c.reprompt,
                        "last_changed": c.last_changed,
                    })
                })
                .collect();
            crate::security::access_log::log_event("bridge-query", &q);
            Answer {
                reply: serde_json::json!({"ok": true, "entries": entries}),
                persist: false,
            }
        }
        // Smart-autofill: payment cards matching the query (checkout fill).
        "cards" => {
            if !unlocked {
                return no("vault locked");
            }
            let q = req
                .get("app")
                .or_else(|| req.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if q.is_empty() {
                return no("empty query (refusing vault dump)");
            }
            let entries: Vec<serde_json::Value> = vault
                .cards
                .iter()
                .filter(|k| {
                    k.deleted_at.is_none()
                        && (k.title.to_lowercase().contains(&q)
                            || k.cardholder_name.to_lowercase().contains(&q))
                })
                .map(|k| {
                    serde_json::json!({
                        "id": k.id,
                        "title": k.title,
                        "cardholder": k.cardholder_name,
                        "number": k.card_number,
                        "exp_month": k.exp_month,
                        "exp_year": k.exp_year,
                        "cvv": k.cvv,
                    })
                })
                .collect();
            crate::security::access_log::log_event("bridge-cards", &q);
            Answer {
                reply: serde_json::json!({"ok": true, "entries": entries}),
                persist: false,
            }
        }
        // Smart-autofill: identities matching the query (address-form fill).
        "identities" => {
            if !unlocked {
                return no("vault locked");
            }
            let q = req
                .get("app")
                .or_else(|| req.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if q.is_empty() {
                return no("empty query (refusing vault dump)");
            }
            let entries: Vec<serde_json::Value> = vault
                .identities
                .iter()
                .filter(|i| {
                    i.deleted_at.is_none()
                        && (i.title.to_lowercase().contains(&q)
                            || i.full_name.to_lowercase().contains(&q)
                            || i.email.to_lowercase().contains(&q))
                })
                .map(|i| {
                    serde_json::json!({
                        "id": i.id,
                        "title": i.title,
                        "full_name": i.full_name,
                        "email": i.email,
                        "phone": i.phone,
                        "address": i.address,
                    })
                })
                .collect();
            crate::security::access_log::log_event("bridge-identities", &q);
            Answer {
                reply: serde_json::json!({"ok": true, "entries": entries}),
                persist: false,
            }
        }
        "assert" => {
            if !unlocked {
                return no("vault locked");
            }
            let rp = req
                .get("rp_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            let challenge = req
                .get("challenge")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if rp.is_empty() || challenge.trim().is_empty() {
                return no("rp_id and challenge required");
            }
            let Some(chal) = b64_any(challenge) else {
                return no("challenge is not base64");
            };
            // Trashed passkeys never sign: a soft-deleted credential is
            // out of the authentication set until restored in the hub.
            let mut matches: Vec<usize> = vault
                .passkeys
                .iter()
                .enumerate()
                .filter(|(_, p)| p.deleted_at.is_none() && p.rp_id.to_lowercase() == rp)
                .map(|(i, _)| i)
                .collect();
            if matches.is_empty() {
                return no("no passkey for rp_id");
            }
            let idx = match req.get("credential_id").and_then(|v| v.as_str()) {
                Some(want) => {
                    let Some(want_bytes) = b64_any(want) else {
                        return no("credential_id is not base64");
                    };
                    match matches
                        .iter()
                        .find(|&&i| vault.passkeys[i].credential_id == want_bytes)
                    {
                        Some(&i) => i,
                        None => return no("credential_id not found for rp_id"),
                    }
                }
                None if matches.len() == 1 => matches.pop().unwrap(),
                None => {
                    let ids: Vec<String> = matches
                        .iter()
                        .map(|&i| {
                            use base64::Engine as _;
                            base64::engine::general_purpose::STANDARD
                                .encode(&vault.passkeys[i].credential_id)
                        })
                        .collect();
                    return Answer {
                        reply: serde_json::json!({
                            "ok": false,
                            "error": "ambiguous rp_id",
                            "credential_ids": ids,
                        }),
                        persist: false,
                    };
                }
            };
            let (seed, count) = {
                let pk = &vault.passkeys[idx];
                let (seed, _) = match crate::core::passkey::pkcs8_decode_private(
                    &pk.private_key_pkcs8,
                ) {
                    Ok(v) => v,
                    Err(e) => return no(&format!("key decode: {e}")),
                };
                (seed, pk.sign_count)
            };
            let sig = crate::core::passkey::sign_bytes(&seed, &chal);
            // Self-check before handing anything out: a corrupt key must
            // fail LOUD here, never as a mystery rejection at the RP.
            {
                let (_, pubkey) = match crate::core::passkey::pkcs8_decode_private(
                    &vault.passkeys[idx].private_key_pkcs8,
                ) {
                    Ok(v) => v,
                    Err(e) => return no(&format!("key decode: {e}")),
                };
                if !crate::core::passkey::verify_bytes(&pubkey, &chal, &sig) {
                    return no("signature self-check failed");
                }
            }
            vault.passkeys[idx].sign_count = count.saturating_add(1);
            {
                use base64::Engine as _;
                let eng = base64::engine::general_purpose::STANDARD;
                crate::security::access_log::log_event("bridge-assert", &rp);
                Answer {
                    reply: serde_json::json!({
                        "ok": true,
                        "credential_id": eng.encode(&vault.passkeys[idx].credential_id),
                        "signature": eng.encode(sig),
                        "sign_count": vault.passkeys[idx].sign_count,
                    }),
                    persist: true,
                }
            }
        }
        "" => no("missing cmd"),
        // Smart-autofill: record a fill (audit sidecar only, no vault write).
        "filled" => {
            if !unlocked {
                return no("vault locked");
            }
            let id = req
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if id.is_empty() {
                return no("id required");
            }
            let mut st = read_ext_stats();
            let now = crate::models::current_timestamp();
            st["total_fills"] = serde_json::json!(st.get("total_fills").and_then(|n| n.as_u64()).unwrap_or(0).saturating_add(1));
            st["last_filled"][id] = serde_json::json!(now);
            write_ext_stats(&st);
            Answer {
                reply: serde_json::json!({"ok": true}),
                persist: false,
            }
        }
        // Smart-autofill: dashboard stats (counts + heuristic security score).
        "stats" => {
            if !unlocked {
                return no("vault locked");
            }
            let now = crate::models::current_timestamp();
            let active: Vec<&crate::models::Credential> = vault
                .credentials
                .iter()
                .filter(|c| c.deleted_at.is_none())
                .collect();
            let stale = active
                .iter()
                .filter(|c| crate::models::is_stale(c.last_changed, now))
                .count();
            let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
            for c in &active {
                if !c.password.is_empty() {
                    *seen.entry(c.password.as_str()).or_insert(0) += 1;
                }
            }
            let reused_groups = seen.values().filter(|&&n| n > 1).count();
            let st = read_ext_stats();
            let mut score: i64 = 100 - (stale.min(10) as i64) * 3 - (reused_groups.min(6) as i64) * 5;
            if score < 0 {
                score = 0;
            }
            Answer {
                reply: serde_json::json!({
                    "ok": true,
                    "logins": active.len(),
                    "cards": vault.cards.iter().filter(|k| k.deleted_at.is_none()).count(),
                    "notes": vault.notes.iter().filter(|n| n.deleted_at.is_none()).count(),
                    "identities": vault.identities.iter().filter(|i| i.deleted_at.is_none()).count(),
                    "ssh_keys": vault.ssh_keys.iter().filter(|s| s.deleted_at.is_none()).count(),
                    "licenses": vault.licenses.iter().filter(|l| l.deleted_at.is_none()).count(),
                    "passkeys": vault.passkeys.iter().filter(|p| p.deleted_at.is_none()).count(),
                    "totp_accounts": vault.totp_accounts.len(),
                    "stale": stale,
                    "reused_groups": reused_groups,
                    "score": score,
                    "total_fills": st.get("total_fills").and_then(|n| n.as_u64()).unwrap_or(0),
                    "last_filled": st.get("last_filled").cloned().unwrap_or_else(|| serde_json::json!({})),
                }),
                persist: false,
            }
        }
        // Smart-autofill: save a freshly submitted login (update or append).
        // persist:true → the serve loop re-seals to disk; cloud sync follows
        // on the next desktop-app save (the host never pushes directly).
        "save_login" => {
            if !unlocked {
                return no("vault locked");
            }
            let username = req.get("username").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let password = req.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let url = req.get("url").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            if username.is_empty() || password.is_empty() || url.is_empty() {
                return no("username, password and url required");
            }
            let title = req.get("title").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let totp = req.get("totp").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let now = crate::models::current_timestamp();
            let dom = url_domain(&url);
            let existing = vault.credentials.iter_mut().find(|c| {
                c.deleted_at.is_none()
                    && c.username.to_lowercase() == username.to_lowercase()
                    && (c.urls.iter().any(|u| {
                        let d = url_domain(u);
                        !d.is_empty() && (d == dom || dom.contains(&d) || d.contains(&dom))
                    }) || c.title.to_lowercase() == dom)
            });
            let updated;
            if let Some(c) = existing {
                if c.password != password {
                    let retired = c.password.clone();
                    crate::models::push_history(&mut c.password_history, &retired, now);
                    c.password = password;
                    c.last_changed = now;
                }
                if !c.urls.iter().any(|u| u.to_lowercase() == url.to_lowercase()) {
                    c.urls.push(url);
                }
                updated = true;
            } else {
                let id = format!(
                    "ext{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0)
                );
                vault.credentials.push(crate::models::Credential {
                    id,
                    title: if title.is_empty() { dom.clone() } else { title },
                    username,
                    password,
                    totp_secret: totp,
                    urls: vec![url],
                    backup_codes: Vec::new(),
                    custom_fields: Vec::new(),
                    notes: String::from("Saved via browser extension"),
                    folder: crate::models::DEFAULT_FOLDER.to_string(),
                    reprompt: false,
                    attachments: Vec::new(),
                    travel_safe: false,
                    last_changed: now,
                    password_history: Vec::new(),
                    favorite: false,
                    deleted_at: None,
                });
                updated = false;
            }
            crate::security::access_log::log_event("bridge-save", &dom);
            Answer {
                reply: serde_json::json!({"ok": true, "updated": updated}),
                persist: true,
            }
        }
        other => no(&format!("unknown cmd: {other}")),
    }
}

/// Build the Chrome/Edge host manifest document (pure — unit tested).
pub fn manifest_json(allowed_origin: &str, exe_path: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "com.phantomvault.host",
        "description": "PhantomVault native bridge (stdio, vault-gated)",
        "path": exe_path.replace('/', "\\"),
        "type": "stdio",
        "allowed_origins": [allowed_origin],
    })
}

/// Print a manifest for `allowed_origin` (e.g. `chrome-extension://<id>/`).
/// Install path: registry
/// `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.phantomvault.host`.
pub fn print_manifest(allowed_origin: &str) {
    let path = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "phantom_vault.exe".to_string());
    println!("{}", manifest_json(allowed_origin, &path));
}

/// `%LOCALAPPDATA%\PhantomVault` — home of the host manifest, the recorded
/// data dir, and the debug log. Single choke-point so register + serve agree.
fn bridge_dir() -> std::path::PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("PhantomVault")
}

/// Best-effort debug log (no secrets, ever). Chrome hides the host's stderr,
// so this file is the only window into launch/CWD failures.
fn bridge_log(line: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(bridge_dir().join("native_host.log"))
    {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{ts}] {line}");
    }
}

/// Resolve the vault data dir: recorded at install time by
/// `register_native_host` (the app's CWD *is* the data dir). Falls back to
/// the current CWD so unit tests and manual runs keep working.
fn resolve_data_dir() -> Option<std::path::PathBuf> {
    let marker = bridge_dir().join("project_dir.txt");
    let recorded = std::fs::read_to_string(&marker).ok()?;
    let dir = std::path::PathBuf::from(recorded.trim());
    if dir.is_dir() {
        Some(dir)
    } else {
        None
    }
}

/// Extension sidecar (NOT encrypted — metadata only, no secrets):
/// `{"total_fills":N,"last_filled":{"<id>":<unix_ts>}}`. Lives beside the
/// vault so fill-audit + stats survive restarts without touching the model.
const EXT_STATS_FILE: &str = "pv_ext_stats.json";

fn read_ext_stats() -> serde_json::Value {
    std::fs::read_to_string(EXT_STATS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({"total_fills": 0, "last_filled": {}}))
}

fn write_ext_stats(v: &serde_json::Value) {
    if let Ok(s) = serde_json::to_string(v) {
        let _ = std::fs::write(EXT_STATS_FILE, s);
    }
}

/// Shared fill-audit writer: desktop auto-type AND the extension report
/// here, so popup "Last filled" + dashboard totals cover every fill path.
/// Sidecar only (metadata, no secrets) — never touches the vault model.
pub(crate) fn record_ext_fill(id: &str) {
    if id.trim().is_empty() {
        return;
    }
    let mut st = read_ext_stats();
    let now = crate::models::current_timestamp();
    st["total_fills"] = serde_json::json!(st.get("total_fills").and_then(|n| n.as_u64()).unwrap_or(0).saturating_add(1));
    st["last_filled"][id.trim()] = serde_json::json!(now);
    write_ext_stats(&st);
}

/// Lowercased registrable-ish domain of a URL (mirrors the extension's
/// base-domain matcher closely enough for save dedup).
fn url_domain(raw: &str) -> String {
    let h = raw.trim().to_lowercase();
    let h = h.rsplit("://").next().unwrap_or(&h);
    let h = h.split('/').next().unwrap_or(h);
    let h = h.split('?').next().unwrap_or(h);
    let h = h.split('#').next().unwrap_or(h);
    let h = h.split(':').next().unwrap_or(h);
    let parts: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 2 {
        parts.join(".")
    } else {
        parts[parts.len() - 2..].join(".")
    }
}
/// Install the native-messaging manifests for Chrome + Edge under HKCU and
/// return the manifest path. `allowed_origin` must be the real extension
/// origin (`chrome-extension://<32-char-id>/`) — Chrome refuses to connect
/// ("host not found" / "forbidden") when the calling extension is absent
/// from `allowed_origins`, so a placeholder default is no longer written.
pub fn register_native_host(
    allowed_origin: &str,
) -> Result<String, crate::error::VaultError> {
    use crate::error::VaultError;

    let origin = allowed_origin.trim().to_string();
    if !origin.starts_with("chrome-extension://") || !origin.ends_with('/') {
        return Err(VaultError::Sync(
            "allowed origin must look like chrome-extension://<id>/".into(),
        ));
    }
    let dir = bridge_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| VaultError::Sync(format!("bridge dir: {e}")))?;
    let manifest_path = dir.join("native-host.json");
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "phantom_vault.exe".to_string());
    // Locked to the user's real extension ID — no placeholder.
    let doc = manifest_json(&origin, &exe);
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&doc)
            .map_err(|e| VaultError::Sync(format!("manifest json: {e}")))?,
    )
    .map_err(|e| VaultError::Sync(format!("manifest write: {e}")))?;

    let manifest_str = manifest_path
        .to_str()
        .ok_or_else(|| VaultError::Sync("manifest path not unicode".into()))?;
    for root in [
        "Software\\Google\\Chrome\\NativeMessagingHosts\\com.phantomvault.host",
        "Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts\\com.phantomvault.host",
        "Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.phantomvault.host",
    ] {
        write_host_key(root, manifest_str)?;
    }
    // Chrome launches the host with CWD=System32/browser dir: record the
    // app's CWD (the vault data dir) so serve_cli can chdir back to it.
    match std::env::current_dir() {
        Ok(cwd) => {
            if let Err(e) = std::fs::write(dir.join("project_dir.txt"), cwd.to_string_lossy().as_bytes()) {
                return Err(VaultError::Sync(format!("project dir record: {e}")));
            }
            bridge_log(&format!("registered; data dir = {}", cwd.to_string_lossy()));
        }
        Err(e) => return Err(VaultError::Sync(format!("current dir: {e}"))),
    }
    Ok(manifest_path.to_string_lossy().into_owned())
}

/// Create `HKCU\<subkey>` and set its default value to `manifest_path`
/// (REG_SZ). The single Win32 choke-point — unit-tested against a sandbox key.
fn write_host_key(subkey: &str, manifest_path: &str) -> Result<(), crate::error::VaultError> {
    use crate::error::VaultError;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, REG_SZ,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let sub = wide(subkey);
    let mut bytes = Vec::with_capacity((manifest_path.len() + 1) * 2);
    for w in wide(manifest_path) {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    // SAFETY: NUL-terminated buffers outlive each call; handle closed below.
    // (RegCreateKeyW opens with full access — HKCU install needs no admin.)
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        let rc = RegCreateKeyW(HKEY_CURRENT_USER, sub.as_ptr(), &mut key);
        if rc != 0 || key.is_null() {
            return Err(VaultError::Sync(format!("registry create (0x{rc:X})")));
        }
        // Default value ("") = manifest path, REG_SZ with NUL, byte count.
        let rc = RegSetValueExW(
            key,
            std::ptr::null(),
            0,
            REG_SZ,
            bytes.as_ptr(),
            bytes.len() as u32,
        );
        RegCloseKey(key);
        if rc != 0 {
            return Err(VaultError::Sync(format!("registry write (0x{rc:X})")));
        }
    }
    Ok(())
}

/// Foreground entrypoint: `vault native-host`. Hello-cached unlock only
/// (stdin is the protocol pipe), then serve frames until EOF.
pub fn serve_cli() -> i32 {
    use secrecy::ExposeSecret;
    // Chrome spawns us with CWD=System32: jump back to the recorded data
    // dir so vault_hello.dpapi / my_secure_vault.enc resolve correctly.
    match resolve_data_dir() {
        Some(d) => {
            if let Err(e) = std::env::set_current_dir(&d) {
                bridge_log(&format!("WARN set_current_dir({}) failed: {e}", d.to_string_lossy()));
            } else {
                bridge_log(&format!("cwd -> {}", d.to_string_lossy()));
            }
        }
        None => bridge_log("WARN no project_dir.txt; using launch CWD"),
    }
    let emit_err = |msg: &str| {
        let frame = encode_frame(&err(msg));
        let _ = std::io::stdout().write_all(&frame);
        let _ = std::io::stdout().flush();
    };
    // No TTY prompt possible here — stdin belongs to the browser.
    let blob = match std::fs::read(HELLO_TOKEN_FILE) {
        Ok(b) => b,
        Err(e) => {
            bridge_log(&format!("Hello token missing: {e}"));
            emit_err("no Hello-cached credential — unlock the app with Hello once first");
            return 2;
        }
    };
    let secret = match crate::core::memory::DpapiGuard::unprotect(&blob) {
        Ok(s) => s,
        Err(_) => {
            emit_err("Hello credential unseal failed");
            return 2;
        }
    };
    let master = String::from_utf8_lossy(secret.expose()).into_owned();
    drop(secret);
    // Real vault first; on failure the cached passphrase may be the duress
    // password (cached by the decoy unlock path) — then serve ONLY the decoy
    // container. Real credentials never cross into the decoy branch.
    let mut serving_decoy = false;
    let (mut vault, _) = match crate::storage::load_vault_versioned(
        &master,
        crate::developer::vault_run::VAULT_FILE,
    ) {
        Ok(v) => v,
        Err(_) => match crate::security::decoy::try_open_decoy(&master) {
            Some(d) => {
                bridge_log("decoy cover served (duress credential)");
                serving_decoy = true;
                (d, false)
            }
            None => {
                use zeroize::Zeroize;
                let mut m = master;
                m.zeroize();
                bridge_log("vault unlock failed");
                emit_err("unlock failed: wrong passphrase");
                return 1;
            }
        },
    };
    let master = secrecy::SecretString::new(master);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut output = std::io::stdout();
    loop {
        let req = match decode_frame(&mut input) {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("frame read") {
                    break; // EOF / browser gone — clean exit, code 0.
                }
                let frame = encode_frame(&err(format!("bad frame: {msg}")));
                if output.write_all(&frame).and(output.flush()).is_err() {
                    break;
                }
                continue;
            }
        };
        // Cover integrity: a coerced session must never write into the decoy
        // (which would prove the cover is fake) — refuse saves silently.
        if serving_decoy && req.get("cmd").and_then(|c| c.as_str()).unwrap_or("") == "save_login" {
            let frame = encode_frame(&err("save refused"));
            if output.write_all(&frame).and(output.flush()).is_err() {
                break;
            }
            continue;
        }
        let ans = answer(&mut vault, true, &req);
        if ans.persist {
            // Clone-detection honesty: a bumped counter MUST reach disk.
            if crate::storage::save_vault(
                &vault,
                master.expose_secret(),
                crate::developer::vault_run::VAULT_FILE,
            )
            .is_err()
            {
                let frame = encode_frame(&err("counter persist failed"));
                let _ = output.write_all(&frame);
                let _ = output.flush();
                continue;
            }
        }
        let frame = encode_frame(&ans.reply);
        if output.write_all(&frame).and(output.flush()).is_err() {
            break;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, PasskeyItem, Vault};

    fn vault_with_login() -> Vault {
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "c1".into(),
            title: "GitHub".into(),
            username: "octo".into(),
            password: "ghp_x".into(),
            totp_secret: String::new(),
            urls: vec!["https://github.com/login".into()],
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
            folder: "General".into(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: 0,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        });
        v
    }

    fn vault_with_passkey() -> Vault {
        let mut v = Vault::new();
        v.passkeys.push(crate::core::passkey::register("github.com", "octo", 1));
        v
    }

    #[test]
    fn framing_roundtrip_and_cap() {
        let msg = serde_json::json!({"cmd": "ping", "n": 42});
        let frame = encode_frame(&msg);
        assert_eq!(u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize, frame.len() - 4);
        let back = decode_frame(&mut &frame[..]).unwrap();
        assert_eq!(back, msg);
        // Oversize length prefix rejected without allocating.
        let evil = (MAX_MSG_BYTES as u32 + 1).to_le_bytes().to_vec();
        assert!(decode_frame(&mut &evil[..]).is_err());
        // Truncated body rejected.
        let cut = &frame[..frame.len() - 2];
        assert!(decode_frame(&mut &cut[..]).is_err());
        // Garbage JSON rejected.
        let mut bad = 3u32.to_le_bytes().to_vec();
        bad.extend_from_slice(b"{{}");
        assert!(decode_frame(&mut &bad[..]).is_err());
    }

    #[test]
    fn ping_reports_lock_state() {
        let mut v = Vault::new();
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "ping"}));
        assert_eq!(r.reply["unlocked"], false);
        assert!(!r.persist);
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "ping"}));
        assert_eq!(r.reply["unlocked"], true);
        assert!(answer(&mut v, true, &serde_json::json!({"cmd": "nope"}))
            .reply["ok"]
            == false);
        assert!(answer(&mut v, true, &serde_json::json!({}))
            .reply["ok"]
            == false);
    }

    #[test]
    fn query_matches_and_never_dumps() {
        let mut v = vault_with_login();
        // Locked → deny even with a good query.
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "query", "app": "git"}));
        assert_eq!(r.reply["ok"], false);
        // Empty query → deny, never a full dump.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "query", "app": ""}));
        assert_eq!(r.reply["ok"], false);
        assert!(r.reply.get("entries").is_none());
        // Substring over title/username/url.
        for q in ["git", "OCTO", "github.com"] {
            let r = answer(&mut v, true, &serde_json::json!({"cmd": "query", "url": q}));
            assert_eq!(r.reply["ok"], true);
            assert_eq!(r.reply["entries"][0]["password"], "ghp_x");
        }
        // Miss → ok with empty list.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "query", "app": "bank"}));
        assert_eq!(r.reply["entries"].as_array().unwrap().len(), 0);
        // Login entries now carry urls for extension-side match-mode filtering.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "query", "url": "git"}));
        assert_eq!(r.reply["entries"][0]["urls"][0], "https://github.com/login");
    }

    #[test]
    fn cards_and_identities_match_without_dumping() {
        use crate::models::{IdentityItem, PaymentCard};
        let mut v = Vault::new();
        v.cards.push(PaymentCard {
            id: "k1".into(),
            title: "Visa Gold".into(),
            cardholder_name: "Ada L".into(),
            card_number: "4111111111111111".into(),
            exp_month: "01".into(),
            exp_year: "30".into(),
            cvv: "123".into(),
            folder: String::new(),
            notes: String::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        v.identities.push(IdentityItem {
            id: "i1".into(),
            title: "Home".into(),
            full_name: "Ada Lovelace".into(),
            nid_or_passport: String::new(),
            email: "ada@example.com".into(),
            phone: "123".into(),
            address: "1 Analytic Way".into(),
            folder: String::new(),
            notes: String::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        // Locked / empty → deny, never dump.
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "cards", "app": "visa"}));
        assert_eq!(r.reply["ok"], false);
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "cards", "app": ""}));
        assert_eq!(r.reply["ok"], false);
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "identities", "app": ""}));
        assert_eq!(r.reply["ok"], false);
        // Happy paths expose fill fields, never anything else.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "cards", "app": "visa"}));
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["entries"][0]["cvv"], "123");
        assert!(r.reply["entries"][0].get("password").is_none());
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "identities", "app": "ada"}));
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["entries"][0]["address"], "1 Analytic Way");
        // Miss → ok with empty list.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "cards", "app": "bank"}));
        assert_eq!(r.reply["entries"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn save_login_appends_updates_and_validates() {
        let mut v = vault_with_login();
        // Validation: missing fields refused, nothing persisted.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "save_login", "username": "a"}));
        assert_eq!(r.reply["ok"], false);
        assert!(!r.persist);
        // Locked → deny.
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "save_login", "username": "a", "password": "b", "url": "https://x.com"}));
        assert_eq!(r.reply["ok"], false);
        // New site → append.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "save_login", "username": "neo", "password": "pw1", "url": "https://example.com/login", "title": "Example"}));
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["updated"], false);
        assert!(r.persist);
        assert_eq!(v.credentials.len(), 2);
        // Same username + domain → update in place, history grows.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "save_login", "username": "NEO", "password": "pw2", "url": "https://example.com/other"}));
        assert_eq!(r.reply["updated"], true);
        let c = v.credentials.iter().find(|c| c.username == "neo").unwrap();
        assert_eq!(c.password, "pw2");
        assert_eq!(c.password_history.len(), 1);
        assert_eq!(v.credentials.len(), 2);
    }

    #[test]
    fn stats_reports_counts_and_score() {
        let mut v = vault_with_login();
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "stats"}));
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["logins"], 1);
        assert_eq!(r.reply["totp_accounts"], 0);
        assert!(r.reply["score"].as_i64().unwrap() >= 0);
        assert_eq!(r.reply["total_fills"], 0);
        // filled bumps the counter and stamps the id.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "filled", "id": "c1"}));
        assert_eq!(r.reply["ok"], true);
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "stats"}));
        assert_eq!(r.reply["total_fills"], 1);
        assert!(r.reply["last_filled"]["c1"].as_u64().unwrap() > 0);
        // Locked → deny both.
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "stats"}));
        assert_eq!(r.reply["ok"], false);
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "filled", "id": "c1"}));
        assert_eq!(r.reply["ok"], false);
        // Sidecar lives in CWD during tests — never leave it behind.
        let _ = std::fs::remove_file(EXT_STATS_FILE);
    }

    #[test]
    fn assert_signs_and_bumps_counter() {
        use base64::Engine as _;
        let mut v = vault_with_passkey();
        let chal = base64::engine::general_purpose::STANDARD.encode(b"rp-challenge-123");
        // Unknown rp → clean error.
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "evil.com", "challenge": chal}),
        );
        assert_eq!(r.reply["ok"], false);
        // Locked → deny.
        let r = answer(
            &mut v,
            false,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal}),
        );
        assert_eq!(r.reply["ok"], false);
        // Bad challenge → deny.
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": "!!!"}),
        );
        assert_eq!(r.reply["ok"], false);
        // Happy path: valid signature over the challenge, counter 0→1.
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal}),
        );
        assert_eq!(r.reply["ok"], true);
        assert!(r.persist);
        assert_eq!(r.reply["sign_count"], 1);
        assert_eq!(v.passkeys[0].sign_count, 1);
        let sig: Vec<u8> = base64::engine::general_purpose::STANDARD
            .decode(r.reply["signature"].as_str().unwrap())
            .unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        let chal_raw = base64::engine::general_purpose::STANDARD.decode(&chal).unwrap();
        let (_, pubkey) = crate::core::passkey::pkcs8_decode_private(
            &v.passkeys[0].private_key_pkcs8,
        )
        .unwrap();
        assert!(crate::core::passkey::verify_bytes(&pubkey, &chal_raw, &sig_arr));
    }

    #[test]
    fn assert_refuses_trashed_passkey() {
        use base64::Engine as _;
        let mut v = vault_with_passkey();
        let chal = base64::engine::general_purpose::STANDARD.encode(b"c");
        // Active key signs fine…
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal}),
        );
        assert_eq!(r.reply["ok"], true);
        // …but once trashed it leaves the auth set (same as missing).
        v.passkeys[0].deleted_at = Some(1000);
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal}),
        );
        assert_eq!(r.reply["ok"], false);
        assert_eq!(r.reply["error"], "no passkey for rp_id");
        assert!(!r.persist);
    }

    #[test]
    fn assert_ambiguous_without_credential_id() {
        use base64::Engine as _;
        let mut v = Vault::new();
        v.passkeys.push(crate::core::passkey::register("github.com", "a", 1));
        v.passkeys.push(crate::core::passkey::register("github.com", "b", 2));
        let chal = base64::engine::general_purpose::STANDARD.encode(b"c");
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal}),
        );
        assert_eq!(r.reply["ok"], false);
        assert_eq!(r.reply["credential_ids"].as_array().unwrap().len(), 2);
        // Disambiguate by credential_id → signs.
        let want = base64::engine::general_purpose::STANDARD.encode(&v.passkeys[1].credential_id);
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal, "credential_id": want}),
        );
        assert_eq!(r.reply["ok"], true);
        assert_eq!(v.passkeys[1].sign_count, 1);
        assert_eq!(v.passkeys[0].sign_count, 0);
    }

    #[test]
    fn registry_install_roundtrip_in_sandbox() {
        use windows_sys::Win32::System::Registry::{
            RegDeleteKeyW, RegGetValueW, HKEY_CURRENT_USER, REG_SZ,
        };
        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }
        // Sandbox key only — never touches the real Chrome/Edge hives.
        let sub = format!(
            "Software\\PhantomVaultTest{}\\NativeMessagingHosts\\com.phantomvault.host",
            std::process::id()
        );
        let marker = r"C:\tmp\pv-native-host.json";
        // Production writer, sandbox target.
        write_host_key(&sub, marker).unwrap();
        // Read back the default value and compare exactly.
        let sub_w = wide(&sub);
        let mut buf = [0u16; 260];
        let mut size = (buf.len() * 2) as u32;
        let mut ty: u32 = 0;
        unsafe {
            assert_eq!(
                RegGetValueW(
                    HKEY_CURRENT_USER,
                    sub_w.as_ptr(),
                    std::ptr::null(),
                    2, // RRF_RT_REG_SZ
                    &mut ty,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    &mut size,
                ),
                0
            );
        }
        assert_eq!(ty, REG_SZ);
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        assert_eq!(String::from_utf16_lossy(&buf[..end]), marker);
        unsafe {
            assert_eq!(RegDeleteKeyW(HKEY_CURRENT_USER, sub_w.as_ptr()), 0);
        }
        // Parent test key cleanup (best effort).
        let parent = wide(&format!("Software\\PhantomVaultTest{}", std::process::id()));
        unsafe {
            let _ = RegDeleteKeyW(HKEY_CURRENT_USER, parent.as_ptr());
        }
    }

    #[test]
    fn manifest_shape_is_installable() {
        let m = manifest_json("chrome-extension://abc/", "C:/x/phantom_vault.exe");
        assert_eq!(m["name"], "com.phantomvault.host");
        assert_eq!(m["type"], "stdio");
        assert_eq!(m["allowed_origins"][0], "chrome-extension://abc/");
        assert_eq!(m["path"], "C:\\x\\phantom_vault.exe");
        // Every key the browser requires is present, nothing extra.
        for k in ["name", "description", "path", "type", "allowed_origins"] {
            assert!(m.get(k).is_some(), "missing {k}");
        }
        let _ = PasskeyItem::default();
    }
}
