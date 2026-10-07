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
/// Bridge liveness beacon (NOT a secret — unix timestamp text). The desktop
/// app rewrites it every 20s while unlocked. A stale/missing beacon means
/// the app is closed, crashed, or locked: serve NOTHING (P1: closed-app
/// serving via a leftover Hello token file).
const HEARTBEAT_FILE: &str = "vault_heartbeat.json";
/// Max beacon age: 20s beat + generous slack (sleep delays, clock skew).
/// Kill -9 / crash safe — no cleanup path needed, staleness refuses.
const HEARTBEAT_MAX_AGE_SECS: u64 = 75;

/// Minimum seconds a TOTP code must have left before the bridge will hand it
/// to the browser. Mirrors `main::TOTP_COPY_GUARD_SECS`: with ~3s left a code
/// can expire between delivery and the user pressing paste/submit. HOTP is
/// exempt — it has no expiry window.
const MIN_TOTP_FILL_REMAINING_SECS: u64 = 3;

/// A code filled this recently counts as "recently used" in the ranking score.
/// Sidecar-driven (no vault field), so this is a scoring hint only, never a
/// correctness input.
const RECENT_FILL_SECS: u64 = 30 * 24 * 3600;

/// Phase C: host session idle TTL (60s). One decrypted session serves the
/// burst, then exits — bounds the plaintext window. Next query pays one
/// fresh KDF. Unit-tested below.
pub(crate) const HOST_IDLE_TTL_SECS: u64 = 60;

/// Pure TTL decision (unit-testable): idle longer than TTL ⇒ expired.
pub(crate) fn session_idle_expired(idle_secs: u64) -> bool {
    idle_secs > HOST_IDLE_TTL_SECS
}

/// Picker bound. Enough rows to disambiguate, small enough that a loose
/// substring match can't dump the entire hub into the popup.
const MAX_TOTP_CANDIDATES: usize = 12;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pure liveness decision (unit-testable): fresh beacon ⇒ live app.
fn heartbeat_parts(beacon: Option<u64>, now: u64) -> bool {
    match beacon {
        Some(t) => now.saturating_sub(t) < HEARTBEAT_MAX_AGE_SECS,
        None => false,
    }
}

fn desktop_alive() -> bool {
    let ts = std::fs::read_to_string(HEARTBEAT_FILE)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    heartbeat_parts(ts, now_secs())
}

/// Full bridge-unlock predicate: sealed Hello credential AND a live app.
/// Either half missing ⇒ locked (extension shows Vault Locked / App Closed).
fn bridge_unlocked() -> bool {
    std::path::Path::new(HELLO_TOKEN_FILE).exists() && desktop_alive()
}
/// Length-prefixed frame for one JSON value.
pub fn encode_frame(msg: &serde_json::Value) -> Vec<u8> {
    let mut body = serde_json::to_vec(msg).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    if body.len() > MAX_MSG_BYTES {
        body = b"{\"ok\":false,\"error\":\"reply too large\"}".to_vec();
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Strict `chrome-extension://<32-char-id>/` format check (Chrome IDs are
/// `[a-p]{32}`; accept `[a-z]{32}` to cover Edge/Brave variants). Rejects
/// `chrome-extension://*/` and any non-matching string.
pub(crate) fn valid_origin_format(origin: &str) -> bool {
    let rest = match origin.strip_prefix("chrome-extension://") {
        Some(r) => r,
        None => return false,
    };
    let id = match rest.strip_suffix('/') {
        Some(id) => id,
        None => return false,
    };
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_lowercase())
}

/// Origins pinned at install time in `%LOCALAPPDATA%\PhantomVault\native-host.json`.
fn registered_origins() -> Vec<String> {
    let doc: serde_json::Value = std::fs::read_to_string(bridge_dir().join("native-host.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    doc.get("allowed_origins")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Origin allow check: strict format AND (if a manifest is registered) listed
/// there. Fail-closed: unknown/missing manifest still requires valid format.
pub(crate) fn origin_allowed(origin: &str) -> bool {
    if !valid_origin_format(origin) {
        return false;
    }
    let reg = registered_origins();
    if reg.is_empty() {
        return true;
    }
    reg.iter().any(|o| o == origin)
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

/// Decoy-cover persistence gate (H9): a coerced session must never write
/// into the decoy — every persisting answer is refused at the loop, not in
/// each arm. Pure so the matrix is unit-testable.
fn persist_refused(serving_decoy: bool, persist: bool) -> bool {
    serving_decoy && persist
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

/// C5: token-bucket for WebAuthn asserts (100/min per host process).
/// Single-shot phishing is blocked by the `uv` gate above; this caps
/// automated relay loops. Lock-free atomics — never panics.
use std::sync::atomic::{AtomicU64, Ordering};
static ASSERT_COUNT: AtomicU64 = AtomicU64::new(0);
static ASSERT_WINDOW: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
pub(crate) fn reset_assert_rate() {
    ASSERT_COUNT.store(0, Ordering::SeqCst);
    ASSERT_WINDOW.store(0, Ordering::SeqCst);
}
fn assert_rate_ok() -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0);
    let win = ASSERT_WINDOW.load(Ordering::SeqCst);
    if win != now {
        ASSERT_WINDOW.store(now, Ordering::SeqCst);
        ASSERT_COUNT.store(1, Ordering::SeqCst);
        return true;
    }
    let n = ASSERT_COUNT.fetch_add(1, Ordering::SeqCst);
    n < 100
}

/// M12: fill-event brake (120/min per host process — popup tiles report
/// per frame; unauthenticated floods must not spin the sidecar).
/// Counters are module-level (not fn-local) so cfg(test) resets make
/// budget tests hermetic — same pattern as the assert limiter above.
static FILL_COUNT: AtomicU64 = AtomicU64::new(0);
static FILL_WINDOW: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
pub(crate) fn reset_fill_rate() {
    FILL_COUNT.store(0, Ordering::SeqCst);
    FILL_WINDOW.store(0, Ordering::SeqCst);
}
fn fill_rate_ok() -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0);
    if FILL_WINDOW.load(Ordering::SeqCst) != now {
        FILL_WINDOW.store(now, Ordering::SeqCst);
        FILL_COUNT.store(1, Ordering::SeqCst);
        return true;
    }
    FILL_COUNT.fetch_add(1, Ordering::SeqCst) < 120
}

fn short_id(id: &str) -> String {
    crate::security::access_log::short_hash(id)
}

/// M13: re-seal brake (30/min per host process). Each save is a full
/// Argon2id + ML-KEM reseal + backup rotation — unthrottled, one caller
/// can pin the disk. Bumps still reach disk under the cap.
/// Module-level counters + cfg(test) reset, same as the fill limiter.
static SAVE_COUNT: AtomicU64 = AtomicU64::new(0);
static SAVE_WINDOW: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
pub(crate) fn reset_save_rate() {
    SAVE_COUNT.store(0, Ordering::SeqCst);
    SAVE_WINDOW.store(0, Ordering::SeqCst);
}
fn save_rate_ok() -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0);
    if SAVE_WINDOW.load(Ordering::SeqCst) != now {
        SAVE_WINDOW.store(now, Ordering::SeqCst);
        SAVE_COUNT.store(1, Ordering::SeqCst);
        return true;
    }
    SAVE_COUNT.fetch_add(1, Ordering::SeqCst) < 30
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
        // Extension PIN state/hash — managed ONLY from the desktop app.
        // The extension keeps zero PIN state and enforces against this hash.
        // Gated on unlocked like stats: a locked vault reveals nothing,
        // and the extension already gates on lock separately.
        "ext_pin_state" => {
            if !unlocked {
                return no("vault locked");
            }
            Answer {
                reply: serde_json::json!({
                    "ok": true,
                    "set": crate::security::ext_pin::is_set(std::path::Path::new(".")),
                }),
                persist: false,
            }
        }
        "ext_pin_hash" => {
            if !unlocked {
                return no("vault locked");
            }
            match crate::security::ext_pin::read_hash(std::path::Path::new(".")) {
                Some(h) => Answer {
                    reply: serde_json::json!({"ok": true, "hash": h}),
                    persist: false,
                },
                None => no("no extension PIN set"),
            }
        }
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
            // C7: refuse 1-char dump probes ("a" matches everything).
            if q.is_empty() || q.chars().count() < 2 {
                return no("query too short (refusing vault dump)");
            }
            // Omni-domain: the raw query plus equivalent siblings, brand
            // stems, and stripped registrables all match (any-hit).
            let variants = expand_query(&q);
            let now = crate::models::current_timestamp();
            let pw_freq = login_pw_freq(vault);
            // One sidecar read per query: last-filled stamps for trust sort.
            let ext_stats = read_ext_stats();
            let last_filled_of = |id: &str| {
                ext_stats
                    .get("last_filled")
                    .and_then(|m| m.get(id))
                    .and_then(|n| n.as_u64())
                    .unwrap_or(0)
            };
            let mut entries: Vec<serde_json::Value> = vault
                .credentials
                .iter()
                .filter(|c| {
                    if c.deleted_at.is_some() {
                        return false;
                    }
                    let title = c.title.to_lowercase();
                    let user = c.username.to_lowercase();
                    variants.iter().any(|v| {
                        title.contains(v) || user.contains(v) || c.urls.iter().any(|u| u.to_lowercase().contains(v))
                    })
                })
                .map(|c| {
                    serde_json::json!({
                        "id": c.id,
                        "title": c.title,
                        "username": c.username,
                        "password": c.password,
                        "totp": live_totp(&c.totp_secret),
                        "urls": c.urls,
                        "folder": c.folder,
                        "reprompt": c.reprompt,
                        "last_changed": c.last_changed,
                        "verified": vault.is_verified(&c.id),
                        "health": login_health_kind(&c.password, c.last_changed, now, pw_freq.get(c.password.as_str()).copied().unwrap_or(0)),
                        "last_filled": last_filled_of(&c.id),
                    })
                })
                .collect();
            // C7: cap bulk exfil — one query never dumps the whole vault.
            entries.truncate(25);
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
            // C5: silent signing was a 2FA-bypass primitive (any page could
            // relay a caller-supplied challenge). Fail-closed: the caller
            // must present a fresh user-verification flag minted by an
            // out-of-band Hello prompt in the desktop app.
            if req.get("uv").and_then(|v| v.as_bool()) != Some(true) {
                return no("user verification required");
            }
            if !assert_rate_ok() {
                return no("assert rate limited");
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
        // Passkey discovery (v1): metadata for live passkeys under an rp_id.
        // No secrets, no sign-count bump, no persist — the full `assert`
        // ceremony (desktop UV + sign) stays explicit. Ceremony relay is a
        // follow-up; this only tells the page-side which key matches.
        "passkey_lookup" => {
            if !unlocked {
                return no("vault locked");
            }
            let rp = req
                .get("rp")
                .or_else(|| req.get("rp_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if rp.is_empty() {
                return no("rp required");
            }
            let found: Vec<serde_json::Value> = vault
                .passkeys
                .iter()
                .filter(|p| p.deleted_at.is_none() && p.rp_id.to_lowercase() == rp)
                .map(|p| {
                    serde_json::json!({"user": p.user_name, "sign_count": p.sign_count})
                })
                .collect();
            Answer {
                reply: serde_json::json!({"ok": true, "passkeys": found}),
                persist: false,
            }
        }
        // Standalone 2FA Hub lookup: live codes for hub accounts whose
        // issuer/account matches the query — the fallback when login entries
        // carry no totp_secret. Live codes only (never secrets), unlocked-
        // only, no persist, no sign-count semantics here.
        //
        // Returns RANKED candidates (`candidates[]`), never a single guess:
        // the extension refuses to auto-fill unless exactly one candidate comes
        // back, and a duplicate-keyed pair always forces the ambiguity picker.
        "totp_lookup" => {
            if !unlocked {
                return no("vault locked");
            }
            let raw_q = req
                .get("app")
                .or_else(|| req.get("url"))
                .or_else(|| req.get("domain"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if raw_q.is_empty() {
                return no("domain required");
            }
            let q = norm_lookup_key(&raw_q);
            if q.is_empty() {
                return no("domain required");
            }
            let q_domain = url_domain(&q);

            // Optional exact-id scope. The caller already knows WHICH row it
            // wants (a login fill knows its own entry id), so the answer must not
            // depend on the issuer/domain scorer guessing that row is a match.
            // Used by the login-fill OTP half, which used to fall back to the
            // code `PV_QUERY` had minted earlier — possibly many seconds before
            // the fill, after a reprompt or an extension PIN — injecting a code
            // that was already dying and bypassing this guard entirely.
            //
            // It widens MATCHING only. The row must still be live and carry a
            // usable secret, the code is still minted here and now, and the
            // expiry guard below still withholds a dying one. The id comes from
            // the vault (never from the page), so trusting it cannot steer a
            // wrong account into a field.
            let want_id = req
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let scoped = !want_id.is_empty();

            // One sidecar read per lookup. Recency is the +10 bonus, so it
            // needs no vault field (no schema change). Best-effort: a missing
            // or corrupt sidecar only drops the bonus, it never breaks a fill.
            let st = read_ext_stats();
            let now = crate::models::current_timestamp();
            let recently_filled = |id: &str| -> bool {
                let ts = st
                    .get("last_filled")
                    .and_then(|m| m.get(id))
                    .and_then(|n| n.as_u64())
                    .unwrap_or(0);
                ts > 0 && now.saturating_sub(ts) <= RECENT_FILL_SECS
            };
            // Same stamp, as an absolute epoch, so the picker can render an
            // honest "Last 3m ago" instead of making the user infer recency from
            // an invisible +10 score bonus. One read, two derivations.
            let last_filled_ts = |id: &str| -> u64 {
                st.get("last_filled")
                    .and_then(|m| m.get(id))
                    .and_then(|n| n.as_u64())
                    .unwrap_or(0)
            };

            // A lookup spans BOTH storage shapes for a live code:
            //   - `totp_accounts`: standalone 2FA Hub cards;
            //   - `credentials`: logins carrying an inline `totp_secret`
            //     (how KeePass/Bitwarden imports usually store TOTP).
            // Scoring them separately and merging afterwards used to leave the
            // client choosing blindly with `.find(e => e.totp)` over a raw login
            // query — which is the exact blind-guess the ambiguity picker
            // exists to prevent. Both shapes are ranked in ONE list here so a
            // site with a hub card AND two inline logins forces a picker
            // instead of an arbitrary pick.
            let hub: Vec<&crate::models::TotpAccount> = vault.totp_accounts.iter().collect();
            let logins: Vec<&crate::models::Credential> = vault
                .credentials
                .iter()
                .filter(|c| c.deleted_at.is_none() && !c.totp_secret.trim().is_empty())
                .collect();

            // is_dup is computed over the UNION of both shapes on purpose: a
            // collision only exists if two candidates share (issuer, account),
            // and checking each collection alone would call a duplicated pair
            // "unique" twice — so both would auto-fill and one of them would be
            // wrong. Same `dup_key` the hub badge uses, so the two agree.
            //
            // Identity uses each item's OWN LABEL (hub `issuer` / login
            // `title`), never the scoring haystack. The scorer folds a login's
            // URL text in so "Work email" on github.com still matches, but a key
            // built from that haystack would read "github https://github.com/login"
            // and never collide with a hub card titled "GitHub" — so the very
            // duplicate this exists to catch would slip through as two unique
            // accounts.
            let mut keys: Vec<(String, String)> = Vec::with_capacity(hub.len() + logins.len());
            for a in &hub {
                keys.push(crate::models::dup_key(&a.issuer, &a.account_name));
            }
            for c in &logins {
                keys.push(crate::models::dup_key(&c.title, &c.username));
            }
            let dups = crate::models::dup_marks_keyed(&keys);

            let mut ranked: Vec<TotpCandidate> = Vec::new();
            for (i, acc) in hub.iter().enumerate() {
                if let Some(c) = score_totp_candidate(
                    acc,
                    &q,
                    &q_domain,
                    dups[i],
                    recently_filled(&acc.id),
                    false,
                ) {
                    ranked.push(c);
                }
            }
            for (i, cred) in logins.iter().enumerate() {
                if let Some(c) = score_credential_totp_candidate(
                    cred,
                    &q,
                    &q_domain,
                    dups[hub.len() + i],
                    recently_filled(&cred.id),
                    false,
                ) {
                    ranked.push(c);
                }
            }

            // Scoped lookup that the scorer rejected: serve the named row
            // anyway. Only the id can have missed (both shapes above already
            // proved the row is live and TOTP-bearing, and `trusted` re-proves it
            // below), so this cannot introduce a row the normal path would have
            // refused on grounds other than text similarity. `is_dup` still rides
            // along: a pinned id is a known identity, not a licence to auto-fill
            // a collision.
            if scoped && !ranked.iter().any(|c| c.id == want_id) {
                for (i, acc) in hub.iter().enumerate().filter(|(_, a)| a.id == want_id) {
                    if let Some(c) = score_totp_candidate(
                        acc,
                        &q,
                        &q_domain,
                        dups[i],
                        recently_filled(&acc.id),
                        true,
                    ) {
                        ranked.push(c);
                    }
                }
                for (i, cred) in logins.iter().enumerate().filter(|(_, c)| c.id == want_id) {
                    if let Some(c) = score_credential_totp_candidate(
                        cred,
                        &q,
                        &q_domain,
                        dups[hub.len() + i],
                        recently_filled(&cred.id),
                        true,
                    ) {
                        ranked.push(c);
                    }
                }
            }

            // Tier, then score, then favorite. `sort_by` is STABLE and `ranked`
            // was built in vault order, so full ties fall through to vault index
            // without an explicit index compare — same vault + same site always
            // yields the same order, so a re-lookup can never silently change
            // which account hands-free fill would have chosen.
            ranked.sort_by(|a, b| {
                a.tier
                    .cmp(&b.tier)
                    .then_with(|| b.score.cmp(&a.score))
                    .then_with(|| b.favorite.cmp(&a.favorite))
            });

            // An id scope is a question about ONE row, so other rows are not
            // part of the answer and must not ride along: a fill that asked for
            // account A should never receive account B's code as a consolation.
            if scoped {
                ranked.retain(|c| c.id == want_id);
            }

            // Expiry guard. A code with under MIN_TOTP_FILL_REMAINING_SECS left
            // dies on arrival at the site, and a rejected code reads as "my
            // authenticator is broken" rather than "you were too slow" — so it
            // is WITHHELD, never sent stale, and the caller gets `next_in`.
            // HOTP has no window: `expires_in` is null and the guard skips.
            let candidates: Vec<serde_json::Value> = ranked
                .iter()
                .take(MAX_TOTP_CANDIDATES)
                .map(|c| {
                    let fresh = c
                        .expires_in
                        .is_none_or(|s| s >= MIN_TOTP_FILL_REMAINING_SECS);
                    serde_json::json!({
                        "id": c.id,
                        "issuer": c.issuer,
                        "account": c.account,
                        "code": if fresh { serde_json::json!(c.code) } else { serde_json::Value::Null },
                        "expires_in": c.expires_in,
                        "next_in": if fresh { serde_json::Value::Null } else { serde_json::json!(c.expires_in.unwrap_or(0)) },
                        "rank": c.tier,
                        "score": c.score,
                        "is_dup": c.is_dup,
                        "verified": vault.is_verified(&c.id),
                        "source": c.source,
                        "last_filled": last_filled_ts(&c.id),
                    })
                })
                .collect();
            crate::security::access_log::log_event(
                "bridge-totp-lookup",
                &format!("{}:{}", q, candidates.len()),
            );
            Answer {
                reply: serde_json::json!({"ok": true, "candidates": candidates}),
                persist: false,
            }
        }
        // Extension-harvested favicon (hybrid engine layer 2): the browser
        // already loaded this icon, so no new network happens here — just
        // validate + file into the desktop disk cache. Unlocked-only,
        // rate-limited, never persisted to the vault (metadata cache).
        "cache_favicon" => {
            if !unlocked {
                return no("vault locked");
            }
            if !fill_rate_ok() {
                return no("fill rate limited");
            }
            let domain = req
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let data_b64 = req.get("data").and_then(|v| v.as_str()).unwrap_or("");
            if domain.is_empty() || data_b64.is_empty() {
                return no("domain and data required");
            }
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data_b64.trim())
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE.decode(data_b64.trim())
                })
                .unwrap_or_default();
            match crate::core::favicon::save_harvested_icon(&domain, &bytes) {
                Ok(saved) => Answer {
                    reply: serde_json::json!({"ok": true, "domain": saved}),
                    persist: false,
                },
                Err(e) => no(&e),
            }
        }
        "" => no("missing cmd"),
        // Popup "All items": metadata ONLY (no secrets) for browsing.
        // Secrets still travel exclusively via query/fill paths, so a
        // compromised popup sees titles — never passwords or TOTP seeds.
        // Covers every kind (Bitwarden vault browser); `fetch` below hands
        // out exactly ONE item's secrets on explicit user action.
        "list" => {
            if !unlocked {
                return no("vault locked");
            }
            let now = crate::models::current_timestamp();
            let pw_freq = login_pw_freq(vault);
            let logins: Vec<serde_json::Value> = vault
                .credentials
                .iter()
                .filter(|c| c.deleted_at.is_none())
                .map(|c| {
                    serde_json::json!({
                        "id": c.id,
                        "title": c.title,
                        "username": c.username,
                        "urls": c.urls,
                        "folder": c.folder,
                        "reprompt": c.reprompt,
                        "verified": vault.is_verified(&c.id),
                        "health": login_health_kind(&c.password, c.last_changed, now, pw_freq.get(c.password.as_str()).copied().unwrap_or(0)),
                        "has_totp": !c.totp_secret.is_empty(),
                    })
                })
                .collect();
            let cards: Vec<serde_json::Value> = vault
                .cards
                .iter()
                .filter(|k| k.deleted_at.is_none())
                .map(|k| {
                    let digits: String = k.card_number.chars().filter(|c| c.is_ascii_digit()).collect();
                    serde_json::json!({
                        "id": k.id,
                        "title": k.title,
                        "cardholder": k.cardholder_name,
                        "masked": if digits.len() > 4 { format!("•••• {}", &digits[digits.len() - 4..]) } else { "••••".to_string() },
                        "folder": k.folder,
                    })
                })
                .collect();
            let identities: Vec<serde_json::Value> = vault
                .identities
                .iter()
                .filter(|i| i.deleted_at.is_none())
                .map(|i| {
                    serde_json::json!({
                        "id": i.id,
                        "title": i.title,
                        "full_name": i.full_name,
                        "email": i.email,
                        "folder": i.folder,
                    })
                })
                .collect();
            let notes: Vec<serde_json::Value> = vault
                .notes
                .iter()
                .filter(|n| n.deleted_at.is_none())
                .map(|n| {
                    serde_json::json!({
                        "id": n.id,
                        "title": n.title,
                        "folder": n.folder,
                    })
                })
                .collect();
            crate::security::access_log::log_event(
                "bridge-list",
                &format!("{}+{}+{}+{}", logins.len(), cards.len(), identities.len(), notes.len()),
            );
            Answer {
                reply: serde_json::json!({"ok": true, "logins": logins, "cards": cards, "identities": identities, "notes": notes}),
                persist: false,
            }
        }
        // Fetch ONE item's fill secrets by (kind, id). Trashed never served.
        // This is what backs Fill/Copy on metadata rows — no vault dump.
        "fetch" => {
            if !unlocked {
                return no("vault locked");
            }
            let kind = req.get("kind").and_then(|k| k.as_i64()).unwrap_or(1) as i32;
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if id.is_empty() {
                return no("id required");
            }
            let entry: Option<serde_json::Value> = match kind {
                4 => vault.cards.iter().find(|k| k.id == id && k.deleted_at.is_none()).map(|k| {
                    serde_json::json!({
                        "id": k.id, "kind": 4, "title": k.title,
                        "cardholder": k.cardholder_name, "number": k.card_number,
                        "exp_month": k.exp_month, "exp_year": k.exp_year, "cvv": k.cvv,
                    })
                }),
                5 => vault.identities.iter().find(|i| i.id == id && i.deleted_at.is_none()).map(|i| {
                    serde_json::json!({
                        "id": i.id, "kind": 5, "title": i.title,
                        "full_name": i.full_name, "email": i.email,
                        "phone": i.phone, "address": i.address,
                    })
                }),
                3 => vault.notes.iter().find(|n| n.id == id && n.deleted_at.is_none()).map(|n| {
                    serde_json::json!({
                        "id": n.id, "kind": 3, "title": n.title, "content": n.content,
                    })
                }),
                _ => vault.credentials.iter().find(|c| c.id == id && c.deleted_at.is_none()).map(|c| {
                    serde_json::json!({
                        "id": c.id, "kind": 1, "title": c.title,
                        "username": c.username, "password": c.password,
                        "totp": live_totp(&c.totp_secret),
                        "urls": c.urls, "reprompt": c.reprompt,
                        "last_changed": c.last_changed,
                    })
                }),
            };
            match entry {
                Some(e) => {
                    // M11: `id` is caller-controlled text — log a truncated
                    // hash, never the raw string (narrative injection into a
                    // valid chain, e.g. "c1 — user confirmed verbally").
                    crate::security::access_log::log_event(
                        "bridge-fetch",
                        &format!("{kind}:{}", crate::security::access_log::short_hash(id)),
                    );
                    Answer { reply: serde_json::json!({"ok": true, "entry": e}), persist: false }
                }
                None => no("item not found"),
            }
        }
        // Smart-autofill: record a fill (audit sidecar only, no vault write).
        // M12: the id must resolve to a real, untrashed item (was blind
        // saturating_add per frame), rate-limited, and access-logged like
        // every other mutating command.
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
            let known = vault.credentials.iter().any(|c| c.id == id && c.deleted_at.is_none())
                || vault.cards.iter().any(|k| k.id == id && k.deleted_at.is_none())
                || vault.notes.iter().any(|n| n.id == id && n.deleted_at.is_none())
                || vault.identities.iter().any(|i| i.id == id && i.deleted_at.is_none())
                || vault.ssh_keys.iter().any(|s| s.id == id && s.deleted_at.is_none())
                || vault.licenses.iter().any(|l| l.id == id && l.deleted_at.is_none())
                || vault.passkeys.iter().any(|p| {
                    use base64::Engine as _;
                    p.deleted_at.is_none()
                        && (base64::engine::general_purpose::STANDARD.encode(&p.credential_id) == id
                            || p.credential_id.iter().map(|b| format!("{b:02x}")).collect::<String>() == id)
                })
                || vault.totp_accounts.iter().any(|t| t.id == id);
            if !known {
                return no("unknown id");
            }
            if !fill_rate_ok() {
                return no("fill rate limited");
            }
            crate::security::access_log::log_event("bridge-filled", &short_id(id));
            let mut st = read_ext_stats();
            let now = crate::models::current_timestamp();
            st["total_fills"] = serde_json::json!(st.get("total_fills").and_then(|n| n.as_u64()).unwrap_or(0).saturating_add(1));
            st["last_filled"][id] = serde_json::json!(now);
            let new_count = st.get("fill_counts").and_then(|m| m.get(id)).and_then(|n| n.as_u64()).unwrap_or(0).saturating_add(1);
            st["fill_counts"][id] = serde_json::json!(new_count);
            write_ext_stats(&st);
            // Hybrid verified badge: the crossing fill (count == N, not >=)
            // flips the sealed model flag with a single re-seal (persist).
            // set_verified refuses non-logins itself; the serve loop's
            // persist guard refuses decoy writes — in-memory only there.
            let mut persist = false;
            if crate::models::auto_verify_crossed(new_count, vault.is_verified(id))
                && vault.set_verified(id, true)
            {
                persist = true;
            }
            Answer {
                reply: serde_json::json!({"ok": true, "verified": vault.is_verified(id)}),
                persist,
            }
        }
        // M14: explicit "is this the working one?" mark, the user's own
        // verdict rather than an inference from fill counts. Backs the
        // `✅ Working` badge for BOTH logins and standalone 2FA accounts, so
        // the badge is never a one-way ratchet that only the 3rd fill can set.
        //
        // Gates mirror `filled` exactly: locked vault, live untrashed id
        // only, rate-limited, and access-logged with a truncated hash (the id
        // is caller-controlled text). `set_verified` re-checks membership and
        // sweeps stale marks itself, so a bad id cannot pollute verified_ids.
        // A no-op toggle (already in the requested state) returns WITHOUT
        // `persist` — re-sealing is the expensive part, and a page that spams
        // clicks must not be able to force a vault rewrite per call.
        "verify" => {
            if !unlocked {
                return no("vault locked");
            }
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("").trim();
            if id.is_empty() {
                return no("id required");
            }
            let on = req.get("on").and_then(|v| v.as_bool()).unwrap_or(true);
            let live = vault
                .credentials
                .iter()
                .any(|c| c.id == id && c.deleted_at.is_none())
                || vault.totp_accounts.iter().any(|t| t.id == id);
            if !live {
                return no("unknown id");
            }
            if !fill_rate_ok() {
                return no("verify rate limited");
            }
            crate::security::access_log::log_event("bridge-verify", &short_id(id));
            if vault.is_verified(id) == on {
                // Idempotent: report the truth, rewrite nothing.
                return Answer {
                    reply: serde_json::json!({"ok": true, "verified": on, "changed": false}),
                    persist: false,
                };
            }
            if !vault.set_verified(id, on) {
                return no("not a verifiable item");
            }
            Answer {
                reply: serde_json::json!({"ok": true, "verified": on, "changed": true}),
                persist: true,
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
                    "fill_counts": st.get("fill_counts").cloned().unwrap_or_else(|| serde_json::json!({})),
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
            // C6: strict registrable-domain equality — substring matching let
            // https://co/ overwrite a github.com credential. Single-label
            // domains (e.g. "co") never match.
            if dom.split('.').filter(|p| !p.is_empty()).count() < 2 {
                return no("url domain invalid");
            }
            let existing = vault.credentials.iter_mut().find(|c| {
                c.deleted_at.is_none()
                    && c.username.to_lowercase() == username.to_lowercase()
                    && (c.urls.iter().any(|u| url_domain(u) == dom)
                        || c.title.to_lowercase() == dom)
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
/// M4: fail-closed on arbitrary origins — an attacker with local exec must
/// not mint a valid manifest for `chrome-extension://malicious_id/`.
pub fn print_manifest(allowed_origin: &str) {
    if !valid_origin_format(allowed_origin.trim()) {
        eprintln!("refusing to mint manifest for invalid origin (want chrome-extension://<32-char-id>/)");
        return;
    }
    let path = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "phantom_vault.exe".to_string());
    println!("{}", manifest_json(allowed_origin.trim(), &path));
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
/// `{"total_fills":N,"last_filled":{"<id>":<unix_ts>},"fill_counts":{"<id>":N}}`.
/// Lives beside the vault so fill-audit + stats survive restarts without
/// touching the model.
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
    st["fill_counts"][id.trim()] = serde_json::json!(st.get("fill_counts").and_then(|m| m.get(id.trim())).and_then(|n| n.as_u64()).unwrap_or(0).saturating_add(1));
    write_ext_stats(&st);
}

/// Per-item usage for the desktop detail card: (fill count, last-fill ts).
/// Metadata only — safe to show beside secrets. Pure read.
pub(crate) fn fill_stats_for(id: &str) -> (u64, u64) {
    let st = read_ext_stats();
    let count = st.get("fill_counts").and_then(|m| m.get(id)).and_then(|n| n.as_u64()).unwrap_or(0);
    let last = st.get("last_filled").and_then(|m| m.get(id)).and_then(|n| n.as_u64()).unwrap_or(0);
    (count, last)
}

/// Per-login health kind for bridge entries (local signals only — breach
/// status needs the desktop audit and is omitted). Priority mirrors the
/// desktop kinds(): reused > weak > stale. Pure.
fn login_health_kind(password: &str, last_changed: u64, now: u64, freq: usize) -> &'static str {
    if freq > 1 {
        "reused"
    } else if crate::security::breach_check::is_weak(password) {
        "weak"
    } else if crate::models::is_stale(last_changed, now) {
        "stale"
    } else {
        ""
    }
}

/// Password reuse frequencies over live logins (empty passwords excluded —
/// blank shared fields are missing data, not reuse). Pure.
fn login_pw_freq(vault: &Vault) -> std::collections::HashMap<&str, usize> {
    let mut freq = std::collections::HashMap::new();
    for c in &vault.credentials {
        if c.deleted_at.is_none() && !c.password.is_empty() {
            *freq.entry(c.password.as_str()).or_insert(0) += 1;
        }
    }
    freq
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

/// Normalized lookup key: lowercase, scheme/path/port stripped, leading
/// `www.` dropped. Mirrors the extension's `pageBase()` closely enough that
/// both sides hash the same site to the same key. Pure.
fn norm_lookup_key(raw: &str) -> String {
    let h = raw.trim().to_lowercase();
    let h = h.rsplit("://").next().unwrap_or(&h);
    let h = h.split('/').next().unwrap_or(h);
    let h = h.split('?').next().unwrap_or(h);
    let h = h.split('#').next().unwrap_or(h);
    let h = h.split(':').next().unwrap_or(h);
    h.trim_start_matches("www.").trim().to_string()
}

/// Tokens carrying no identifying signal. Kept in the haystack but dropped
/// from scoring: otherwise a bare "com" would fully overlap the token "com" of
/// "instagram.com" and score a perfect, meaningless match.
const TOKEN_STOPWORDS: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co", "www", "web",
    "app", "apps", "login", "logins", "signin", "account", "accounts", "auth", "id", "my", "the",
    "authenticator", "otp", "2fa", "mfa",
];

/// Alphanumeric token set of a normalized key, minus stopwords. Pure.
fn token_set(raw: &str) -> std::collections::HashSet<String> {
    raw.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .filter(|t| !TOKEN_STOPWORDS.contains(&t.as_str()))
        .collect()
}

/// |A n B| / min(|A|,|B|): how completely the SHORTER, more specific side is
/// covered by the longer one.
///
/// The denominator is `min`, not `max` and not the union: "Instagram" ⊂
/// "instagram.com" is one identifying token inside two, and coverage is the
/// honest reading of that — the brand IS fully present in the site. `max`
/// scored it 0.5 (below the 0.6 bar) which handed a strong match a score of
/// zero; the union scored it 0.25, worse still. `min` is also immune to the
/// short-query pathology, because stopwords leave the short side empty.
/// Empty on either side scores 0.0. Pure.
fn token_overlap(a: &str, b: &str) -> f64 {
    let (ta, tb) = (token_set(a), token_set(b));
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let shared = ta.intersection(&tb).count();
    if shared == 0 {
        return 0.0;
    }
    shared as f64 / ta.len().min(tb.len()) as f64
}

/// A 2FA hub account scored against the queried site, built by
/// `score_totp_candidate` and ranked by `totp_lookup`.
///
/// Holds a *reference*, never the secret: the code is materialized here, in
/// the trusted process, and the secret is not a field so it cannot leak into
/// the JSON payload by accident.
/// One ranked TOTP answer, decoupled from which storage shape it came from.
///
/// Fields are owned rather than a `&TotpAccount` borrow because a lookup now
/// spans two shapes (a hub card, or a login row with an inline secret) and only
/// one of them is a real `TotpAccount`. Carrying just the identity + ranking
/// fields lets both feed the same sort, the same payload shape, and the same
/// picker.
struct TotpCandidate {
    id: String,
    issuer: String,
    account: String,
    /// 1 = issuer or registrable-domain exact, 2 = substring, 3 = tokens only.
    tier: u8,
    score: i64,
    is_dup: bool,
    favorite: bool,
    code: String,
    /// `None` = counter-based (HOTP): never expires, so no expiry guard.
    expires_in: Option<u64>,
    /// "hub" for a standalone 2FA card, "login" for an inline secret on a
    /// credential. Surfaced so the picker can say where the answer came from.
    source: &'static str,
}

/// Pure ranking: tier + score for one (issuer, account) pair against a site.
///
/// The old filter was `iss.contains(&q) || q.contains(&iss) || acc.contains(&q)`,
/// which is symmetric substring soup: querying `git` matched `GitHub`, and an
/// empty issuer matched every site in the vault because `x.contains("")` is
/// true. Both haystacks are now required non-empty and tiers are ordered
/// exact -> substring -> tokens so an exact issuer can never be outranked by a
/// lucky substring.
///
/// STRICTLY pure: no clock, no secret, no code. The three things that can
/// legitimately fail (does it match, how well, is the secret valid) are kept
/// apart on purpose — a code-generation failure must not change the ORDER of the
/// candidates, or a broken account would silently promote the next one.
fn score_totp_pair(
    issuer_raw: &str,
    account_raw: &str,
    q: &str,
    q_domain: &str,
) -> Option<(u8, i64)> {
    let issuer = norm_lookup_key(issuer_raw);
    let account = norm_lookup_key(account_raw);

    let issuer_exact = !issuer.is_empty() && issuer == q;
    let domain_exact = !issuer.is_empty() && url_domain(&issuer) == q_domain;
    let issuer_sub = !issuer.is_empty() && (issuer.contains(q) || q.contains(&issuer));
    // An account string containing the site is real evidence (user@github.com
    // on github.com) but weaker than the issuer naming it, so it shares the
    // bottom tier with a token-only match rather than outranking one.
    let acct_sub = !account.is_empty() && account.contains(q);
    let overlap = token_overlap(&issuer, q).max(token_overlap(&account, q));

    let tier = if issuer_exact || domain_exact {
        1u8
    } else if issuer_sub {
        2u8
    } else if acct_sub || overlap > 0.0 {
        3u8
    } else {
        return None;
    };

    let score = 100 * i64::from(issuer_exact)
        + 60 * i64::from(domain_exact)
        + 30 * i64::from(overlap >= 0.6);
    Some((tier, score))
}

/// Score one hub account against a site, or `None` when it isn't a match.
fn score_totp_candidate(
    acc: &crate::models::TotpAccount,
    q: &str,
    q_domain: &str,
    is_dup: bool,
    recently_filled: bool,
    trusted: bool,
) -> Option<TotpCandidate> {
    // `trusted` means the caller named this exact row, so text similarity is no
    // longer evidence of anything and must not be able to veto it. Only the
    // MATCH is waived - the code below is minted and guarded identically, so a
    // trusted row is not a second, looser code path. Tier 0 marks it unranked.
    let (tier, score) = match score_totp_pair(&acc.issuer, &acc.account_name, q, q_domain) {
        Some(ts) => ts,
        None if trusted => (0u8, 0i64),
        None => return None,
    };

    // B2: the per-account dispatcher honours algorithm/digits/period/otp_type.
    // `generate_live_code` hardcodes SHA1/6/30 and computes remaining against a
    // flat 30s window, so before this switch 8-digit, Steam, HOTP and
    // 60s-period accounts all served a WRONG code here - and a `period`-agnostic
    // `expires_in` would have lied to the freshness guard on top of that.
    let (code, remaining) = crate::totp_engine::generate_code_for_account(acc).ok()?;
    let expires_in = if remaining == u64::MAX {
        None
    } else {
        Some(remaining)
    };

    Some(TotpCandidate {
        id: acc.id.clone(),
        issuer: acc.issuer.clone(),
        account: acc.account_name.clone(),
        tier,
        score: score + 10 * i64::from(recently_filled),
        is_dup,
        favorite: acc.favorite,
        code,
        expires_in,
        source: "hub",
    })
}

/// Score a login row that carries an inline TOTP secret.
///
/// A credential's `totp_secret` is a bare base32 string with no per-account
/// algorithm/digits/period to honour, so it is projected onto a canonical
/// SHA1/6/30 TOTP account and pushed through `generate_code_for_account` — the
/// SAME dispatcher the hub uses. Deliberately not a second code path: that is
/// exactly how the pre-B2 bug (hardcoded window) survived in two places at
/// once. `title` plays the issuer role and `username` the account role, which is
/// the same signal the login dropdown ranks on.
///
/// Credential shape, not the site's login page, decides `issuer`: a row titled
/// "GitHub" is a far better brand token than its URL, and both are considered by
/// `score_totp_pair` anyway (url text is folded into the issuer string below).
fn score_credential_totp_candidate(
    cred: &crate::models::Credential,
    q: &str,
    q_domain: &str,
    is_dup: bool,
    recently_filled: bool,
    trusted: bool,
) -> Option<TotpCandidate> {
    let secret = cred.totp_secret.trim();
    if secret.is_empty() || cred.deleted_at.is_some() {
        return None;
    }
    // Issuer = the user's own label for the site, plus its URL text as a second
    // haystack (a row titled "Work email" on github.com still resolves).
    let url_text = cred.urls.first().map(|u| u.as_str()).unwrap_or("");
    let issuer_raw = format!("{} {}", cred.title, url_text);
    // Same `trusted` waiver as the hub scorer, and for the same reason: it drops
    // the MATCH requirement only. The live/secret checks above and the minting
    // below still run, so a trashed or secretless row stays unservable.
    let (tier, score) = match score_totp_pair(&issuer_raw, &cred.username, q, q_domain) {
        Some(ts) => ts,
        None if trusted => (0u8, 0i64),
        None => return None,
    };

    let acc = crate::models::TotpAccount {
        id: cred.id.clone(),
        account_name: cred.username.clone(),
        issuer: cred.title.clone(),
        secret: secret.to_string(),
        digits: 6,
        period: 30,
        algorithm: "SHA1".into(),
        otp_type: "totp".into(),
        counter: 0,
        favorite: cred.favorite,
    };
    let (code, remaining) = crate::totp_engine::generate_code_for_account(&acc).ok()?;
    let expires_in = if remaining == u64::MAX {
        None
    } else {
        Some(remaining)
    };

    Some(TotpCandidate {
        id: cred.id.clone(),
        issuer: cred.title.clone(),
        account: cred.username.clone(),
        tier,
        score: score + 10 * i64::from(recently_filled),
        is_dup,
        favorite: cred.favorite,
        code,
        expires_in,
        source: "login",
    })
}

/// Equivalent-domain clusters (Bitwarden-style): one account spans every
/// sibling (login on youtube.com matches a google.com credential).
/// Trailing `.*` members are ccTLD-prefix rules (`google.co.*`).
const EQUIV_CLUSTERS: &[&[&str]] = &[
    &["proton.me", "protonmail.com", "protonvpn.com", "protondrive.com"],
    &["google.com", "youtube.com", "gmail.com", "googlemail.com", "gstatic.com", "google.co.*"],
    &["facebook.com", "messenger.com", "instagram.com", "threads.net"],
    &["microsoft.com", "live.com", "office.com", "login.microsoftonline.com", "xbox.com", "outlook.com", "hotmail.com", "onedrive.com"],
    &["apple.com", "icloud.com"],
    &["amazon.com", "primevideo.com", "audible.com", "amazon.co.*"],
    &["sony.com", "playstation.com", "playstationnetwork.com"],
    &["yahoo.com", "aol.com"],
];

/// Subdomain prefixes stripped before matching (`account.google.com` → google).
const SUB_PREFIXES: &[&str] = &[
    "account", "accounts", "login", "auth", "myaccount", "my", "app", "www",
    "signin", "sso", "secure", "id", "mail",
];

/// Strip well-known login sub-prefixes (`account.google.com` → `google.com`).
pub(crate) fn strip_sub_prefixes(host: &str) -> String {
    let lower = host.to_lowercase();
    let mut parts: Vec<&str> = lower.split('.').filter(|p| !p.is_empty()).collect();
    while parts.len() > 2 && SUB_PREFIXES.contains(&parts[0]) {
        parts.remove(0);
    }
    parts.join(".")
}

fn member_hit(member: &str, domain: &str) -> bool {
    if let Some(prefix) = member.strip_suffix(".*") {
        domain == prefix || domain.starts_with(&format!("{prefix}."))
    } else {
        domain == member
            || domain.ends_with(&format!(".{member}"))
            || member.ends_with(&format!(".{domain}"))
    }
}

/// Brand-stem fallback: longest common first-label prefix (≥5 chars) shared
/// by a cluster (`protonvpn`/`proton` → `proton`). Pure — unit tested.
fn cluster_stem(members: &[&str]) -> Option<String> {
    let labels: Vec<&str> = members
        .iter()
        .map(|m| m.trim_end_matches(".*").split('.').next().unwrap_or(""))
        .collect();
    let first = labels.first().copied().unwrap_or("");
    let mut len = first.len();
    for l in &labels[1..] {
        len = first
            .chars()
            .zip(l.chars())
            .take_while(|(a, b)| a == b)
            .count()
            .min(len);
    }
    if len >= 5 {
        Some(first[..len].to_string())
    } else {
        None
    }
}

fn first_label(domain: &str) -> String {
    domain.split('.').next().unwrap_or("").to_string()
}

/// Expand one query host into equivalent match strings: itself, stripped
/// host + every multi-label suffix (ccTLD-safe: `google.co.uk` is tested,
/// not just the naive last-2 `co.uk`), cluster siblings, brand-stem hits.
pub(crate) fn expand_query(raw_q: &str) -> Vec<String> {
    let mut out = vec![raw_q.trim().to_lowercase()];
    // Full host with login prefixes stripped (scheme/path/port removed).
    let h = raw_q.trim().to_lowercase();
    let h = h.rsplit("://").next().unwrap_or(&h);
    let h = h.split('/').next().unwrap_or(h);
    let h = h.split(':').next().unwrap_or(h);
    let full = strip_sub_prefixes(h);
    // Candidate domains: full host + every suffix with 2+ labels.
    let labels: Vec<&str> = full.split('.').filter(|p| !p.is_empty()).collect();
    let mut cands = vec![full.clone()];
    for i in 1..labels.len() {
        if labels.len() - i >= 2 {
            cands.push(labels[i..].join("."));
        }
    }
    for c in &cands {
        if !c.is_empty() && !out.contains(c) {
            out.push(c.clone());
        }
    }
    for cluster in EQUIV_CLUSTERS {
        let direct = cluster
            .iter()
            .any(|m| cands.iter().any(|d| member_hit(m, d)));
        let tok = first_label(&full);
        let stem_hit = cluster_stem(cluster).map(|stem| {
            !tok.is_empty() && (tok == stem || tok.starts_with(&stem) || stem.starts_with(&tok))
        });
        if direct || stem_hit == Some(true) {
            for m in *cluster {
                let s = m.trim_end_matches(".*").to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    }
    out
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
    // L5: strict ID charset (matches valid_origin_format) — never write a
    // wildcard/placeholder manifest to HKCU.
    if !valid_origin_format(&origin) {
        return Err(VaultError::Sync(
            "allowed origin must look like chrome-extension://<32-lowercase-id>/".into(),
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
///
/// Trust boundary (C2+C3+C4): argv[1] origin is enforced against the
/// registered manifest; `unlocked` is re-derived every frame from the live
/// Hello token + idle/max lifetimes (lock deletes the token → host exits).
pub fn serve_cli() -> i32 {
    use secrecy::ExposeSecret;
    // Phase C: 60s idle TTL (HOST_IDLE_TTL_SECS) — one decrypted session
    // serves the burst, then exits. Bounds the plaintext window; next
    // query pays one fresh KDF.
    const MAX_SECS: u64 = 8 * 3600;
    let origin = std::env::args().nth(1).unwrap_or_default();
    if origin != "native-host" && !origin_allowed(&origin) {
        let frame = encode_frame(&err("origin not allowed"));
        let _ = std::io::stdout().write_all(&frame);
        let _ = std::io::stdout().flush();
        bridge_log("origin rejected");
        return 2;
    }
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
    // P1 (closed-app serving): a leftover Hello token file is NOT enough —
    // the desktop app must be alive (fresh heartbeat) or we serve nothing.
    // Checked BEFORE the backoff sleep + vault decrypt (no wasted Argon2id).
    if !desktop_alive() {
        bridge_log("refused: stale/missing heartbeat (app closed or locked)");
        emit_err("desktop app closed — open PhantomVault");
        return 2;
    }
    // H7: share the unlock throttle — an unthrottled second Argon2id path
    // defeats the UI backoff. Sleep the persisted delay before touching DPAPI.
    {
        let bp = crate::security::backoff::default_path();
        let fails = crate::security::backoff::read_failures(&bp);
        let wait = crate::security::backoff::delay_for_failures(fails);
        if wait > 0 {
            std::thread::sleep(std::time::Duration::from_secs(wait));
        }
    }
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
    let start = std::time::Instant::now();
    let mut last_active = std::time::Instant::now();
    // M1: watchdog — the loop blocks on stdin, so per-frame checks alone
    // leave the decrypted vault in heap indefinitely while idle. Poll every
    // 5 s: token deleted (app locked) / idle / max lifetime → hard exit.
    // INTERACTION (H14): this bounds ALL secret serving, including
    // reprompt-flagged entries the host still ships with the flag (the
    // one-time reauth-token flow stays the follow-up).
    let watch_start = start;
    let watch_last = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    ));
    let watch_last2 = watch_last.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let idle = now.saturating_sub(watch_last2.load(std::sync::atomic::Ordering::SeqCst));
        let total = watch_start.elapsed().as_secs();
        if !std::path::Path::new(HELLO_TOKEN_FILE).exists()
            || session_idle_expired(idle)
            || total > MAX_SECS
        {
            bridge_log("host watchdog expired/locked — exiting");
            std::process::exit(0);
        }
    });
    loop {
        // Live lock state: token deleted (app locked) / idle / max lifetime
        // → zeroize + exit instead of serving secrets indefinitely.
        let token_alive = std::path::Path::new(HELLO_TOKEN_FILE).exists();
        if !token_alive
            || session_idle_expired(last_active.elapsed().as_secs())
            || start.elapsed().as_secs() > MAX_SECS
        {
            use zeroize::Zeroize;
            let mut m = master.expose_secret().clone();
            m.zeroize();
            bridge_log("host session expired/locked — exiting");
            break;
        }
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
        // Cover integrity (H9): a coerced session must never write into the
        // decoy — refuse every persisting command, not just save_login
        // (assert also has persist:true via the sign-count bump).
        if serving_decoy && req.get("cmd").and_then(|c| c.as_str()).unwrap_or("") == "save_login" {
            let frame = encode_frame(&err("save refused"));
            if output.write_all(&frame).and(output.flush()).is_err() {
                break;
            }
            continue;
        }
        let unlocked = bridge_unlocked();
        // P1: app closed/locked mid-session (heartbeat went stale while we
        // idled) — kill the session instead of serving on a dead token.
        if !desktop_alive() {
            bridge_log("host session ended: heartbeat stale (app closed/locked)");
            break;
        }
        let ans = answer(&mut vault, unlocked, &req);
        last_active = std::time::Instant::now();
        watch_last.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            std::sync::atomic::Ordering::SeqCst,
        );
        // H9: decoy cover must never persist (save_login early-returns
        // above; assert's sign-count bump is caught here).
        if persist_refused(serving_decoy, ans.persist) {
            let frame = encode_frame(&err("save refused"));
            let _ = output.write_all(&frame);
            let _ = output.flush();
            continue;
        }
        if ans.persist {
            // M13: brake before the full re-seal.
            if !save_rate_ok() {
                let frame = encode_frame(&err("save rate limited"));
                let _ = output.write_all(&frame);
                let _ = output.flush();
                continue;
            }
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

    // Rate-budget tests consume process-global limiter state, so every test
    // that touches a limiter (directly or via filled()/assert) serializes
    // here AND resets its budget first. Lock order: sidecar_guard, then this.
    static RATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    fn fill_counts_and_verified_propagate() {
        // Distinctive id: the CWD sidecar is shared with other tests running
        // in parallel — only assert on keys this test owns, under the guard.
        let _g = sidecar_guard();
        // Rate budget is process-global: reset + serialize so brake-test
        // consumption (120/min) can never reject these small-count fills.
        let _rg = RATE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_fill_rate();
        let snap = snap_sidecar();
        reset_test_id("verify-count-id");
        let mut v = vault_with_login();
        v.credentials[0].id = "verify-count-id".into();
        assert!(v.set_verified("verify-count-id", true));
        // Query entries carry the verified flag (popup ✅ source).
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "query", "app": "git"}));
        assert_eq!(r.reply["entries"][0]["verified"], true);
        // List metadata carries it too (All-items rows).
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "list"}));
        let logins = r.reply["logins"].as_array().unwrap();
        assert_eq!(logins.iter().find(|e| e["id"] == "verify-count-id").unwrap()["verified"], true);
        // Two fills → count 2; helper agrees.
        for _ in 0..2 {
            let r = answer(&mut v, true, &serde_json::json!({"cmd": "filled", "id": "verify-count-id"}));
            assert_eq!(r.reply["ok"], true);
        }
        let (n, last) = fill_stats_for("verify-count-id");
        assert_eq!(n, 2);
        assert!(last > 0);
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "stats"}));
        assert_eq!(r.reply["fill_counts"]["verify-count-id"], 2);
        restore_sidecar(snap);
    }

    // Sidecar snapshot/restore: the CWD file is shared with parallel tests
    // AND the developer's real stats — never leave test keys behind, never
    // wipe real data with remove_file.
    static SIDECAR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // Hold across a whole fill sequence: read-modify-write on one shared
    // file means per-call locking still loses counts to interleaved tests.
    fn sidecar_guard() -> std::sync::MutexGuard<'static, ()> {
        SIDECAR_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn snap_sidecar() -> Option<Vec<u8>> {
        std::fs::read(EXT_STATS_FILE).ok()
    }
    fn restore_sidecar(snap: Option<Vec<u8>>) {
        match snap {
            Some(b) => {
                let _ = std::fs::write(EXT_STATS_FILE, b);
            }
            None => {
                let _ = std::fs::remove_file(EXT_STATS_FILE);
            }
        }
    }
    // Drop one id's keys (stale from a crashed run) while holding the guard.
    fn reset_test_id(id: &str) {
        let mut st = read_ext_stats();
        if let Some(m) = st.get_mut("last_filled").and_then(|v| v.as_object_mut()) {
            m.remove(id);
        }
        if let Some(m) = st.get_mut("fill_counts").and_then(|v| v.as_object_mut()) {
            m.remove(id);
        }
        write_ext_stats(&st);
    }
    // Caller MUST hold sidecar_guard() across sequences (see above).
    fn filled(v: &mut Vault, id: &str) -> Answer {
        answer(&mut *v, true, &serde_json::json!({"cmd": "filled", "id": id}))
    }

    #[test]
    fn auto_verify_crossing_at_three() {
        let _g = sidecar_guard();
        let _rg = RATE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_fill_rate();
        let snap = snap_sidecar();
        reset_test_id("auto-v-id");
        let mut v = vault_with_login();
        v.credentials[0].id = "auto-v-id".into();
        // Fills 1–2: sidecar only, no model touch, no re-seal.
        for n in 1..crate::models::AUTO_VERIFY_FILLS {
            let r = filled(&mut v, "auto-v-id");
            assert_eq!(r.reply["ok"], true);
            assert_eq!(r.reply["verified"], false);
            assert!(!r.persist, "fill {n} must not re-seal");
            assert!(!v.is_verified("auto-v-id"));
        }
        // Crossing fill: flips the sealed flag, single re-seal.
        let r = filled(&mut v, "auto-v-id");
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["verified"], true);
        assert!(r.persist, "crossing fill must re-seal once");
        assert!(v.is_verified("auto-v-id"));
        restore_sidecar(snap);
    }

    #[test]
    fn no_reseal_past_threshold() {
        let _g = sidecar_guard();
        let _rg = RATE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_fill_rate();
        let snap = snap_sidecar();
        reset_test_id("auto-v-past");
        let mut v = vault_with_login();
        v.credentials[0].id = "auto-v-past".into();
        for _ in 0..crate::models::AUTO_VERIFY_FILLS {
            let _ = filled(&mut v, "auto-v-past");
        }
        assert!(v.is_verified("auto-v-past"));
        // 4th, 5th… fills: counts still accrue, model untouched.
        for _ in 0..2 {
            let r = filled(&mut v, "auto-v-past");
            assert_eq!(r.reply["ok"], true);
            assert!(!r.persist, "post-threshold fills must not re-seal");
        }
        let (n, _) = fill_stats_for("auto-v-past");
        assert_eq!(n, crate::models::AUTO_VERIFY_FILLS + 2);
        restore_sidecar(snap);
    }

    #[test]
    fn manual_unverify_suppresses_reverify() {
        let _g = sidecar_guard();
        let _rg = RATE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_fill_rate();
        let snap = snap_sidecar();
        reset_test_id("auto-v-man");
        let mut v = vault_with_login();
        v.credentials[0].id = "auto-v-man".into();
        // Manually verified BEFORE any fill: crossing never fires (already on).
        assert!(v.set_verified("auto-v-man", true));
        for _ in 0..crate::models::AUTO_VERIFY_FILLS {
            let r = filled(&mut v, "auto-v-man");
            assert!(!r.persist, "pre-verified item must not re-seal");
        }
        // Manual un-verify at count 3, then fill 4 (!= 3): stays off.
        assert!(v.set_verified("auto-v-man", false));
        let r = filled(&mut v, "auto-v-man");
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["verified"], false);
        assert!(!r.persist, "manual un-verify must not be fought");
        assert!(!v.is_verified("auto-v-man"));
        restore_sidecar(snap);
    }

    #[test]
    fn non_login_never_auto_verifies() {
        use crate::models::PaymentCard;
        let _g = sidecar_guard();
        let _rg = RATE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_fill_rate();
        let snap = snap_sidecar();
        reset_test_id("auto-v-card");
        let mut v = Vault::new();
        v.cards.push(PaymentCard {
            id: "auto-v-card".into(),
            title: "Card".into(),
            cardholder_name: "A".into(),
            card_number: "4111".into(),
            exp_month: "01".into(),
            exp_year: "30".into(),
            cvv: "123".into(),
            folder: String::new(),
            notes: String::new(),
            travel_safe: false,
            favorite: false,
            deleted_at: None,
        });
        for _ in 0..crate::models::AUTO_VERIFY_FILLS {
            let r = filled(&mut v, "auto-v-card");
            assert_eq!(r.reply["ok"], true);
            assert!(!r.persist, "cards must never flip verified_ids");
        }
        assert!(v.verified_ids.is_empty());
        restore_sidecar(snap);
    }

    #[test]
    fn totp_fill_stamps_sidecar_and_auto_verifies_at_three() {
        use crate::models::TotpAccount;
        let _g = sidecar_guard();
        let _rg = RATE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_fill_rate();
        let snap = snap_sidecar();
        reset_test_id("totp-v-1");
        let mut v = Vault::new();
        v.totp_accounts.push(TotpAccount {
            id: "totp-v-1".into(),
            account_name: "u".into(),
            issuer: "example.com".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        });
        // A hub account is a fillable item: `filled` accepts its id and stamps
        // the sidecar, which is what feeds the ranking's recently-used bonus
        // WITHOUT adding a field to the vault schema.
        for _ in 1..crate::models::AUTO_VERIFY_FILLS {
            let r = filled(&mut v, "totp-v-1");
            assert_eq!(r.reply["ok"], true);
            assert_eq!(r.reply["verified"], false, "not yet at the threshold");
            assert!(!r.persist);
        }
        // Third fill crosses the threshold and seals, exactly like a login.
        let r = filled(&mut v, "totp-v-1");
        assert_eq!(r.reply["verified"], true);
        assert!(r.persist, "crossing fill must re-seal the vault");
        assert!(v.is_verified("totp-v-1"));
        // The badge now rides the ranked lookup payload.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "totp_lookup", "app": "example.com"}));
        assert_eq!(r.reply["candidates"][0]["verified"], true);
        // Manual un-verify is respected on the next fill.
        assert!(v.set_verified("totp-v-1", false));
        let r = filled(&mut v, "totp-v-1");
        assert_eq!(r.reply["verified"], false);
        assert!(!v.is_verified("totp-v-1"));
        restore_sidecar(snap);
    }

    #[test]
    fn totp_lookup_ranks_login_inline_secrets_alongside_hub_cards() {
        let mut v = vault_with_login();
        // The case the blind `PV_QUERY.find(x => x.totp)` fallback used to cover:
        // TOTP living on the LOGIN row, with no standalone hub card anywhere.
        v.credentials[0].totp_secret = "JBSWY3DPEHPK3PXP".into();
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "github.com"}),
        );
        assert_eq!(r.reply["ok"], true);
        let cands = r.reply["candidates"].as_array().unwrap();
        assert_eq!(cands.len(), 1, "the inline secret must be served");
        assert_eq!(cands[0]["id"], "c1");
        assert_eq!(cands[0]["source"], "login");
        assert_eq!(cands[0]["issuer"], "GitHub");
        assert_eq!(cands[0]["account"], "octo");
        assert_eq!(cands[0]["is_dup"], false);
        // A live 6-digit SHA1/30 code — or, in the last seconds of the window,
        // correctly withheld. Asserting the shape rather than unwrapping keeps
        // this test off the wall clock (see the hub-lookup test above).
        if let Some(code) = cands[0]["code"].as_str() {
            assert_eq!(code.len(), 6, "inline secret must produce a 6-digit code");
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
        } else {
            assert!(cands[0]["next_in"].as_u64().unwrap() < 30);
        }
        // Never a secret.
        assert!(!r.reply.to_string().to_lowercase().contains("secret"));
    }

    #[test]
    fn totp_lookup_flags_a_collision_that_spans_storage_shapes() {
        use crate::models::TotpAccount;
        let mut v = vault_with_login();
        // Same real account, stored twice: once inline on the login row, once as
        // a hub card, with the same issuer and the same account name.
        v.credentials[0].totp_secret = "JBSWY3DPEHPK3PXP".into();
        v.totp_accounts.push(TotpAccount {
            id: "t-dup".into(),
            account_name: "octo".into(),
            issuer: "GitHub".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        });
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "github.com"}),
        );
        let cands = r.reply["candidates"].as_array().unwrap();
        assert_eq!(cands.len(), 2, "both shapes must be offered");
        // THE point of this test: dup detection runs over the union, so neither
        // half looks unique on its own. Checking per-collection would flag
        // neither and auto-fill an arbitrary one of the pair.
        for c in cands {
            assert_eq!(c["is_dup"], true, "cross-shape collision must be flagged");
        }
        let mut sources: Vec<&str> = cands
            .iter()
            .map(|c| c["source"].as_str().unwrap())
            .collect();
        sources.sort_unstable();
        assert_eq!(sources, vec!["hub", "login"]);
    }

    /// The one invariant every `totp_lookup` shape must keep: a payload carries a
    /// rendered code and metadata, never the secret it came from.
    fn cands_never_carry_secrets(cands: &serde_json::Value) -> bool {
        let arr = cands.as_array().unwrap();
        arr.iter().all(|c| c.get("secret").is_none()) && {
            let body = cands.to_string();
            !body.contains("JBSWY3DPEHPK3PXP") && !body.contains("GEZDGNBVGY3TQOJQ")
        }
    }

    #[test]
    fn totp_lookup_id_scope_trusts_a_row_the_scorer_cannot_match() {
        let mut v = vault_with_login();
        // The exact coverage case the old fallback used to cover: a login whose
        // title says nothing about the site and which carries NO url, so the
        // issuer/domain scorer returns None for it. The fill path still knows
        // which row it means, so it must be served.
        v.credentials[0].title = "Personal".into();
        v.credentials[0].urls = Vec::new();
        v.credentials[0].totp_secret = "JBSWY3DPEHPK3PXP".into();
        let open = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "example.com"}),
        );
        assert!(
            open.reply["candidates"].as_array().unwrap().is_empty(),
            "precondition: the scorer cannot see this row"
        );
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "example.com", "id": "c1"}),
        );
        assert_eq!(r.reply["ok"], true);
        let cands = r.reply["candidates"].as_array().unwrap();
        assert_eq!(cands.len(), 1, "the named row must be served");
        assert_eq!(cands[0]["id"], "c1");
        // Still a live, guarded code minted here — not a replay, not a secret.
        if let Some(code) = cands[0]["code"].as_str() {
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
        } else {
            assert!(cands[0]["next_in"].as_u64().unwrap() < 30);
        }
        assert!(!r.reply.to_string().contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn totp_lookup_id_scope_returns_that_row_only() {
        use crate::models::TotpAccount;
        let mut v = vault_with_login();
        v.credentials[0].totp_secret = "JBSWY3DPEHPK3PXP".into();
        v.credentials.push(test_cred("c2", "second", "GEZDGNBVGY3TQOJQ", false));
        v.totp_accounts.push(TotpAccount {
            id: "t1".into(),
            account_name: "octo".into(),
            issuer: "GitHub".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        });
        // Unscoped, this site offers three rows. Scoped to one, the answer is
        // about that row alone: an id is a question about a single account, so
        // its neighbours must never ride along as a consolation — that is how a
        // wrong account's code would reach a field that asked for a specific one.
        for (id, expected) in [("t1", 1), ("c2", 1)] {
            let r = answer(
                &mut v,
                true,
                &serde_json::json!({"cmd": "totp_lookup", "app": "github.com", "id": id}),
            );
            let cands = r.reply["candidates"].as_array().unwrap();
            assert_eq!(cands.len(), expected, "scope to {id} must return only it");
            assert_eq!(cands[0]["id"], id);
        }
        // An id that exists but carries no TOTP must not be served, and must not
        // drag a different row in to fill the gap.
        v.credentials.push(test_cred("c3", "nosecret", "", false));
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "github.com", "id": "c3"}),
        );
        assert!(
            r.reply["candidates"].as_array().unwrap().is_empty(),
            "a row without a secret must never serve a code"
        );
        // A trashed row is not a match either.
        v.credentials.push(test_cred("c4", "gone", "GEZDGNBVGY3TQOJQ", true));
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "github.com", "id": "c4"}),
        );
        assert!(
            r.reply["candidates"].as_array().unwrap().is_empty(),
            "a trashed row must never serve a code"
        );
        // Unknown id: empty, and still `ok` so the caller can tell "not here"
        // from "vault locked".
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "github.com", "id": "nope"}),
        );
        assert_eq!(r.reply["ok"], true);
        assert!(r.reply["candidates"].as_array().unwrap().is_empty());
    }

    #[test]
    fn totp_lookup_id_scope_still_honours_lock_and_never_leaks_a_secret() {
        let mut v = vault_with_login();
        v.credentials[0].totp_secret = "JBSWY3DPEHPK3PXP".into();
        // The id scope must not become a way around the unlocked gate.
        let locked = answer(
            &mut v,
            false,
            &serde_json::json!({"cmd": "totp_lookup", "app": "github.com", "id": "c1"}),
        );
        assert_eq!(locked.reply["ok"], false);
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "github.com", "id": "c1"}),
        );
        let body = r.reply.to_string();
        assert!(!body.contains("JBSWY3DPEHPK3PXP"), "no secret may ride along");
        assert!(cands_never_carry_secrets(&r.reply["candidates"]));
    }

    #[test]
    fn totp_lookup_skips_trashed_and_secretless_logins() {
        let mut v = vault_with_login();
        v.credentials[0].totp_secret = "JBSWY3DPEHPK3PXP".into();
        // An unparseable secret must not sink the whole lookup, and must not
        // appear as a candidate with a null code pretending to be a withheld
        // fresh one (indistinguishable from the real expiry guard).
        v.credentials
            .push(test_cred("c2", "other", "not-base32!!", false));
        // A trashed row must never be offered a live code.
        v.credentials
            .push(test_cred("c3", "gone", "JBSWY3DPEHPK3PXP", true));
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "github.com"}),
        );
        let cands = r.reply["candidates"].as_array().unwrap();
        let ids: Vec<&str> = cands.iter().map(|c| c["id"].as_str().unwrap()).collect();
        assert!(
            ids.contains(&"c1"),
            "the good row must still serve: {ids:?}"
        );
        assert!(!ids.contains(&"c3"), "a trashed row must never be offered");
        assert!(
            !ids.contains(&"c2"),
            "an unusable secret must not be offered: {ids:?}"
        );
    }

    /// A GitHub-shaped login row. `Credential` implements `Drop`, so struct
    /// update syntax (`..base`) cannot be used to build these; a helper is the
    /// only way to keep the literals from drifting apart.
    fn test_cred(id: &str, user: &str, secret: &str, trashed: bool) -> Credential {
        Credential {
            id: id.into(),
            title: "GitHub".into(),
            username: user.into(),
            password: "pw".into(),
            totp_secret: secret.into(),
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
            deleted_at: trashed.then(crate::models::current_timestamp),
        }
    }

    #[test]
    fn verify_cmd_toggles_login_and_totp_and_gates_bad_ids() {
        use crate::models::TotpAccount;
        let _g = sidecar_guard();
        let snap = snap_sidecar();
        reset_test_id("pv-totp-v");
        let mut v = vault_with_login();
        v.credentials[0].id = "pv-login-v".into();
        v.totp_accounts.push(TotpAccount {
            id: "pv-totp-v".into(),
            account_name: "u".into(),
            issuer: "example.com".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        });
        let call = |v: &mut Vault, id: &str, on: bool| {
            answer(
                v,
                true,
                &serde_json::json!({"cmd": "verify", "id": id, "on": on}),
            )
        };

        // Login: user marks working, badge becomes computable.
        let r = call(&mut v, "pv-login-v", true);
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["verified"], true);
        assert_eq!(r.reply["changed"], true);
        assert!(r.persist, "a real state change must re-seal");
        assert!(v.is_verified("pv-login-v"));
        // Login: un-marking is equally first-class.
        let r = call(&mut v, "pv-login-v", false);
        assert_eq!(r.reply["verified"], false);
        assert!(r.persist);
        assert!(!v.is_verified("pv-login-v"));

        // Standalone 2FA account: same door, same gates.
        let r = call(&mut v, "pv-totp-v", true);
        assert_eq!(r.reply["verified"], true);
        assert!(r.persist);
        assert!(v.is_verified("pv-totp-v"));
        // The badge rides the ranked lookup payload, computed not hardcoded.
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "example.com"}),
        );
        assert_eq!(r.reply["candidates"][0]["verified"], true);
        // Un-mark, and confirm the payload follows it back down.
        call(&mut v, "pv-totp-v", false);
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "totp_lookup", "app": "example.com"}),
        );
        assert_eq!(r.reply["candidates"][0]["verified"], false);

        // No-op toggles must not rewrite the vault (spam brake).
        call(&mut v, "pv-totp-v", false);
        let r = call(&mut v, "pv-totp-v", false);
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["changed"], false);
        assert!(!r.persist, "idempotent verify must not re-seal");

        // Locked vault refuses outright.
        let r = answer(
            &mut v,
            false,
            &serde_json::json!({"cmd": "verify", "id": "pv-totp-v", "on": true}),
        );
        assert_eq!(r.reply["ok"], false);
        assert!(!v.is_verified("pv-totp-v"));
        // Unknown and empty ids cannot pollute verified_ids.
        let r = call(&mut v, "ghost", true);
        assert_eq!(r.reply["ok"], false);
        assert!(v.verified_ids.is_empty());
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "verify", "id": "  ", "on": true}),
        );
        assert_eq!(r.reply["ok"], false);
        // Trashed logins are not verifiable through the bridge.
        v.credentials[0].deleted_at = Some(crate::models::current_timestamp());
        let r = call(&mut v, "pv-login-v", true);
        assert_eq!(r.reply["ok"], false);
        assert!(v.verified_ids.is_empty());
        restore_sidecar(snap);
    }

    #[test]
    fn persist_refused_matrix() {
        assert!(!persist_refused(false, false));
        assert!(!persist_refused(false, true));
        assert!(!persist_refused(true, false));
        assert!(persist_refused(true, true));
    }

    #[test]
    fn cache_favicon_rejects_without_touching_disk() {
        fn cmd(v: &mut Vault, unlocked: bool, domain: &str, data: &str) -> Answer {
            answer(
                &mut *v,
                unlocked,
                &serde_json::json!({"cmd": "cache_favicon", "domain": domain, "data": data}),
            )
        }
        let mut v = Vault::new();
        // Locked ⇒ deny before validation.
        let r = cmd(&mut v, false, "x.com", "aGk=");
        assert_eq!(r.reply["ok"], false);
        // Missing fields.
        assert_eq!(cmd(&mut v, true, "", "aGk=").reply["ok"], false);
        // Traversal / bad domains rejected by the sanitizer (no disk).
        let long = "a".repeat(200);
        for evil in ["../../x", "..\\x", "a/b.com", "", long.as_str()] {
            let r = cmd(&mut v, true, evil, "aGk=");
            assert_eq!(r.reply["ok"], false, "must reject {evil:?}");
        }
        // Oversize payload (>64KB decoded) rejected.
        let big = "A".repeat((64 * 1024 + 1) / 3 * 4 + 4);
        let r = cmd(&mut v, true, "big.com", &big);
        assert_eq!(r.reply["ok"], false);
        // Corrupt bytes ("hello") fail decode validation.
        use base64::Engine as _;
        let hello = base64::engine::general_purpose::STANDARD.encode("hello");
        let r = cmd(&mut v, true, "fine.com", &hello);
        assert_eq!(r.reply["ok"], false);
        assert!(!r.persist);
    }

    #[test]
    fn totp_lookup_serves_hub_codes_not_secrets() {
        use crate::models::TotpAccount;
        let card = |id: &str, issuer: &str, name: &str| TotpAccount {
            id: id.into(),
            account_name: name.into(),
            issuer: issuer.into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        };
        let mut v = Vault::new();
        v.totp_accounts.push(card("t1", "Instagram", "user@example.com"));
        // Issuer match (case-insensitive): live code, never the secret.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "totp_lookup", "app": "instagram.com"}));
        assert_eq!(r.reply["ok"], true);
        assert!(!r.persist);
        let cand = r.reply["candidates"].as_array().unwrap();
        assert_eq!(cand.len(), 1);
        assert_eq!(cand[0]["account"], "user@example.com");
        assert_eq!(cand[0]["id"], "t1");
        // Contract, not a snapshot of the wall clock: a lookup landing in the
        // last MIN_TOTP_FILL_REMAINING_SECS of the window MUST withhold the code,
        // so unwrapping `code` here made this test fail ~10% of all runs (3s of
        // every 30s) depending on nothing but the phase it started in.
        // Deterministic expiry coverage lives in the guard test below; here we
        // only assert the payload never lies about a code it withheld.
        match cand[0]["code"].as_str() {
            Some(code) => {
                assert_eq!(code.len(), 6);
                assert!(code.bytes().all(|b| b.is_ascii_digit()));
                assert!(cand[0]["expires_in"].as_u64().unwrap() >= MIN_TOTP_FILL_REMAINING_SECS);
                assert_eq!(cand[0]["next_in"], serde_json::Value::Null);
            }
            None => {
                let wait = cand[0]["next_in"].as_u64().unwrap();
                assert!(wait < 30, "next_in must be a short wait, got {wait}");
            }
        }
        // Invariant, now on the ranked shape: no secret may ride along.
        assert!(cand[0].get("secret").is_none());
        // "Instagram" vs site "instagram.com" is a brand-inside-domain
        // substring, NOT tier 1: tier 1 needs the issuer string itself to
        // equal the query, or its registrable domain to. That is the common
        // real shape, so it must still clear the +60 domain bonus via score.
        assert_eq!(cand[0]["rank"], 2);
        assert!(cand[0]["score"].as_i64().unwrap() >= 30);
        assert_eq!(cand[0]["is_dup"], false);
        // A lone card is never flagged; the picker relies on that to allow
        // hands-free fill.
        assert_eq!(cand[0]["verified"], false);
        // Time-based accounts always carry a relative countdown, never an
        // absolute timestamp: the extension's clock carries a manual offset
        // and an absolute epoch would desync its countdown.
        let exp = cand[0]["expires_in"].as_u64().unwrap();
        assert!((1..=30).contains(&exp), "expires_in in 1..=30, got {exp}");
        // `next_in` is the mirror of the guard, not a constant: it is non-null
        // exactly when the code was withheld. Asserting it null unconditionally
        // contradicted `expires_in in 1..=30` for the 1..=2 case, so this test
        // failed whenever it started in the last 2s of a 30s window.
        if exp >= MIN_TOTP_FILL_REMAINING_SECS {
            assert!(
                cand[0]["code"].is_string(),
                "a fresh window must serve a code"
            );
            assert!(cand[0]["next_in"].is_null(), "a served code needs no wait");
        } else {
            assert!(
                cand[0]["code"].is_null(),
                "a dying window must withhold the code"
            );
            assert_eq!(
                cand[0]["next_in"],
                serde_json::json!(exp),
                "wait == what is left"
            );
        }

        // Duplicate (issuer, account) pair ⇒ BOTH members flagged, so the
        // extension refuses to auto-pick between them.
        v.totp_accounts.push(card("t2", "Instagram", "user@example.com"));
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "totp_lookup", "app": "instagram.com"}));
        let cand = r.reply["candidates"].as_array().unwrap();
        assert_eq!(cand.len(), 2);
        assert!(cand.iter().all(|c| c["is_dup"] == true));

        // Empty issuer must NOT match every site (the old `contains("")`
        // symmetry bug), and a short query must not fuzzy-match a longer
        // issuer when the tiers say otherwise.
        let mut v2 = Vault::new();
        v2.totp_accounts.push(card("e1", "", "someone@example.com"));
        let r = answer(&mut v2, true, &serde_json::json!({"cmd": "totp_lookup", "app": "example.com"}));
        let cand = r.reply["candidates"].as_array().unwrap();
        assert_eq!(cand.len(), 1);
        assert_eq!(cand[0]["rank"], 3, "token-only match, never tier 1");

        // HOTP has no expiry window: expires_in null, guard skipped, code sent.
        let mut v3 = Vault::new();
        let mut h = card("h1", "GitHub", "octo");
        h.otp_type = "hotp".into();
        h.counter = 5;
        v3.totp_accounts.push(h);
        let r = answer(&mut v3, true, &serde_json::json!({"cmd": "totp_lookup", "app": "github.com"}));
        let cand = r.reply["candidates"].as_array().unwrap();
        assert_eq!(cand.len(), 1);
        assert!(cand[0]["expires_in"].is_null());
        assert!(cand[0]["code"].as_str().unwrap().len() == 6);

        // Unknown domain ⇒ ok with empty list; missing/locked ⇒ deny.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "totp_lookup", "app": "nope.invalid"}));
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["candidates"].as_array().unwrap().len(), 0);
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "totp_lookup"}));
        assert_eq!(r.reply["ok"], false);
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "totp_lookup", "app": "instagram.com"}));
        assert_eq!(r.reply["ok"], false);
    }

    #[test]
    fn totp_lookup_expiry_guard_withholds_dying_codes() {
        use crate::models::TotpAccount;
        // A 2s window: the code is inside the guard almost always, and when it
        // is, the bridge must withhold it rather than ship something that dies
        // mid-typing. Asserted on BOTH branches so the test is meaningful
        // whichever side of the rollover it runs on.
        let mut v = Vault::new();
        v.totp_accounts.push(TotpAccount {
            id: "g1".into(),
            account_name: "u".into(),
            issuer: "example.com".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 2,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        });
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "totp_lookup", "app": "example.com"}));
        let c = &r.reply["candidates"][0];
        let exp = c["expires_in"].as_u64().unwrap();
        if exp >= MIN_TOTP_FILL_REMAINING_SECS {
            assert!(c["code"].is_string(), "fresh enough to ship");
            assert!(c["next_in"].is_null());
        } else {
            assert!(c["code"].is_null(), "expiring code must be withheld");
            assert_eq!(c["next_in"].as_u64(), Some(exp));
        }
        // Either way the secret never rides along.
        assert!(c.get("secret").is_none());
    }

    #[test]
    fn totp_lookup_ranking_prefers_exact_issuer_over_substring() {
        use crate::models::TotpAccount;
        let card = |id: &str, issuer: &str| TotpAccount {
            id: id.into(),
            account_name: format!("{id}@example.com"),
            issuer: issuer.into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        };
        let mut v = Vault::new();
        // Vault order deliberately puts the WEAKER match first: ranking, not
        // storage order, must decide. (This is the bug the old
        // `list[0]`-on-every-consumer path had.)
        v.totp_accounts.push(card("sub", "GitHub Extra"));
        v.totp_accounts.push(card("exact", "github.com"));
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "totp_lookup", "app": "github.com"}));
        let cand = r.reply["candidates"].as_array().unwrap();
        assert!(cand.len() >= 2, "both should match: {cand:?}");
        assert_eq!(cand[0]["id"], "exact", "exact issuer outranks substring");
        assert_eq!(cand[0]["rank"], 1);
    }

    #[test]
    fn totp_accounts_can_be_marked_verified() {
        use crate::models::TotpAccount;
        let mut v = Vault::new();
        v.totp_accounts.push(TotpAccount {
            id: "t9".into(),
            account_name: "u".into(),
            issuer: "example.com".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            otp_type: "totp".into(),
            counter: 0,
            favorite: false,
        });
        assert!(!v.is_verified("t9"));
        assert!(v.set_verified("t9", true));
        assert!(v.is_verified("t9"));
        // Still refuses ids that name nothing, so a typo can't pollute.
        assert!(!v.set_verified("ghost", true));
        // The badge rides the ranked payload.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "totp_lookup", "app": "example.com"}));
        assert_eq!(r.reply["candidates"][0]["verified"], true);
        // Un-verify clears it.
        assert!(v.set_verified("t9", false));
        assert!(!v.is_verified("t9"));
    }

    #[test]
    fn passkey_lookup_returns_metadata_only() {        let mut v = vault_with_passkey();
        // Match (case-insensitive): user metadata, no secrets, no persist.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "passkey_lookup", "rp": "GitHub.COM"}));
        assert_eq!(r.reply["ok"], true);
        assert!(!r.persist);
        let keys = r.reply["passkeys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["user"], "octo");
        assert!(keys[0].get("sign_count").is_some());
        assert!(keys[0].get("credential_id").is_none());
        assert!(keys[0].get("private_key_pkcs8").is_none());
        // Unknown rp ⇒ ok with empty list (not an error — discovery).
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "passkey_lookup", "rp": "evil.com"}));
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["passkeys"].as_array().unwrap().len(), 0);
        // Missing rp / locked ⇒ deny.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "passkey_lookup"}));
        assert_eq!(r.reply["ok"], false);
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "passkey_lookup", "rp": "github.com"}));
        assert_eq!(r.reply["ok"], false);
    }

    #[test]
    fn heartbeat_parts_matrix() {
        let now = 9_999_999_999u64;
        // Fresh beacon ⇒ live.
        assert!(heartbeat_parts(Some(now), now));
        assert!(heartbeat_parts(Some(now - 1), now));
        assert!(heartbeat_parts(Some(now - (HEARTBEAT_MAX_AGE_SECS - 1)), now));
        // Stale boundary (saturating, clock-skew safe).
        assert!(!heartbeat_parts(Some(now - HEARTBEAT_MAX_AGE_SECS), now));
        assert!(!heartbeat_parts(Some(1), now));
        // Missing/unparsable beacon ⇒ dead.
        assert!(!heartbeat_parts(None, now));
        // Future beacon (clock moved) ⇒ tolerated, not a lockout.
        assert!(heartbeat_parts(Some(now + 3600), now));
    }

    #[test]
    #[test]
    fn assert_brake_allows_100_then_rejects() {
        let _rg = RATE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_assert_rate();
        // Window-start call + 99 counted calls = 100 allowed…
        for _ in 0..100 {
            assert!(assert_rate_ok());
        }
        // …101st call trips the brake.
        assert!(!assert_rate_ok());
        // New window (reset) re-arms.
        reset_assert_rate();
        assert!(assert_rate_ok());
    }

    #[test]
    fn fill_brake_allows_120_then_rejects() {
        let _rg = RATE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_fill_rate();
        for _ in 0..120 {
            assert!(fill_rate_ok());
        }
        assert!(!fill_rate_ok());
        reset_fill_rate();
        assert!(fill_rate_ok());
    }

    #[test]
    fn save_brake_allows_30_then_rejects() {
        let _rg = RATE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_save_rate();
        for _ in 0..30 {
            assert!(save_rate_ok());
        }
        assert!(!save_rate_ok());
        reset_save_rate();
        assert!(save_rate_ok());
    }

    #[test]
    fn session_ttl_is_60s_and_boundary_holds() {
        assert_eq!(HOST_IDLE_TTL_SECS, 60);
        assert!(!session_idle_expired(0));
        assert!(!session_idle_expired(30));
        assert!(!session_idle_expired(60));
        assert!(session_idle_expired(61));
        assert!(session_idle_expired(3600));
    }

    #[test]
    fn desktop_alive_reads_beacon_file() {
        let _g = sidecar_guard();
        let snap: Option<Vec<u8>> = std::fs::read(HEARTBEAT_FILE).ok();
        // Fresh beacon ⇒ alive even with no other state.
        let now = now_secs();
        std::fs::write(HEARTBEAT_FILE, now.to_string()).unwrap();
        assert!(desktop_alive());
        // Stale beacon ⇒ dead (app closed/crashed).
        std::fs::write(HEARTBEAT_FILE, "1").unwrap();
        assert!(!desktop_alive());
        // Garbage ⇒ dead, never a pass-through.
        std::fs::write(HEARTBEAT_FILE, "not-a-number").unwrap();
        assert!(!desktop_alive());
        // Missing ⇒ dead.
        let _ = std::fs::remove_file(HEARTBEAT_FILE);
        assert!(!desktop_alive());
        match snap {
            Some(b) => {
                let _ = std::fs::write(HEARTBEAT_FILE, b);
            }
            None => {
                let _ = std::fs::remove_file(HEARTBEAT_FILE);
            }
        }
    }

    #[test]
    fn bridge_unlocked_needs_both_halves() {
        // Full AND-matrix over fixture files. bridge_unlocked() only checks
        // token EXISTENCE (content never read here), so a garbage token
        // fixture is safe. Both files snapshot-restored, never wiped.
        let _g = sidecar_guard();
        let snap_hb: Option<Vec<u8>> = std::fs::read(HEARTBEAT_FILE).ok();
        let snap_tok: Option<Vec<u8>> = std::fs::read(HELLO_TOKEN_FILE).ok();
        let write_hb = |s: &str| std::fs::write(HEARTBEAT_FILE, s).unwrap();
        let write_tok = || std::fs::write(HELLO_TOKEN_FILE, b"test-fixture").unwrap();
        let wipe = || {
            let _ = std::fs::remove_file(HEARTBEAT_FILE);
            let _ = std::fs::remove_file(HELLO_TOKEN_FILE);
        };
        // Neither ⇒ locked.
        wipe();
        assert!(!bridge_unlocked());
        // Token only (P1: leftover token, closed app) ⇒ locked.
        write_tok();
        assert!(!bridge_unlocked());
        // Heartbeat only (no credential) ⇒ locked.
        wipe();
        write_hb(&now_secs().to_string());
        assert!(!bridge_unlocked());
        // Both fresh ⇒ unlocked.
        write_tok();
        assert!(bridge_unlocked());
        // Fresh token + stale heartbeat (app died) ⇒ locked.
        write_hb("1");
        assert!(!bridge_unlocked());
        // Restore.
        match snap_hb {
            Some(b) => {
                let _ = std::fs::write(HEARTBEAT_FILE, b);
            }
            None => {
                let _ = std::fs::remove_file(HEARTBEAT_FILE);
            }
        }
        match snap_tok {
            Some(b) => {
                let _ = std::fs::write(HELLO_TOKEN_FILE, b);
            }
            None => {
                let _ = std::fs::remove_file(HELLO_TOKEN_FILE);
            }
        }
    }

    #[test]
    fn login_health_kind_priorities() {
        let now = 9_999_999_999u64;
        // Reused wins over everything (even a strong, fresh password).
        assert_eq!(login_health_kind("Str0ng!Pass#2024$", now, now, 2), "reused");
        // Weak short password, fresh timestamp.
        assert_eq!(login_health_kind("abc", now, now, 1), "weak");
        // Strong but ancient.
        assert_eq!(login_health_kind("Str0ng!Pass#2024$", 1, now, 1), "stale");
        // Healthy: strong, fresh, unique.
        assert_eq!(login_health_kind("Str0ng!Pass#2024$", now, now, 1), "");
        // Empty password is missing data, not reuse — but still weak.
        assert_eq!(login_health_kind("", now, now, 0), "weak");
    }

    #[test]
    fn query_and_list_entries_carry_health() {
        let mut v = vault_with_login();
        v.credentials[0].password = "shared-pw-123!".into();
        v.credentials.push(Credential {
            id: "c2".into(),
            title: "GitLab".into(),
            username: "octo2".into(),
            password: "shared-pw-123!".into(),
            totp_secret: String::new(),
            urls: vec!["https://gitlab.com/login".into()],
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
            folder: "General".into(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: crate::models::current_timestamp(),
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        });
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "query", "app": "git"}));
        let entries = r.reply["entries"].as_array().unwrap();
        assert!(!entries.is_empty());
        assert_eq!(entries[0]["health"], "reused");
        // Trust-sort field present (0 = never filled).
        assert!(entries[0]["last_filled"].as_u64().is_some());
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "list"}));
        let logins = r.reply["logins"].as_array().unwrap();
        let c1 = logins.iter().find(|e| e["id"] == "c1").unwrap();
        assert_eq!(c1["health"], "reused");
        // No TOTP secret on either fixture login ⇒ no 2FA buttons.
        assert_eq!(c1["has_totp"], false);
    }

    #[test]
    fn ping_reports_lock_state() {        let mut v = Vault::new();
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
        // Hermetic: a real sidecar (pv_ext_stats.json) may exist in CWD from
        // app/extension runs — snapshot it, start clean so counts are
        // deterministic, restore after (never wipe real data).
        let _g = sidecar_guard();
        let snap = snap_sidecar();
        write_ext_stats(&serde_json::json!({"total_fills": 0, "last_filled": {}}));
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
        // Sidecar lives in CWD during tests — restore what was there.
        restore_sidecar(snap);
    }

    #[test]
    fn assert_signs_and_bumps_counter() {
        use base64::Engine as _;
        let mut v = vault_with_passkey();
        let chal = base64::engine::general_purpose::STANDARD.encode(b"rp-challenge-123");
        // C5: missing uv → deny even with good challenge.
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal}),
        );
        assert_eq!(r.reply["ok"], false);
        assert_eq!(r.reply["error"], "user verification required");
        // Unknown rp → clean error.
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "evil.com", "challenge": chal, "uv": true}),
        );
        assert_eq!(r.reply["ok"], false);
        // Locked → deny.
        let r = answer(
            &mut v,
            false,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal, "uv": true}),
        );
        assert_eq!(r.reply["ok"], false);
        // Bad challenge → deny.
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": "!!!", "uv": true}),
        );
        assert_eq!(r.reply["ok"], false);
        // Happy path: valid signature over the challenge, counter 0→1.
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal, "uv": true}),
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
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal, "uv": true}),
        );
        assert_eq!(r.reply["ok"], true);
        // …but once trashed it leaves the auth set (same as missing).
        v.passkeys[0].deleted_at = Some(1000);
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal, "uv": true}),
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
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal, "uv": true}),
        );
        assert_eq!(r.reply["ok"], false);
        assert_eq!(r.reply["credential_ids"].as_array().unwrap().len(), 2);
        // Disambiguate by credential_id → signs.
        let want = base64::engine::general_purpose::STANDARD.encode(&v.passkeys[1].credential_id);
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "assert", "rp_id": "github.com", "challenge": chal, "credential_id": want, "uv": true}),
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

    #[test]
    fn omni_domain_matching() {
        // Subdomain prefixes stripped.
        assert_eq!(strip_sub_prefixes("account.google.com"), "google.com");
        assert_eq!(strip_sub_prefixes("login.microsoftonline.com"), "microsoftonline.com");
        // Cluster siblings expand.
        let v = expand_query("youtube.com");
        assert!(v.contains(&"google.com".to_string()));
        assert!(v.contains(&"youtube.com".to_string()));
        // Brand-stem fallback: protonvpn ↔ proton.
        let v = expand_query("protonvpn.com");
        assert!(v.contains(&"proton.me".to_string()));
        assert!(v.contains(&"protonvpn.com".to_string()));
        // ccTLD prefix rule: google.co.uk hits the google cluster.
        let v = expand_query("mail.google.co.uk");
        assert!(v.contains(&"google.com".to_string()));
        // Unrelated domains stay lonely (no cross-contamination).
        let v = expand_query("mybank.example");
        assert_eq!(v, vec!["mybank.example".to_string()]);
    }

    #[test]
    fn omni_query_matches_siblings_end_to_end() {
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "c9".into(),
            title: "Google".into(),
            username: "me@gmail.com".into(),
            password: "pw".into(),
            totp_secret: String::new(),
            urls: vec!["https://accounts.google.com".into()],
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
        // youtube.com query finds the google.com credential via cluster.
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "query", "app": "youtube.com"}));
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["entries"].as_array().unwrap().len(), 1);
        assert_eq!(r.reply["entries"][0]["username"], "me@gmail.com");
    }

    #[test]
    fn list_exposes_metadata_never_secrets() {
        let mut v = Vault::new();
        v.credentials.push(Credential {
            id: "c1".into(),
            title: "Bank".into(),
            username: "me".into(),
            password: "s3cret".into(),
            totp_secret: "JBSWY3DPEHPK3PXP".into(),
            urls: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
            folder: "Finance".into(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: 0,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        });
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "list"}));
        assert_eq!(r.reply["ok"], false);
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "list"}));
        assert_eq!(r.reply["ok"], true);
        let e = &r.reply["logins"][0];
        assert_eq!(e["title"], "Bank");
        assert_eq!(e["folder"], "Finance");
        assert!(e.get("password").is_none());
        assert!(e.get("totp").is_none());
        assert_eq!(r.reply["cards"].as_array().unwrap().len(), 0);
        // fetch hands out exactly one item's secrets (trashed excluded).
        // The live TOTP code renders for ANY decodable secret length now
        // (new_unchecked — no 128-bit minimum); genuine junk still maps to "".
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "fetch", "kind": 1, "id": "c1"}));
        assert_eq!(r.reply["ok"], true);
        assert_eq!(r.reply["entry"]["password"], "s3cret");
        let live = r.reply["entry"]["totp"].as_str().unwrap_or_default().to_string();
        assert_eq!(live.len(), 6);
        assert!(live.bytes().all(|c| c.is_ascii_digit()));
        v.credentials[0].totp_secret = "!!!junk!!!".into();
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "fetch", "kind": 1, "id": "c1"}));
        assert_eq!(r.reply["entry"]["totp"], "");
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "fetch", "kind": 1, "id": "nope"}));
        assert_eq!(r.reply["ok"], false);
        let r = answer(&mut v, false, &serde_json::json!({"cmd": "fetch", "kind": 1, "id": "c1"}));
        assert_eq!(r.reply["ok"], false);
    }

    #[test]
    fn c2_origin_format_strict() {
        assert!(valid_origin_format("chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/"));
        assert!(!valid_origin_format("chrome-extension://*/"));
        assert!(!valid_origin_format("chrome-extension://abc/"));
        assert!(!valid_origin_format("native-host"));
        assert!(!valid_origin_format("https://github.com/"));
    }

    #[test]
    fn c6_substring_domain_does_not_overwrite() {
        let mut v = vault_with_login(); // octo / github.com
        let r = answer(
            &mut v,
            true,
            &serde_json::json!({"cmd": "save_login", "username": "octo",
                "password": "ATTACKER", "url": "https://co/"}),
        );
        assert_eq!(r.reply["ok"], false);
        assert_eq!(v.credentials[0].password, "ghp_x");
    }

    #[test]
    fn c7_single_char_and_trashed_never_dump() {
        let mut v = vault_with_login();
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "query", "app": "a"}));
        assert_eq!(r.reply["ok"], false);
        v.credentials[0].deleted_at = Some(1);
        let r = answer(&mut v, true, &serde_json::json!({"cmd": "query", "app": "github"}));
        assert_eq!(r.reply["entries"].as_array().unwrap().len(), 0);
    }
}
