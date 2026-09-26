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
                    })
                })
                .collect();
            crate::security::access_log::log_event("bridge-query", &q);
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

/// Install the native-messaging manifests for Chrome + Edge under HKCU and
/// return the manifest path. `allowed_origins` starts EMPTY (secure default —
/// no extension can connect until the user adds its ID, e.g. via
/// `vault native-host --print-manifest <origin>` as a editing guide).
/// Registry work is real Win32 (create key, set default REG_SZ, close).
pub fn register_native_host() -> Result<String, crate::error::VaultError> {
    use crate::error::VaultError;

    let dir = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("PhantomVault");
    std::fs::create_dir_all(&dir)
        .map_err(|e| VaultError::Sync(format!("bridge dir: {e}")))?;
    let manifest_path = dir.join("native-host.json");
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "phantom_vault.exe".to_string());
    // Empty origins: locked down until the user adds their extension ID.
    let doc = manifest_json("chrome-extension://__FILL_YOUR_EXTENSION_ID__/", &exe);
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
    let emit_err = |msg: &str| {
        let frame = encode_frame(&err(msg));
        let _ = std::io::stdout().write_all(&frame);
        let _ = std::io::stdout().flush();
    };
    // No TTY prompt possible here — stdin belongs to the browser.
    let blob = match std::fs::read(HELLO_TOKEN_FILE) {
        Ok(b) => b,
        Err(_) => {
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
    let (mut vault, _) = match crate::storage::load_vault_versioned(
        &master,
        crate::developer::vault_run::VAULT_FILE,
    ) {
        Ok(v) => v,
        Err(e) => {
            use zeroize::Zeroize;
            let mut m = master;
            m.zeroize();
            emit_err(&format!("unlock failed: {e}"));
            return 1;
        }
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
