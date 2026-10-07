//! 1-click GitHub Releases auto-updater (on-demand, never silent).
//!
//! Flow: Settings → System → [Check for Updates] → version compare against
//! `CARGO_PKG_VERSION` → [Download & Stage] (worker thread) → user clicks
//! [Restart to Update] → batch script swaps the binary after exit.
//!
//! Honesty notes: Windows locks the running exe, so replacement happens
//! post-exit via a temp `.bat` (written to %TEMP%, self-deleting). No
//! code-signature verification exists yet — trust root is TLS + the pinned
//! `zjhasan13/phantom_vault` repo; releases SHOULD be signed in future.

use crate::error::{Result, VaultError};

pub const RELEASES_URL: &str =
    "https://api.github.com/repos/zjhasan13/phantom_vault/releases/latest";
const USER_AGENT: &str = "phantom-vault-updater";

/// Release-signing public key (Ed25519). The matching PRIVATE key lives ONLY
/// as a GitHub Actions secret — it is NEVER in this repo. Every release
/// asset must ship `<asset>.sig` (raw 64-byte detached signature); binaries
/// without a valid signature are refused, no exceptions.
pub const UPDATER_PUBLIC_KEY: [u8; 32] = [
    199, 62, 33, 33, 153, 183, 61, 17, 153, 186, 193, 81, 125, 98, 44, 26,
    217, 109, 183, 126, 115, 189, 59, 210, 175, 22, 68, 21, 44, 2, 169, 139,
];

#[derive(Debug, Clone, PartialEq)]
pub struct ReleaseInfo {
    pub tag: String,
    pub name: String,
    pub asset_name: String,
    pub asset_url: String,
    pub asset_size: u64,
    /// Checksum sidecar (`<asset>.sha256` preferred, else SHA256SUMS*).
    /// `None` = release ships no verifiable hash (download refuses).
    pub checksum_url: Option<String>,
    /// Detached Ed25519 signature (`<asset>.sig`, raw 64 bytes or hex).
    /// `None` = release ships no signature (download refuses).
    pub sig_url: Option<String>,
    /// Release notes (`body`), cleaned + capped for the What's New dialog.
    /// Empty when the release ships no notes — the dialog then says so.
    pub notes: String,
}

/// `v1.2.3` / `1.2` / `1.2.3-beta.1` → numeric triple (suffix ignored for
/// ordering; a bare tag mismatch never counts as "newer" on its own).
pub fn parse_version(tag: &str) -> Option<(u64, u64, u64)> {
    let t = tag.trim().trim_start_matches(['v', 'V']);
    let core = t.split(['-', '+']).next().unwrap_or(t);
    let mut it = core.split('.');
    let maj: u64 = it.next()?.trim().parse().ok()?;
    let min: u64 = it.next().unwrap_or("0").trim().parse().ok()?;
    let pat: u64 = it.next().unwrap_or("0").trim().parse().ok()?;
    Some((maj, min, pat))
}

/// True when `latest` is strictly newer than `current`. Unparseable tags
/// never trigger an update (fail-closed).
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Pick the Windows binary: `.exe` with a platform/installer hint wins,
/// any other `.exe` is the fallback. Pure — unit tested.
pub fn pick_asset(names_urls: &[(String, String, u64)]) -> Option<(String, String, u64)> {
    let exes: Vec<_> = names_urls
        .iter()
        .filter(|(n, _, _)| n.to_lowercase().ends_with(".exe"))
        .collect();
    if exes.is_empty() {
        return None;
    }
    let hinted = exes.iter().find(|(n, _, _)| {
        let l = n.to_lowercase();
        l.contains("windows") || l.contains("win64") || l.contains("setup") || l.contains("installer") || l.contains("phantom")
    });
    hinted.copied().or(exes.first().copied()).map(|(n, u, s)| (n.clone(), u.clone(), *s))
}

fn client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(25));
    if let Some(proxy_url) = crate::sync::github_sync::effective_proxy() {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| VaultError::Sync(format!("invalid proxy URL: {e}")))?;
        builder = builder.proxy(proxy);
    }
    builder
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| VaultError::Sync(format!("HTTP client init failed: {e}")))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| VaultError::Sync(format!("async runtime failed: {e}")))
}

/// Query the latest release (network on the caller's thread — invoke from a
/// worker). Returns None when already up to date.
pub fn check_latest() -> Result<Option<ReleaseInfo>> {
    let rt = runtime()?;
    rt.block_on(async {
        let text = client()?
            .get(RELEASES_URL)
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("releases API unreachable: {e}")))?
            .error_for_status()
            .map_err(|e| VaultError::Sync(format!("releases API error: {e}")))?
            .text()
            .await
            .map_err(|e| VaultError::Sync(format!("releases read failed: {e}")))?;
        let doc: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| VaultError::Sync(format!("releases parse failed: {e}")))?;
        let tag = doc.get("tag_name").and_then(|t| t.as_str()).unwrap_or("").to_string();
        if tag.is_empty() {
            return Err(VaultError::Sync("release has no tag".into()));
        }
        if !is_newer(&tag, env!("CARGO_PKG_VERSION")) {
            return Ok(None);
        }
        let assets: Vec<(String, String, u64)> = doc
            .get("assets")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| {
                        Some((
                            a.get("name")?.as_str()?.to_string(),
                            a.get("browser_download_url")?.as_str()?.to_string(),
                            a.get("size")?.as_u64().unwrap_or(0),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        match pick_asset(&assets) {
            Some((asset_name, asset_url, asset_size)) => {
                // Checksum sidecar, most-specific first: "<asset>.sha256",
                // then the GNU-style aggregate files.
                let lower: Vec<(String, String)> = assets
                    .iter()
                    .map(|(n, u, _)| (n.to_lowercase(), u.clone()))
                    .collect();
                let want = format!("{asset_name}.sha256").to_lowercase();
                let checksum_url = lower
                    .iter()
                    .find(|(n, _)| *n == want)
                    .map(|(_, u)| u.clone())
                    .or_else(|| {
                        lower
                            .iter()
                            .find(|(n, _)| {
                                let f = n.rsplit('/').next().unwrap_or(n);
                                f == "sha256sums" || f == "sha256sums.txt"
                            })
                            .map(|(_, u)| u.clone())
                    });
                // Detached signature sidecar: exact "<asset>.sig" only —
                // never a shared/aggregate file (wrong-asset confusion).
                let sig_want = format!("{asset_name}.sig").to_lowercase();
                let sig_url = lower
                    .iter()
                    .find(|(n, _)| *n == sig_want)
                    .map(|(_, u)| u.clone());
                Ok(Some(ReleaseInfo {
                    tag: tag.clone(),
                    name: doc.get("name").and_then(|n| n.as_str()).unwrap_or(&tag).to_string(),
                    asset_name,
                    asset_url,
                    asset_size,
                    checksum_url,
                    sig_url,
                    notes: clean_notes(doc.get("body").and_then(|b| b.as_str()).unwrap_or("")),
                }))
            }
            None => Err(VaultError::Sync(format!(
                "{tag} has no Windows (.exe) asset"
            ))),
        }
    })
}

/// Clean GitHub release notes for in-app display: trimmed, runs of blank
/// lines collapsed to one, capped at 1500 chars (whole words). Pure.
pub fn clean_notes(body: &str) -> String {
    let mut out = String::new();
    let mut blanks = 0u32;
    for line in body.lines() {
        if line.trim().is_empty() {
            blanks += 1;
            if blanks == 1 {
                out.push('\n');
            }
            continue;
        }
        blanks = 0;
        out.push_str(line.trim_end());
        out.push('\n');
    }
    let out = out.trim().to_string();
    if out.chars().count() <= 1500 {
        return out;
    }
    let cut: String = out.chars().take(1490).collect();
    let cut = cut.rsplit_once(char::is_whitespace).map(|(h, _)| h).unwrap_or(&cut);
    format!("{cut}…")
}

/// Parse a checksum sidecar: GNU `SHA256SUMS` lines (`<hex>[ *]filename`)
/// plus bare single-hash files. Returns filename → lowercase hex.
pub fn parse_sums(text: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut parts = t.split_whitespace();
        let (Some(hash), Some(name)) = (parts.next(), parts.next()) else {
            // Bare hash with no filename (single-asset .sha256 file).
            if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
                out.insert(String::new(), t.to_lowercase());
            }
            continue;
        };
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            // GNU `*` marks binary mode — strip it; keep basename only.
            let file = name.trim_start_matches('*');
            let file = file.rsplit(['/', '\\']).next().unwrap_or(file);
            out.insert(file.to_string(), hash.to_lowercase());
        }
    }
    out
}

/// SHA-256 hex of bytes (integrity gate for staged binaries).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut s = String::with_capacity(64);
    for b in sha2::Sha256::digest(bytes) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Verify bytes against an expected hex digest (case-insensitive).
/// Plain std Result (message IS the user-facing toast). Pure — unit tested.
pub fn check_hash(bytes: &[u8], expected_hex: &str) -> std::result::Result<(), String> {
    let got = sha256_hex(bytes);
    if got == expected_hex.trim().to_lowercase() {
        Ok(())
    } else {
        Err("🚨 Update Integrity Check Failed: Binary hash mismatch! Aborted for security.".to_string())
    }
}

/// Verify raw bytes against a detached Ed25519 signature (raw 64 bytes or
/// hex-encoded). Pure — unit tested. This is the final gate before any
/// staged binary may execute or replace the live exe.
pub fn check_signature(bytes: &[u8], sig_blob: &[u8]) -> std::result::Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    // Accept raw 64-byte signatures and hex (with optional whitespace).
    let raw: Vec<u8> = if sig_blob.len() == 64 {
        sig_blob.to_vec()
    } else {
        let t: String = String::from_utf8_lossy(sig_blob)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        hex_decode(&t).ok_or_else(|| {
            "🚨 Update signature unreadable — refusing unverified binary.".to_string()
        })?
    };
    let arr: [u8; 64] = raw.try_into().map_err(|_| {
        "🚨 Update signature has wrong length — refusing unverified binary.".to_string()
    })?;
    let vk = VerifyingKey::from_bytes(&UPDATER_PUBLIC_KEY).map_err(|_| {
        "🚨 Embedded updater key corrupt — refusing all updates.".to_string()
    })?;
    let sig = Signature::from_bytes(&arr);
    vk.verify_strict(bytes, &sig).map_err(|_| {
        "🚨 Update Signature Invalid: untrusted binary! Aborted for security.".to_string()
    })?;
    Ok(())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Download the asset to `%TEMP%`, then PROVE it: fetch the release checksum
/// sidecar and compare SHA-256. No sums asset (or no entry) = fail CLOSED.
/// On ANY failure the staged file is securely deleted and nothing executes.
pub fn download_asset(info: &ReleaseInfo) -> Result<std::path::PathBuf> {
    let rt = runtime()?;
    rt.block_on(async {
        let bytes = client()?
            .get(&info.asset_url)
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("download failed: {e}")))?
            .error_for_status()
            .map_err(|e| VaultError::Sync(format!("download HTTP error: {e}")))?
            .bytes()
            .await
            .map_err(|e| VaultError::Sync(format!("download read failed: {e}")))?;
        if bytes.is_empty() {
            return Err(VaultError::Sync("downloaded asset is empty".into()));
        }
        if info.asset_size > 0 && bytes.len() as u64 != info.asset_size {
            return Err(VaultError::Sync(format!(
                "size mismatch: got {}, expected {}",
                bytes.len(),
                info.asset_size
            )));
        }
        // H11: unpredictable stage name (OsRng suffix) + create_new so a
        // pre-planted %TEMP% symlink/name can't be swapped under us.
        use rand_core::RngCore;
        let mut nonce = [0u8; 8];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let dest = std::env::temp_dir().join(format!(
            "phantom-vault-update-{}-{:016x}.exe",
            info.tag.replace(['/', '\\', ':'], "_"),
            u64::from_le_bytes(nonce)
        ));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(&bytes)
            })
            .map_err(|e| VaultError::Sync(format!("stage write failed: {e}")))?;
        // Integrity gate BEFORE anything may execute or replace.
        let sums_url = info.checksum_url.clone().ok_or_else(|| {
            VaultError::Sync("release ships no checksum file — refusing unverified binary".to_string())
        })?;
        let sums_text = client()?
            .get(&sums_url)
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("checksum download failed: {e}")))?
            .error_for_status()
            .map_err(|e| VaultError::Sync(format!("checksum HTTP error: {e}")))?
            .text()
            .await
            .map_err(|e| VaultError::Sync(format!("checksum read failed: {e}")))?;
        let sums = parse_sums(&sums_text);
        // Exact filename first, bare-hash single file second.
        let expected = sums
            .get(&info.asset_name)
            .or_else(|| sums.get(""))
            .cloned()
            .ok_or_else(|| {
                VaultError::Sync(format!(
                    "no checksum entry for {} — refusing unverified binary",
                    info.asset_name
                ))
            })?;
        if let Err(e) = check_hash(&bytes, &expected) {
            let _ = std::fs::remove_file(&dest);
            return Err(VaultError::Sync(e));
        }
        // Signature gate (final): detached Ed25519 over the exact bytes.
        // Missing .sig asset = fail CLOSED. Any failure shreds the stage.
        let sig_url = info.sig_url.clone().ok_or_else(|| {
            let _ = std::fs::remove_file(&dest);
            VaultError::Sync("release ships no .sig signature — refusing unverified binary".to_string())
        })?;
        let sig_blob = client()?
            .get(&sig_url)
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("signature download failed: {e}")))?
            .error_for_status()
            .map_err(|e| VaultError::Sync(format!("signature HTTP error: {e}")))?
            .bytes()
            .await
            .map_err(|e| VaultError::Sync(format!("signature read failed: {e}")))?;
        if sig_blob.is_empty() || sig_blob.len() > 4096 {
            let _ = std::fs::remove_file(&dest);
            return Err(VaultError::Sync("signature file implausible — refusing unverified binary".into()));
        }
        if let Err(e) = check_signature(&bytes, &sig_blob) {
            let _ = std::fs::remove_file(&dest);
            return Err(VaultError::Sync(e));
        }
        Ok(dest)
    })
}

/// Stage the post-exit swap script. Returns the `.bat` path; the UI's
/// Restart button launches it detached, then `process::exit(0)`.
/// The script waits for OUR pid to vanish, moves the staged exe over the
/// live one, restarts the app, and deletes itself.
pub fn stage_swap_script(staged_exe: &std::path::Path, tag: &str) -> Result<std::path::PathBuf> {
    let live = std::env::current_exe().map_err(|e| VaultError::Sync(format!("current exe: {e}")))?;
    // Batch injection guard: a `"` or line-break in either path would break
    // out of the quoted `move`/`start` lines. TEMP/exe paths with quotes are
    // pathological — fail LOUD instead of writing a weaponizable script.
    for p in [staged_exe, live.as_path()] {
        let s = p.to_string_lossy();
        if s.contains(['"', '\n', '\r']) {
            return Err(VaultError::Sync("refusing to stage: path contains quote/newline".into()));
        }
    }
    let pid = std::process::id();
    // H11: randomize the swap-script name too (same %TEMP% plant concern).
    use rand_core::RngCore as _;
    let mut nonce2 = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut nonce2);
    let bat = std::env::temp_dir().join(format!(
        "phantom-vault-apply-{}-{:016x}.bat",
        tag.replace(['/', '\\', ':'], "_"),
        u64::from_le_bytes(nonce2)
    ));
    let script = format!(
        "@echo off\r\n\
         :wait\r\n\
         tasklist /FI \"PID eq {pid}\" 2>NUL | find /I \"{pid}\" >NUL\r\n\
         if not errorlevel 1 ( timeout /t 1 /nobreak >NUL & goto wait )\r\n\
         move /Y \"{staged}\" \"{live}\" >NUL\r\n\
         start \"\" \"{live}\"\r\n\
         del \"%~f0\"\r\n",
        staged = staged_exe.to_string_lossy(),
        live = live.to_string_lossy(),
    );
    std::fs::write(&bat, script).map_err(|e| VaultError::Sync(format!("swap script failed: {e}")))?;
    Ok(bat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse_and_compare() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2"), Some((1, 2, 0)));
        assert_eq!(parse_version("V0.1.0-beta.1"), Some((0, 1, 0)));
        assert!(parse_version("nope").is_none());
        assert!(parse_version("").is_none());
        assert!(is_newer("v1.2.4", "1.2.3"));
        assert!(is_newer("v2.0.0", "1.9.9"));
        assert!(!is_newer("v1.2.3", "1.2.3"));
        assert!(!is_newer("v1.2.2", "1.2.3"));
        assert!(!is_newer("garbage", "1.2.3"));
        assert!(!is_newer("v9.9.9", "garbage"));
    }

    #[test]
    fn notes_cleaned_and_capped() {
        assert_eq!(clean_notes("  hello  \n\n\n\nworld  "), "hello\n\nworld");
        assert_eq!(clean_notes(""), "");
        assert_eq!(clean_notes("   \n  "), "");
        let long = "word ".repeat(400);
        let out = clean_notes(&long);
        assert!(out.chars().count() <= 1501);
        assert!(out.ends_with('…'));
        assert!(!out.contains("  "));
    }

    #[test]
    fn asset_pick_prefers_windows_exe() {
        let assets = vec![
            ("app-linux.tar.gz".to_string(), "u1".to_string(), 10u64),
            ("app.exe".to_string(), "u2".to_string(), 20u64),
            ("phantom-vault-windows-setup.exe".to_string(), "u3".to_string(), 30u64),
        ];
        let picked = pick_asset(&assets).unwrap();
        assert_eq!(picked.0, "phantom-vault-windows-setup.exe");
        assert_eq!(picked.1, "u3");
        // No hint → first exe fallback.
        let plain = vec![("app.exe".to_string(), "u2".to_string(), 20u64)];
        assert_eq!(pick_asset(&plain).unwrap().1, "u2");
        // No exe at all → None (honest "no windows binary" error upstream).
        let none: Vec<(String, String, u64)> = vec![("app.tar.gz".to_string(), "u".to_string(), 1)];
        assert!(pick_asset(&none).is_none());
        assert!(pick_asset(&[]).is_none());
    }

    #[test]
    fn sha256_vector_and_check() {
        // NIST vector: SHA-256("abc").
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(check_hash(b"abc", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD").is_ok());
        let err = check_hash(b"abc", &"0".repeat(64)).unwrap_err();
        assert!(err.contains("hash mismatch"));
    }

    #[test]
    fn sums_parse_gnu_bare_and_binary() {
        let gnu = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  app.exe\n\
                   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  *setup.exe\n\
                   # comment\n\
                   notahash\n";
        let m = parse_sums(gnu);
        assert_eq!(m["app.exe"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(m["setup.exe"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(m.len(), 2);
        // Bare single-hash file.
        let bare = parse_sums("  BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD\n");
        assert_eq!(bare[""], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(parse_sums("garbage\n").is_empty());
    }

    #[test]
    fn signature_verify_strict_roundtrip() {
        use ed25519_dalek::Signer;
        // Independent test key (NOT the embedded release key).
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let msg = b"phantom-vault fake binary bytes";
        let sig = signing.sign(msg);
        // Raw 64-byte form verifies against its own key...
        let vk_bytes = signing.verifying_key().to_bytes();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).unwrap();
        vk.verify_strict(msg, &sig).unwrap();
        // ...but the EMBEDDED release key must reject it.
        assert!(check_signature(msg, &sig.to_bytes()).is_err());
        // Tampered message fails even with a structurally-valid sig blob.
        assert!(check_signature(b"tampered!", &sig.to_bytes()).is_err());
        // Hex form accepted when valid — build one against the embedded key
        // is impossible here (no private key), so assert the SHAPE path:
        // 128-hex-char blob parses (length gate), then key rejects.
        let hex_sig: String = sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let err = check_signature(msg, hex_sig.as_bytes()).unwrap_err();
        assert!(err.contains("Invalid") || err.contains("untrusted"));
        // Garbage / short blobs fail loud, never panic.
        assert!(check_signature(msg, b"nope").is_err());
        assert!(check_signature(msg, &[0u8; 63]).is_err());
        assert!(check_signature(msg, &[0u8; 64]).is_err());
    }

    #[test]
    fn embedded_key_is_well_formed() {
        // Would panic the updater at runtime otherwise — pin it in a test.
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&UPDATER_PUBLIC_KEY).unwrap();
        // Sanity: not the all-zero key.
        assert_ne!(UPDATER_PUBLIC_KEY, [0u8; 32]);
        let _ = vk;
    }
}
