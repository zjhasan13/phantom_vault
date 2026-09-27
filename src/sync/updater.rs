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

#[derive(Debug, Clone, PartialEq)]
pub struct ReleaseInfo {
    pub tag: String,
    pub name: String,
    pub asset_name: String,
    pub asset_url: String,
    pub asset_size: u64,
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
            Some((asset_name, asset_url, asset_size)) => Ok(Some(ReleaseInfo {
                tag: tag.clone(),
                name: doc.get("name").and_then(|n| n.as_str()).unwrap_or(&tag).to_string(),
                asset_name,
                asset_url,
                asset_size,
            })),
            None => Err(VaultError::Sync(format!(
                "{tag} has no Windows (.exe) asset"
            ))),
        }
    })
}

/// Download the asset to `%TEMP%`. Sanity: non-empty + matches advertised
/// size when the API reported one.
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
        let dest = std::env::temp_dir().join(format!("phantom-vault-update-{}.exe", info.tag.replace(['/', '\\', ':'], "_")));
        std::fs::write(&dest, &bytes).map_err(|e| VaultError::Sync(format!("stage write failed: {e}")))?;
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
    let bat = std::env::temp_dir().join(format!("phantom-vault-apply-{}.bat", tag.replace(['/', '\\', ':'], "_")));
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
}
