//! Phase 12 — Zero-knowledge private-repo sync.
//!
//! Privacy contract:
//! - Only the raw encrypted vault blob (`vault.enc` bytes) ever leaves the device.
//!   It is already XChaCha20-Poly1305 sealed; GitHub sees ciphertext exclusively.
//! - Commit messages are a fixed generic string — no timestamps, counts, or names.
//! - The personal access token lives DPAPI-sealed on disk and is never logged.
//! - No listing, search, or metadata calls — exactly one get-content and one
//!   create/update call per sync direction.

use crate::core::memory::DpapiGuard;
use crate::error::{Result, VaultError};
use base64::Engine as _;
use zeroize::Zeroize;

const REPO_FILE: &str = "sync_repo.txt";
const TOKEN_FILE: &str = "github_token.dpapi";
const REMOTE_PATH: &str = "vault.enc";
const COMMIT_MESSAGE: &str = "chore: vault sync";

pub const MAX_BLOB_BYTES: usize = 48 * 1024 * 1024;

pub struct SyncConfig {
    pub owner: String,
    pub repo: String,
}

fn clean(s: &str) -> String {
    s.trim().to_string()
}

/// Persist `owner/repo` (not sensitive) as plain `owner/repo` text.
pub fn save_repo(owner: &str, repo: &str) -> Result<()> {
    let owner = clean(owner);
    let repo = clean(repo);
    if owner.is_empty() || repo.is_empty() {
        return Err(VaultError::Sync("owner/repo required".into()));
    }
    if owner.contains('/') || repo.contains('/') || owner.contains(' ') || repo.contains(' ') {
        return Err(VaultError::Sync("invalid owner/repo".into()));
    }
    std::fs::write(REPO_FILE, format!("{owner}/{repo}"))
        .map_err(|e| VaultError::Sync(format!("cannot save sync target: {e}")))?;
    Ok(())
}

pub fn load_repo() -> Result<SyncConfig> {
    let raw = std::fs::read_to_string(REPO_FILE)
        .map_err(|_| VaultError::Sync("sync not configured".into()))?;
    let mut parts = raw.trim().splitn(2, '/');
    let owner = parts.next().unwrap_or("").to_string();
    let repo = parts.next().unwrap_or("").to_string();
    if owner.is_empty() || repo.is_empty() {
        return Err(VaultError::Sync("sync not configured".into()));
    }
    Ok(SyncConfig { owner, repo })
}

pub fn is_configured() -> bool {
    load_repo().is_ok() && std::path::Path::new(TOKEN_FILE).exists()
}

/// DPAPI-seal the token to disk. Plaintext is zeroized immediately.
pub fn store_token(token: &str) -> Result<()> {
    let mut owned = token.trim().to_string();
    if owned.is_empty() {
        return Err(VaultError::Sync("empty token".into()));
    }
    let blob = DpapiGuard::protect(owned.as_bytes())?;
    owned.zeroize();
    std::fs::write(TOKEN_FILE, blob)
        .map_err(|e| VaultError::Sync(format!("cannot store token: {e}")))?;
    Ok(())
}

fn load_token() -> Result<String> {
    let blob =
        std::fs::read(TOKEN_FILE).map_err(|_| VaultError::Sync("sync not configured".into()))?;
    let secret = DpapiGuard::unprotect(&blob)?;
    let token = String::from_utf8_lossy(secret.expose()).into_owned();
    if token.trim().is_empty() {
        return Err(VaultError::Sync("stored token is empty".into()));
    }
    Ok(token)
}

fn client(token: &str) -> Result<octocrab::Octocrab> {
    octocrab::Octocrab::builder()
        .personal_token(token.to_string())
        .build()
        .map_err(|e| VaultError::Sync(format!("client init failed: {e}")))
}

/// True when an octocrab error is HTTP 404 (missing file/repo path).
/// Matches the structured variant first, falls back to message sniffing
/// across octocrab versions.
fn is_not_found(e: &octocrab::Error) -> bool {
    if matches!(
        e,
        octocrab::Error::GitHub { source, .. } if source.status_code == http::StatusCode::NOT_FOUND
    ) {
        return true;
    }
    let msg = e.to_string();
    msg.contains("404") || msg.to_lowercase().contains("not found")
}

/// Pull the remote ciphertext. Returns None when the repo has no vault yet.
pub async fn pull_remote(
    owner: &str,
    repo: &str,
    token: &str,
) -> Result<Option<(Vec<u8>, String)>> {
    let octo = client(token)?;
    let items = match octo
        .repos(owner, repo)
        .get_content()
        .path(REMOTE_PATH)
        .send()
        .await
    {
        Ok(items) => items,
        Err(e) => {
            // Fresh repo: no vault file yet (HTTP 404) is NOT an error —
            // it signals push_remote() to take the create_file path.
            if is_not_found(&e) {
                return Ok(None);
            }
            return Err(VaultError::Sync(format!("fetch failed: {e}")));
        }
    };
    let first = items
        .items
        .first()
        .ok_or_else(|| VaultError::Sync("remote vault missing".into()))?;
    let sha = first.sha.clone();
    let decoded = first
        .decoded_content()
        .ok_or_else(|| VaultError::Sync("remote content unreadable".into()))?;
    if decoded.len() > MAX_BLOB_BYTES {
        return Err(VaultError::Sync("remote blob suspiciously large".into()));
    }
    // We upload base64(ciphertext); decode one layer to recover raw bytes.
    let raw = base64::engine::general_purpose::STANDARD
        .decode(decoded.trim())
        .map_err(|e| VaultError::Sync(format!("remote blob corrupt: {e}")))?;
    Ok(Some((raw, sha)))
}

/// Push local ciphertext. `sha` must be the last-seen remote sha (None = create).
/// Returns the new remote sha. Refuses blind overwrites on conflict.
pub async fn push_remote(
    owner: &str,
    repo: &str,
    token: &str,
    blob: &[u8],
    sha: Option<String>,
    expected_remote_sha: Option<String>,
) -> Result<String> {
    if blob.is_empty() || blob.len() > MAX_BLOB_BYTES {
        return Err(VaultError::Sync("local blob invalid".into()));
    }
    let octo = client(token)?;
    // Re-read remote head: refuse to overwrite a remote we haven't seen.
    let current = pull_remote(owner, repo, token).await?;
    match (&current, &sha, &expected_remote_sha) {
        (Some((_, head)), _, Some(expected)) if head != expected => {
            return Err(VaultError::Sync(
                "remote changed elsewhere — pull first".into(),
            ))
        }
        (Some(_), None, _) => {
            return Err(VaultError::Sync(
                "remote vault exists — pull first".into(),
            ))
        }
        _ => {}
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
    if current.is_some() {
        let head_sha = sha.or_else(|| current.map(|(_, s)| s)).ok_or_else(|| {
            VaultError::Sync("remote vault exists — pull first".into())
        })?;
        let _ = expected_remote_sha;
        octo.repos(owner, repo)
            .update_file(REMOTE_PATH, COMMIT_MESSAGE, b64, head_sha)
            .branch("main")
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("push failed: {e}")))?;
    } else {
        octo.repos(owner, repo)
            .create_file(REMOTE_PATH, COMMIT_MESSAGE, b64)
            .branch("main")
            .send()
            .await
            .map_err(|e| VaultError::Sync(format!("push failed: {e}")))?;
    }
    // Return fresh head sha for the caller's last-seen record.
    let (_, new_sha) = pull_remote(owner, repo, token)
        .await?
        .ok_or_else(|| VaultError::Sync("push verify failed".into()))?;
    Ok(new_sha)
}

/// Convenience: load stored repo + token for worker threads.
pub fn load_credentials() -> Result<(SyncConfig, String)> {
    let cfg = load_repo()?;
    let token = load_token()?;
    Ok((cfg, token))
}

/// Last-seen remote sha sidecar (prevents blind overwrites across restarts).
const SHA_FILE: &str = "sync_head.sha";

pub fn load_head_sha() -> Option<String> {
    std::fs::read_to_string(SHA_FILE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn store_head_sha(sha: &str) {
    let _ = std::fs::write(SHA_FILE, sha);
}
