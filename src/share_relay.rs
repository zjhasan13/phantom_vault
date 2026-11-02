//! A20b: async relay for share bundles via GitHub **secret gists**.
//!
//! The sender publishes the already-encrypted `PVSH1`/`PVSH2` bundle as
//! base64 in one secret (unlisted) gist. The recipient fetches that gist
//! **without a token** — a secret gist is readable by anyone who knows its
//! id, which is exactly the share link. GitHub only ever sees ciphertext.
//!
//! Honest limits (see `docs/A20_SEND.md`):
//! - GitHub cannot enforce TTL or one-view. Expiry is the sender's clock;
//!   the sender deletes the gist on revoke, and the recipient can re-fetch
//!   until that delete lands. Label it "expiring", never "one-time".
//! - The gist owner's GitHub username is visible to the recipient (and to
//!   GitHub); the link itself carries only the random gist id.
//! - Publish/delete need the stored GitHub token with the `gist` scope.
//!   A fine-grained token usually cannot create gists.

use crate::share::{is_gist_id, is_gist_owner};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use zeroize::Zeroizing;

/// Fixed filename so the recipient does not need the local share id.
pub const GIST_FILE: &str = "bundle.pvsh.b64";
/// A login bundle is small; 64 KiB of ciphertext is already generous.
pub const MAX_RELAY_BUNDLE: usize = 64 * 1024;
const DEFAULT_API: &str = "https://api.github.com";
const USER_AGENT: &str = "PhantomVault-A20-relay";
const DESCRIPTION: &str = "PhantomVault share";
const API_VERSION: &str = "2022-11-28";

#[cfg(test)]
fn api_base() -> String {
    std::env::var("PV_RELAY_API")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_API.to_string())
}

#[cfg(not(test))]
fn api_base() -> String {
    DEFAULT_API.to_string()
}

fn http() -> Result<reqwest::Client, String> {
    let default = api_base() == DEFAULT_API;
    let mut builder = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(25));
    // A loopback/mock API must never be sent through an ambient proxy (the
    // test hook is also useful behind a local TLS terminator).
    if default {
        if let Some(proxy) = crate::sync::github_sync::effective_proxy() {
            builder = builder
                .proxy(reqwest::Proxy::all(&proxy).map_err(|e| format!("relay proxy: {e}"))?);
        }
    }
    builder.build().map_err(|e| format!("relay http: {e}"))
}

fn token() -> Result<Zeroizing<String>, String> {
    #[cfg(test)]
    if let Some(token) = TEST_TOKEN
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
    {
        return Ok(Zeroizing::new(token.clone()));
    }
    crate::sync::github_sync::load_token().map_err(|_| {
        "GitHub token not configured — Settings → GitHub Sync; the token needs the gist scope"
            .to_string()
    })
}

#[cfg(test)]
static TEST_TOKEN: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn set_test_token(token: Option<&str>) {
    *TEST_TOKEN.lock().unwrap_or_else(|p| p.into_inner()) = token.map(str::to_string);
}

fn status_hint(status: u16) -> &'static str {
    match status {
        401 | 403 => " (token rejected — the token needs the gist scope)",
        404 => " (not found, or the token lacks the gist scope)",
        429 => " (GitHub rate limit — retry later)",
        _ => "",
    }
}

async fn failure(what: &str, response: reqwest::Response) -> String {
    let status = response.status().as_u16();
    format!("{what} failed: HTTP {status}{}", status_hint(status))
}

#[derive(Serialize)]
struct NewGist<'a> {
    description: &'a str,
    public: bool,
    files: BTreeMap<&'a str, NewFile<'a>>,
}

#[derive(Serialize)]
struct NewFile<'a> {
    content: &'a str,
}

#[derive(Deserialize)]
struct CreatedGist {
    id: String,
    #[serde(default)]
    owner: Option<GistOwner>,
}

#[derive(Deserialize)]
struct GistOwner {
    login: String,
}

/// A published relay object: the gist id plus the owner needed for a
/// tokenless raw fetch (`gist.githubusercontent.com/<owner>/<id>/raw`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub gist_id: String,
    pub owner: String,
}

#[derive(Deserialize)]
struct GistResponse {
    #[serde(default)]
    files: BTreeMap<String, GistFile>,
}

#[derive(Deserialize)]
struct GistFile {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    truncated: Option<bool>,
}

/// Publish `bundle` as a secret gist. Returns the gist id + owner login.
pub async fn publish(bundle: &[u8]) -> Result<Published, String> {
    if bundle.is_empty() || bundle.len() > MAX_RELAY_BUNDLE {
        return Err(format!(
            "bundle is too large for the gist relay ({} bytes; max {MAX_RELAY_BUNDLE})",
            bundle.len()
        ));
    }
    let content = STANDARD.encode(bundle);
    let mut files = BTreeMap::new();
    files.insert(GIST_FILE, NewFile { content: &content });
    let body = NewGist {
        description: DESCRIPTION,
        public: false,
        files,
    };
    let tok = token()?;
    let body = serde_json::to_vec(&body).map_err(|e| format!("relay publish encode: {e}"))?;
    let response = http()?
        .post(format!("{}/gists", api_base()))
        .bearer_auth(tok.as_str())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", API_VERSION)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("relay publish: {e}"))?;
    if !response.status().is_success() {
        return Err(failure("relay publish", response).await);
    }
    let text = response
        .text()
        .await
        .map_err(|e| format!("relay publish response: {e}"))?;
    let created: CreatedGist =
        serde_json::from_str(&text).map_err(|e| format!("relay publish response: {e}"))?;
    if !is_gist_id(&created.id) {
        return Err("relay publish returned an invalid gist id".to_string());
    }
    let owner = created
        .owner
        .map(|o| o.login)
        .filter(|o| is_gist_owner(o))
        .ok_or_else(|| "relay publish response has no valid owner login".to_string())?;
    Ok(Published {
        gist_id: created.id,
        owner,
    })
}

fn decode_bundle(content: &str) -> Result<Vec<u8>, String> {
    // base64 expands by 4/3; leave room for whitespace before decoding.
    if content.len() > MAX_RELAY_BUNDLE * 2 {
        return Err("relay object is suspiciously large".to_string());
    }
    let raw = STANDARD
        .decode(content.trim())
        .map_err(|_| "relay object is not valid base64".to_string())?;
    if raw.len() < 5 + 24 + 16 {
        return Err("relay object is too small to be a share".to_string());
    }
    if raw.len() > MAX_RELAY_BUNDLE {
        return Err("relay bundle is too large".to_string());
    }
    Ok(raw)
}

#[cfg(test)]
fn raw_base() -> String {
    std::env::var("PV_RELAY_RAW")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://gist.githubusercontent.com".to_string())
}

#[cfg(not(test))]
fn raw_base() -> String {
    "https://gist.githubusercontent.com".to_string()
}

/// Tokenless raw fetch. The owner comes from the link, so this works even
/// when the GitHub API requires auth for a secret gist's metadata.
async fn fetch_raw(owner: &str, gist_id: &str) -> Result<Vec<u8>, String> {
    if !is_gist_owner(owner) {
        return Err("bad GitHub owner in share link".to_string());
    }
    let base = raw_base();
    for url in [
        format!("{base}/{owner}/{gist_id}/raw/{GIST_FILE}"),
        format!("{base}/{owner}/{gist_id}/raw"),
    ] {
        let response = http()?
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("relay fetch: {e}"))?;
        if response.status().as_u16() == 404 {
            continue;
        }
        if response.status().as_u16() == 401 {
            return Err(
                "GitHub requires authentication for this gist — ask the sender to re-publish"
                    .to_string(),
            );
        }
        if response.status().as_u16() == 403 {
            return Err(
                "GitHub refused the relay fetch (rate limit or network policy)".to_string(),
            );
        }
        if !response.status().is_success() {
            return Err(failure("relay fetch", response).await);
        }
        let text = response
            .text()
            .await
            .map_err(|e| format!("relay fetch response: {e}"))?;
        return decode_bundle(&text);
    }
    Err("share not found — it was deleted, expired, or the link is wrong".to_string())
}

/// Fetch a gist without a token. With an owner we use the raw host (secret
/// gists included); without one we fall back to the unauthenticated API.
pub async fn fetch(owner: Option<&str>, gist_id: &str) -> Result<Vec<u8>, String> {
    if !is_gist_id(gist_id) {
        return Err("bad gist id in share link".to_string());
    }
    if let Some(owner) = owner {
        return fetch_raw(owner, gist_id).await;
    }
    let response = http()?
        .get(format!("{}/gists/{gist_id}", api_base()))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", API_VERSION)
        .send()
        .await
        .map_err(|e| format!("relay fetch: {e}"))?;
    let status = response.status();
    if status.as_u16() == 404 {
        return Err("share not found — it was deleted, expired, or the link is wrong".to_string());
    }
    if status.as_u16() == 403 {
        return Err("GitHub refused the relay fetch (rate limit or network policy)".to_string());
    }
    if !status.is_success() {
        return Err(failure("relay fetch", response).await);
    }
    let text = response
        .text()
        .await
        .map_err(|e| format!("relay fetch response: {e}"))?;
    let gist: GistResponse =
        serde_json::from_str(&text).map_err(|e| format!("relay fetch response: {e}"))?;
    let file = gist
        .files
        .get(GIST_FILE)
        .or_else(|| {
            if gist.files.len() == 1 {
                gist.files.values().next()
            } else {
                None
            }
        })
        .ok_or_else(|| "relay object does not contain a share bundle".to_string())?;
    if file.truncated == Some(true) {
        return Err("relay object is truncated".to_string());
    }
    let content = file
        .content
        .as_deref()
        .ok_or_else(|| "relay object has no content".to_string())?;
    decode_bundle(content)
}

/// Delete a published gist (sender only). A missing gist is already gone.
pub async fn delete(gist_id: &str) -> Result<(), String> {
    if !is_gist_id(gist_id) {
        return Err("bad gist id".to_string());
    }
    let tok = token()?;
    let response = http()?
        .delete(format!("{}/gists/{gist_id}", api_base()))
        .bearer_auth(tok.as_str())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", API_VERSION)
        .send()
        .await
        .map_err(|e| format!("relay delete: {e}"))?;
    if response.status().as_u16() == 404 {
        return Ok(());
    }
    if !response.status().is_success() {
        return Err(failure("relay delete", response).await);
    }
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    crate::tokio_rt().ok_or_else(|| "could not start network runtime".to_string())
}

// Blocking wrappers for the CLI and the Slint callbacks (both run on plain
// threads). Tests use these too, except the pure/async cases.

pub fn publish_sync(bundle: &[u8]) -> Result<Published, String> {
    runtime()?.block_on(publish(bundle))
}

pub fn fetch_sync(owner: Option<&str>, gist_id: &str) -> Result<Vec<u8>, String> {
    runtime()?.block_on(fetch(owner, gist_id))
}

pub fn delete_sync(gist_id: &str) -> Result<(), String> {
    runtime()?.block_on(delete(gist_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    // `PV_RELAY_API` is process-wide; serialize the network tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const GIST_ID: &str = "0123456789abcdef0123456789abcdef";

    /// Tiny HTTP/1.1 mock: POST /gists, GET /gists/<id>, DELETE /gists/<id>.
    /// It records the last request body and serves one fixed bundle.
    fn mock_server(bundle: &[u8]) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let b64 = STANDARD.encode(bundle);
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = vec![0u8; 64 * 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let first = req.lines().next().unwrap_or("").to_string();
                seen.push(first.clone());
                if first.starts_with("POST /gists") {
                    let body =
                        format!(r#"{{"id":"{GIST_ID}","owner":{{"login":"tester"}}}}"#);
                    write!(
                        stream,
                        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                } else if first.starts_with(&format!("GET /tester/{GIST_ID}/raw/")) {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b64}",
                        b64.len()
                    )
                    .unwrap();
                } else if first.starts_with("GET /gists/") {
                    let body = format!(
                        r#"{{"files":{{"{GIST_FILE}":{{"content":"{b64}","truncated":false}}}}}}"#
                    );
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                } else if first.starts_with("DELETE /gists/") {
                    write!(
                        stream,
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .unwrap();
                } else {
                    write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .unwrap();
                }
                let _ = stream.flush();
            }
            seen
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn gist_ids_and_owners_are_strict() {
        assert!(is_gist_id(GIST_ID));
        assert!(!is_gist_id("short"));
        assert!(!is_gist_id(&format!("{}g", "a".repeat(31))));
        assert!(is_gist_owner("tester"));
        assert!(is_gist_owner("zjhasan13"));
        assert!(!is_gist_owner(""));
        assert!(!is_gist_owner("-bad"));
        assert!(!is_gist_owner("bad-"));
        assert!(!is_gist_owner("bad_name"));
    }

    #[test]
    fn publish_fetch_delete_roundtrip_over_mock_api() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut bundle = b"PVSH1".to_vec();
        bundle.extend_from_slice(&[7u8; 64]);
        let (base, server) = mock_server(&bundle);
        std::env::set_var("PV_RELAY_API", &base);
        std::env::set_var("PV_RELAY_RAW", &base);
        set_test_token(Some("ghp_test-token"));

        let published = publish_sync(&bundle).unwrap();
        assert_eq!(published.gist_id, GIST_ID);
        assert_eq!(published.owner, "tester");
        // Raw host (the generated link path) and the legacy API path agree.
        assert_eq!(
            fetch_sync(Some("tester"), &published.gist_id).unwrap(),
            bundle
        );
        assert_eq!(fetch_sync(None, &published.gist_id).unwrap(), bundle);
        delete_sync(&published.gist_id).unwrap();

        let seen = server.join().unwrap();
        assert!(seen[0].starts_with("POST /gists"));
        assert!(seen[1].starts_with(&format!("GET /tester/{GIST_ID}/raw/")));
        assert!(seen[2].starts_with(&format!("GET /gists/{GIST_ID}")));
        assert!(seen[3].starts_with(&format!("DELETE /gists/{GIST_ID}")));

        set_test_token(None);
        std::env::remove_var("PV_RELAY_API");
        std::env::remove_var("PV_RELAY_RAW");
    }

    #[test]
    fn oversized_and_missing_relay_objects_fail_closed() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        assert!(publish_sync(&vec![0u8; MAX_RELAY_BUNDLE + 1]).is_err());
        assert!(fetch_sync(None, "not-a-gist-id").is_err());
        assert!(fetch_sync(Some("tester"), "not-a-gist-id").is_err());
        assert!(delete_sync("not-a-gist-id").is_err());
    }
}
