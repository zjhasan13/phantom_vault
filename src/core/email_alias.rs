//! Privacy email aliases (Batch-4): Addy.io / SimpleLogin forwarders.
//!
//! Shapes follow the vendors' public REST docs:
//! - Addy.io: `POST {base}/api/v1/aliases`, `Authorization: Bearer <token>`,
//!   JSON body `{"domain": <id-or-shared-domain>, "description": ...}` →
//!   response `{"data": {"email": ...}}`.
//! - SimpleLogin: `POST {base}/api/alias/random/new`, raw-key header
//!   `Authentication: <key>` (NOT Bearer) — response `{"alias": ...}`.
//!
//! The API token is DPAPI-sealed on disk (`alias_token.dpapi`); the provider
//! choice + Addy domain ride alongside in `alias_provider.txt`. Server-side
//! error bodies are surfaced verbatim so misconfiguration is diagnosable.
//! Request building + response parsing are pure (fixture-tested); only the
//! final `create_alias` touches the network, and tests pin it against a
//! loopback mock server — no vendor account needed.

use crate::error::{Result, VaultError};
use zeroize::Zeroize;

const TOKEN_FILE: &str = "alias_token.dpapi";
const PROVIDER_FILE: &str = "alias_provider.txt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    AddyIo,
    SimpleLogin,
}

impl Provider {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Provider::SimpleLogin,
            _ => Provider::AddyIo,
        }
    }

    pub fn to_i32(self) -> i32 {
        match self {
            Provider::AddyIo => 0,
            Provider::SimpleLogin => 1,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Provider::AddyIo => "Addy.io",
            Provider::SimpleLogin => "SimpleLogin",
        }
    }
}

/// Persist provider + domain (plain) and token (DPAPI-sealed, zeroized).
pub fn save_config(provider: Provider, domain: &str, token: &str) -> Result<()> {
    let mut owned = token.trim().to_string();
    if owned.is_empty() {
        return Err(VaultError::Sync("alias API token required".into()));
    }
    let blob = crate::core::memory::DpapiGuard::protect(owned.as_bytes())
        .map_err(|e| VaultError::Sync(format!("token seal failed: {e}")))?;
    owned.zeroize();
    std::fs::write(TOKEN_FILE, blob)
        .map_err(|e| VaultError::Sync(format!("token store failed: {e}")))?;
    std::fs::write(PROVIDER_FILE, format!("{}\n{}", provider.to_i32(), domain.trim()))
        .map_err(|e| VaultError::Sync(format!("provider store failed: {e}")))?;
    Ok(())
}

/// Load `(provider, domain, token)`. Missing files = "not configured".
pub fn load_config() -> Result<(Provider, String, String)> {
    let raw = std::fs::read_to_string(PROVIDER_FILE)
        .map_err(|_| VaultError::Sync("alias provider not configured".into()))?;
    let mut lines = raw.lines();
    let provider = lines
        .next()
        .and_then(|l| l.trim().parse::<i32>().ok())
        .map(Provider::from_i32)
        .unwrap_or(Provider::AddyIo);
    let domain = lines.next().unwrap_or("").trim().to_string();
    let blob =
        std::fs::read(TOKEN_FILE).map_err(|_| VaultError::Sync("alias token missing".into()))?;
    let secret = crate::core::memory::DpapiGuard::unprotect(&blob)
        .map_err(|e| VaultError::Sync(format!("token unseal failed: {e}")))?;
    let token = String::from_utf8_lossy(secret.expose()).into_owned();
    drop(secret);
    if token.trim().is_empty() {
        return Err(VaultError::Sync("stored alias token is empty".into()));
    }
    Ok((provider, domain, token))
}

/// Pure request construction: (url, headers, json body). Unit-tested.
pub fn build_request(
    provider: Provider,
    base_url: &str,
    token: &str,
    domain: &str,
    description: &str,
) -> (String, Vec<(String, String)>, serde_json::Value) {
    let base = base_url.trim_end_matches('/');
    match provider {
        Provider::AddyIo => (
            format!("{base}/api/v1/aliases"),
            vec![
                ("Authorization".into(), format!("Bearer {}", token.trim())),
                ("Accept".into(), "application/json".into()),
            ],
            serde_json::json!({"domain": domain, "description": description}),
        ),
        Provider::SimpleLogin => (
            format!("{base}/api/alias/random/new"),
            vec![("Authentication".into(), token.trim().to_string())],
            serde_json::json!({}),
        ),
    }
}

/// Pure response parsing: extract the forwarder address. Unit-tested.
pub fn parse_response(provider: Provider, body: &serde_json::Value) -> Result<String> {
    let email = match provider {
        Provider::AddyIo => body
            .get("data")
            .and_then(|d| d.get("email"))
            .and_then(|e| e.as_str()),
        Provider::SimpleLogin => body.get("alias").and_then(|e| e.as_str()),
    };
    match email {
        Some(e) if !e.trim().is_empty() => Ok(e.trim().to_string()),
        _ => Err(VaultError::Sync(format!(
            "alias parse failed ({}): unexpected payload",
            provider.name()
        ))),
    }
}

/// Live call: build → POST → surface server errors verbatim → parse.
pub async fn create_alias(
    client: &reqwest::Client,
    provider: Provider,
    base_url: &str,
    token: &str,
    domain: &str,
    description: &str,
) -> Result<String> {
    let (url, headers, body) = build_request(provider, base_url, token, domain, description);
    // NOTE: reqwest runs WITHOUT its `json` feature (lean TLS-only build),
    // so the body goes out as an explicit JSON string — same bytes, no dep.
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| VaultError::Sync(format!("alias JSON encode: {e}")))?;
    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body_bytes);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| VaultError::Sync(format!("alias API unreachable: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| VaultError::Sync(format!("alias API read failed: {e}")))?;
    if !status.is_success() {
        // Vendor error payloads (e.g. Addy's {"message": ...}) go straight
        // to the user — guessing would hide misconfiguration.
        let hint: String = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .or_else(|| v.get("error"))
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| text.chars().take(200).collect());
        return Err(VaultError::Sync(format!("alias API {status}: {hint}")));
    }
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| VaultError::Sync(format!("alias JSON: {e}")))?;
    parse_response(provider, &json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shapes_match_vendor_docs() {
        let (url, headers, body) = build_request(
            Provider::AddyIo,
            "https://app.addy.io/",
            "tok",
            "shared-dom",
            "vault",
        );
        assert_eq!(url, "https://app.addy.io/api/v1/aliases");
        assert!(headers.iter().any(|(k, v)| k == "Authorization" && v == "Bearer tok"));
        assert_eq!(body["domain"], "shared-dom");
        assert_eq!(body["description"], "vault");

        let (url, headers, body) = build_request(
            Provider::SimpleLogin,
            "https://app.simplelogin.io",
            "rawkey",
            "",
            "",
        );
        assert_eq!(url, "https://app.simplelogin.io/api/alias/random/new");
        // SimpleLogin takes the RAW key — Bearer here would 401.
        assert!(headers.iter().any(|(k, v)| k == "Authentication" && v == "rawkey"));
        assert!(!headers.iter().any(|(k, _)| k == "Authorization"));
        assert!(body.as_object().unwrap().is_empty());
    }

    #[test]
    fn response_parsing_and_rejects() {
        let addy = serde_json::json!({"data": {"email": "a@addy.io", "id": "1"}});
        assert_eq!(parse_response(Provider::AddyIo, &addy).unwrap(), "a@addy.io");
        let sl = serde_json::json!({"alias": "x@aleeas.com"});
        assert_eq!(parse_response(Provider::SimpleLogin, &sl).unwrap(), "x@aleeas.com");
        assert!(parse_response(Provider::AddyIo, &sl).is_err());
        assert!(parse_response(Provider::SimpleLogin, &addy).is_err());
        assert!(parse_response(Provider::AddyIo, &serde_json::json!({"data": {"email": " "}})).is_err());
    }

    /// Loopback mock vendor: canned JSON over real HTTP, asserting the exact
    /// auth header the client sends. No vendor account, no internet.
    /// NOTE: header NAMES go lowercase on the wire (http crate normalizes),
    /// so the expectation is matched case-insensitively; VALUES keep case.
    async fn mock_vendor(expected_auth: &'static str, payload: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        clear_proxy_env();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(
                head.to_lowercase().contains(&expected_auth.to_lowercase()),
                "mock vendor must see {expected_auth}"
            );
            let body = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = sock.write_all(body.as_bytes()).await;
        });
        format!("http://{addr}")
    }

    /// Hermetic tests: proxy env would reroute loopback through a corporate
    /// proxy (reqwest honors system proxy). Only these tests care about the
    /// vars, and clearing is monotonic — safe under parallel execution.
    fn clear_proxy_env() {
        for k in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            std::env::remove_var(k);
        }
    }

    #[tokio::test]
    async fn addy_mock_roundtrip() {
        let base = mock_vendor(
            "Authorization: Bearer MOCKTOK",
            r#"{"data":{"email":"vault99@addy.io"}}"#,
        )
        .await;
        let client = reqwest::Client::new();
        let email = create_alias(&client, Provider::AddyIo, &base, "MOCKTOK", "d", "vault")
            .await
            .unwrap();
        assert_eq!(email, "vault99@addy.io");
    }

    #[tokio::test]
    async fn simplelogin_mock_roundtrip() {
        let base = mock_vendor(
            "Authentication: RAWKEY",
            r#"{"alias":"vault99@aleeas.com"}"#,
        )
        .await;
        let client = reqwest::Client::new();
        let email = create_alias(&client, Provider::SimpleLogin, &base, "RAWKEY", "", "")
            .await
            .unwrap();
        assert_eq!(email, "vault99@aleeas.com");
    }

    #[tokio::test]
    async fn server_error_surfaces_message() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let body = r#"{"message":"The domain field is required."}"#;
            let resp = format!(
                "HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
        let client = reqwest::Client::new();
        let err = create_alias(
            &client,
            Provider::AddyIo,
            &format!("http://{addr}"),
            "MOCKTOK",
            "",
            "",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("domain field is required"));
    }
}
