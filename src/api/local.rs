//! A23: loopback-only read API (`127.0.0.1`) with per-request approval.
//!
//! Threat model: the token is a bearer secret sealed with DPAPI for this user;
//! a same-user process can steal it. That is why every read also creates a
//! **pending request** that the app must Allow (30s window), and every decision
//! is audit-logged. The listener never binds anything but loopback.
//!
//! Threading: the HTTP worker never touches Slint. `GET /v1/get` returns
//! `202 {request_id}` and stores the requested value; the UI thread polls
//! `pending_front()` (Slint `Timer`) and calls `decide_current`. The CLI polls
//! `GET /v1/result?id=...` until the decision exists.

use crate::api::token;
use crate::models::Vault;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const MAX_REQUESTS_PER_MIN: usize = 30;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// How long a pending request stays valid (approval window + CLI poll).
const PENDING_TTL: Duration = Duration::from_secs(60);

struct PendingRequest {
    id: String,
    prompt: String,
    decision: Option<bool>,
    value: Option<String>,
    created: Instant,
}

fn pending_slot() -> &'static Mutex<Vec<PendingRequest>> {
    static SLOT: OnceLock<Mutex<Vec<PendingRequest>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(Vec::new()))
}

fn cleanup_locked(now: Instant) {
    let mut q = pending_slot().lock().unwrap_or_else(|p| p.into_inner());
    q.retain(|r| now.duration_since(r.created) < PENDING_TTL);
}

/// UI thread: the oldest undecided, unexpired request `(id, prompt)`.
pub fn pending_front() -> Option<(String, String)> {
    let now = Instant::now();
    cleanup_locked(now);
    let q = pending_slot().lock().unwrap_or_else(|p| p.into_inner());
    q.iter()
        .find(|r| r.decision.is_none())
        .map(|r| (r.id.clone(), r.prompt.clone()))
}

/// UI thread: answer the oldest undecided request.
pub fn decide_current(allow: bool) {
    let mut q = pending_slot().lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    if let Some(r) = q
        .iter_mut()
        .find(|r| r.decision.is_none() && now.duration_since(r.created) < PENDING_TTL)
    {
        r.decision = Some(allow);
    }
}

/// Test/cleanup helper: drop every pending request (zeroizing values).
pub fn clear_pending() {
    let mut q = pending_slot().lock().unwrap_or_else(|p| p.into_inner());
    for r in q.iter_mut() {
        if let Some(v) = r.value.as_mut() {
            v.zeroize();
        }
    }
    q.clear();
}

pub struct ApiState {
    pub vault: Arc<Mutex<Vault>>,
    pub master: Arc<Mutex<Option<SecretString>>>,
    hits: Mutex<Vec<Instant>>,
}

impl ApiState {
    pub fn new(vault: Arc<Mutex<Vault>>, master: Arc<Mutex<Option<SecretString>>>) -> Self {
        Self {
            vault,
            master,
            hits: Mutex::new(Vec::new()),
        }
    }

    fn rate_ok(&self) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(|p| p.into_inner());
        let cutoff = Instant::now() - Duration::from_secs(60);
        hits.retain(|t| *t > cutoff);
        if hits.len() >= MAX_REQUESTS_PER_MIN {
            return false;
        }
        hits.push(Instant::now());
        true
    }

    fn locked(&self) -> bool {
        self.master
            .lock()
            .map(|m| m.is_none())
            .unwrap_or(true)
    }
}

pub struct ApiServer {
    pub port: u16,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ApiServer {
    /// Stops the listener and removes the port file. The caller owns token
    /// revocation (`token::revoke`) so an explicit disable clears both.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(token::port_path());
        clear_pending();
    }
}

pub fn start(
    vault: Arc<Mutex<Vault>>,
    master: Arc<Mutex<Option<SecretString>>>,
) -> Result<ApiServer, String> {
    // A valid token must exist before the listener opens.
    let _ = token::load()?;
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| format!("local API bind failed: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("local API address: {e}"))?
        .port();
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("local API nonblocking: {e}"))?;
    token::write_port(port)?;
    clear_pending();
    let state = Arc::new(ApiState::new(vault, master));
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let join = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    serve_conn(stream, &state);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    Ok(ApiServer {
        port,
        stop,
        join: Some(join),
    })
}

fn serve_conn(mut stream: TcpStream, state: &ApiState) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_REQUEST_BYTES {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    if buf.is_empty() || buf.len() > MAX_REQUEST_BYTES {
        return;
    }
    let Some((method, path, _body, headers)) =
        crate::sync::p2p_local::parse_http_request_headers(&buf)
    else {
        let _ = stream.write_all(&http_response(400, r#"{"ok":false,"error":"bad request"}"#));
        return;
    };
    let (status, mut body) = handle_request(state, &method, &path, &headers);
    let _ = stream.write_all(&http_response(status, &body));
    body.zeroize();
}

fn http_response(status: u16, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        423 => "Locked",
        429 => "Too Many Requests",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn authorized(headers: &HashMap<String, String>) -> bool {
    let Some(auth) = headers.get("authorization") else {
        return false;
    };
    let Some(got) = auth.strip_prefix("Bearer ") else {
        return false;
    };
    let Ok(tok) = token::load() else {
        return false;
    };
    ct_eq(got.trim().as_bytes(), tok.value.expose_secret().as_bytes())
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k == key {
            return Some(
                percent_encoding::percent_decode_str(v)
                    .decode_utf8_lossy()
                    .into_owned(),
            );
        }
    }
    None
}

fn json_error(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

fn new_request_id() -> String {
    use rand_core::RngCore;
    let mut raw = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// Pure-ish request handler (also the unit-test entry point).
pub fn handle_request(
    state: &ApiState,
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
) -> (u16, String) {
    if method != "GET" {
        return (405, json_error("only GET is supported"));
    }
    if !authorized(headers) {
        return (401, json_error("missing, invalid or expired API token"));
    }
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    // Status is cheap; don't burn the read rate limit on it.
    if route == "/v1/status" {
        let locked = state.locked();
        return (
            200,
            serde_json::json!({
                "ok": true,
                "locked": locked,
                "version": env!("CARGO_PKG_VERSION"),
            })
            .to_string(),
        );
    }
    if !state.rate_ok() {
        return (429, json_error("rate limit: 30 requests/minute"));
    }
    match route {
        "/v1/get" => {
            if state.locked() {
                return (423, json_error("vault is locked"));
            }
            let field = query_param(query, "field").unwrap_or_else(|| "password".to_string());
            if field != "password" && field != "username" {
                return (400, json_error("field must be password or username"));
            }
            let id = query_param(query, "id");
            let title = query_param(query, "title");
            if id.is_none() && title.is_none() {
                return (400, json_error("pass id= or title="));
            }
            let (cred_id, title_text, value) = {
                let vault = state
                    .vault
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                let mut matches: Vec<&crate::models::Credential> = vault
                    .credentials
                    .iter()
                    .filter(|c| c.deleted_at.is_none())
                    .filter(|c| match (&id, &title) {
                        (Some(id), _) => c.id.eq_ignore_ascii_case(id),
                        (None, Some(t)) => c.title.eq_ignore_ascii_case(t),
                        _ => false,
                    })
                    .collect();
                if matches.len() > 1 {
                    return (409, json_error("ambiguous title — use id="));
                }
                let Some(c) = matches.pop() else {
                    return (404, json_error("no matching login"));
                };
                let value = if field == "username" {
                    c.username.clone()
                } else {
                    c.password.clone()
                };
                (c.id.clone(), c.title.clone(), value)
            };
            // Enqueue one pending request; the UI thread answers it.
            cleanup_locked(Instant::now());
            let request_id = new_request_id();
            let prompt = format!("pv: read the {field} of “{title_text}”");
            pending_slot()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(PendingRequest {
                    id: request_id.clone(),
                    prompt,
                    decision: None,
                    value: Some(value),
                    created: Instant::now(),
                });
            crate::security::access_log::log_event(
                "api",
                &format!("request {cred_id} {field}"),
            );
            (
                202,
                serde_json::json!({
                    "ok": true,
                    "pending": true,
                    "request_id": request_id,
                })
                .to_string(),
            )
        }
        "/v1/result" => {
            let Some(request_id) = query_param(query, "id") else {
                return (400, json_error("pass id="));
            };
            let now = Instant::now();
            let mut q = pending_slot().lock().unwrap_or_else(|p| p.into_inner());
            let Some(idx) = q.iter().position(|r| r.id == request_id) else {
                return (404, json_error("unknown or expired request"));
            };
            if now.duration_since(q[idx].created) >= PENDING_TTL {
                if let Some(v) = q[idx].value.as_mut() {
                    v.zeroize();
                }
                q.remove(idx);
                return (408, json_error("approval timed out"));
            }
            match q[idx].decision {
                None => (
                    202,
                    serde_json::json!({ "ok": true, "pending": true }).to_string(),
                ),
                Some(false) => {
                    if let Some(v) = q[idx].value.as_mut() {
                        v.zeroize();
                    }
                    let title = q[idx].prompt.clone();
                    q.remove(idx);
                    crate::security::access_log::log_event("api", "denied");
                    (403, json_error(&format!("denied in the app ({title})")))
                }
                Some(true) => {
                    let mut req = q.remove(idx);
                    let mut value = req.value.take().unwrap_or_default();
                    crate::security::access_log::log_event("api", "allowed");
                    let body = serde_json::json!({
                        "ok": true,
                        "field": "",
                        "value": value,
                    })
                    .to_string();
                    value.zeroize();
                    (200, body)
                }
            }
        }
        _ => (404, json_error("unknown endpoint")),
    }
}

/// Resolve the app's token/port directory for the CLI: explicit env override,
/// current directory, then the executable's directory.
pub fn client_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("PV_API_DIR") {
        let p = std::path::PathBuf::from(dir);
        if p.join(token::TOKEN_FILE).is_file() {
            return Some(p);
        }
    }
    let cwd = std::env::current_dir().ok();
    if let Some(p) = cwd.as_ref() {
        if p.join(token::TOKEN_FILE).is_file() {
            return Some(p.clone());
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    if dir.join(token::TOKEN_FILE).is_file() {
        return Some(dir.to_path_buf());
    }
    None
}

/// CLI helper: GET a local API path with the bearer token.
pub fn client_get(
    dir: &Path,
    path_and_query: &str,
    timeout: Duration,
) -> Result<(u16, String), String> {
    let token = {
        let path = dir.join(token::TOKEN_FILE);
        let blob = std::fs::read(&path).map_err(|_| {
            "local API is off (token file missing) — enable it in Settings".to_string()
        })?;
        let secret = crate::core::memory::DpapiGuard::unprotect(&blob)
            .map_err(|_| "cannot unseal the API token".to_string())?;
        #[derive(serde::Deserialize)]
        struct Stored {
            token: String,
            expires: u64,
        }
        let stored: Stored = serde_json::from_slice(secret.expose())
            .map_err(|_| "API token file is corrupt".to_string())?;
        if stored.expires <= token::now_secs() {
            return Err("API token expired — toggle the local API off/on".to_string());
        }
        stored.token
    };
    let port = {
        let text = std::fs::read_to_string(dir.join(token::PORT_FILE))
            .map_err(|_| "local API is not running".to_string())?;
        text.trim()
            .parse::<u16>()
            .map_err(|_| "API port file is corrupt".to_string())?
    };
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|_| "local API is not reachable (is the app unlocked?)".to_string())?;
    let _ = stream.set_read_timeout(Some(timeout));
    let req = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("API write failed: {e}"))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            // Windows can surface a graceful server close as a reset after the
            // body is already buffered; keep what we have.
            Err(e)
                if !raw.is_empty()
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ) =>
            {
                break;
            }
            Err(e) => return Err(format!("API read failed: {e}")),
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed API response".to_string())?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "malformed API status".to_string())?;
    Ok((status, body.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Vault};

    fn state(locked: bool) -> ApiState {
        let mut vault = Vault::new();
        vault.credentials.push(Credential {
            id: "id-1".into(),
            title: "Gmail".into(),
            username: "u@example.com".into(),
            password: "s3cret!".into(),
            totp_secret: String::new(),
            urls: Vec::new(),
            apps: Vec::new(),
            backup_codes: Vec::new(),
            custom_fields: Vec::new(),
            notes: String::new(),
            folder: String::new(),
            reprompt: false,
            attachments: Vec::new(),
            travel_safe: false,
            last_changed: 0,
            password_history: Vec::new(),
            favorite: false,
            deleted_at: None,
        });
        let master = Arc::new(Mutex::new(if locked {
            None
        } else {
            Some(SecretString::new("pw".to_string()))
        }));
        ApiState::new(Arc::new(Mutex::new(vault)), master)
    }

    fn authed() -> HashMap<String, String> {
        let tok = token::load().unwrap();
        let mut h = HashMap::new();
        h.insert(
            "authorization".to_string(),
            format!("Bearer {}", tok.value.expose_secret()),
        );
        h
    }

    fn setup_token() {
        let dir = std::env::temp_dir().join(format!("pv-api-handler-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("PV_API_TOKEN_FILE", dir.join("t.dpapi"));
        std::env::set_var("PV_API_PORT_FILE", dir.join("port"));
        token::revoke();
        token::create().unwrap();
        clear_pending();
    }

    #[test]
    fn handler_enforces_token_lock_approval_and_rate() {
        let _guard = crate::api::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        setup_token();
        let h = authed();
        let st = state(false);
        // No/bad token.
        assert_eq!(handle_request(&st, "GET", "/v1/status", &HashMap::new()).0, 401);
        let mut bad = h.clone();
        bad.insert("authorization".into(), "Bearer deadbeef".into());
        assert_eq!(handle_request(&st, "GET", "/v1/status", &bad).0, 401);
        // Status works.
        let (code, body) = handle_request(&st, "GET", "/v1/status", &h);
        assert_eq!(code, 200);
        assert!(body.contains("\"locked\":false"));
        // Read -> 202 + request id; result pending until a decision.
        let (code, body) = handle_request(&st, "GET", "/v1/get?title=Gmail&field=password", &h);
        assert_eq!(code, 202);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let rid = v.get("request_id").unwrap().as_str().unwrap().to_string();
        let path = format!("/v1/result?id={rid}");
        assert_eq!(handle_request(&st, "GET", &path, &h).0, 202);
        let (id, prompt) = pending_front().unwrap();
        assert_eq!(id, rid);
        assert!(prompt.contains("Gmail"));
        decide_current(true);
        let (code, body) = handle_request(&st, "GET", &path, &h);
        assert_eq!(code, 200);
        assert!(body.contains("s3cret!"));
        // Request is consumed.
        assert_eq!(handle_request(&st, "GET", &path, &h).0, 404);
        // Denied.
        let (_, body) = handle_request(&st, "GET", "/v1/get?id=id-1&field=username", &h);
        let rid = serde_json::from_str::<serde_json::Value>(&body).unwrap()["request_id"]
            .as_str()
            .unwrap()
            .to_string();
        decide_current(false);
        assert_eq!(
            handle_request(&st, "GET", &format!("/v1/result?id={rid}"), &h).0,
            403
        );
        // Unknown / bad field.
        assert_eq!(handle_request(&st, "GET", "/v1/get?title=Nope", &h).0, 404);
        assert_eq!(
            handle_request(&st, "GET", "/v1/get?title=Gmail&field=totp", &h).0,
            400
        );
        // Locked vault.
        let locked = state(true);
        assert_eq!(
            handle_request(&locked, "GET", "/v1/get?title=Gmail", &h).0,
            423
        );
        // Rate limit (30/min).
        let limited = state(false);
        for _ in 0..MAX_REQUESTS_PER_MIN {
            let _ = handle_request(&limited, "GET", "/v1/status", &h);
            let _ = handle_request(&limited, "GET", "/v1/get?title=Nope", &h);
        }
        // status is exempt; get must trip after 30.
        for _ in 0..MAX_REQUESTS_PER_MIN {
            let _ = handle_request(&limited, "GET", "/v1/get?title=Nope", &h);
        }
        assert_eq!(
            handle_request(&limited, "GET", "/v1/get?title=Nope", &h).0,
            429
        );
    }

    #[test]
    fn loopback_get_waits_for_ui_approval_and_returns_the_value() {
        let _guard = crate::api::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("pv-api-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PV_API_TOKEN_FILE", dir.join(token::TOKEN_FILE));
        std::env::set_var("PV_API_PORT_FILE", dir.join(token::PORT_FILE));
        token::revoke();
        token::create().unwrap();
        clear_pending();

        let st = state(false);
        let server = start(Arc::clone(&st.vault), Arc::clone(&st.master)).unwrap();
        let api_dir = dir.clone();
        // Simulate the UI thread: approve the first pending request.
        let ui = std::thread::spawn(move || {
            for _ in 0..200 {
                if pending_front().is_some() {
                    decide_current(true);
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let (code, body) = client_get(
            &api_dir,
            "/v1/get?title=Gmail&field=password",
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(code, 202);
        let rid = serde_json::from_str::<serde_json::Value>(&body).unwrap()["request_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut result = (0, String::new());
        for _ in 0..100 {
            result = client_get(
                &api_dir,
                &format!("/v1/result?id={rid}"),
                Duration::from_secs(5),
            )
            .unwrap();
            if result.0 != 202 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(result.0, 200, "body: {}", result.1);
        assert!(result.1.contains("s3cret!"));
        ui.join().unwrap();
        server.stop();
        token::revoke();
        std::env::remove_var("PV_API_TOKEN_FILE");
        std::env::remove_var("PV_API_PORT_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
