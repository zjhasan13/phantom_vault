//! Local Wi-Fi P2P sync (offline LAN, LocalSend-style). std-only: UDP
//! beacons + minimal HTTP/1.1 over TCP — no internet, no cloud, no new deps.
//!
//! Safety contract (zero-knowledge preserved):
//! - Only CIPHERTEXT (`my_secure_vault.enc` bytes) crosses the Wi-Fi. Keys,
//!   passwords, and plaintext never touch the socket.
//! - Conflict guard: blobs carry SHA-256 + file mtime. Newer mtime wins;
//!   equal mtime with different SHA = conflict → keep local, report loudly,
//!   never auto-merge ciphertext.
//! - Binds LAN port 52199 only while the user enables discovery (default OFF).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// LAN port for beacons + sync HTTP.
pub const P2P_PORT: u16 = 52199;
/// Peer discovery beacon interval.
const BEACON_EVERY: Duration = Duration::from_secs(5);
/// Cap: vault blobs bigger than this are refused (DoS guard, mirrors import).
const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub name: String,
    pub ip: String,
    pub version: String,
    pub head_sha: String,
}

/// Presence beacon. `head_sha`/`mtime` describe the CIPHERTEXT only.
pub fn beacon_json(version: &str, head_sha: &str) -> String {
    let name = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "PC".to_string());
    serde_json::json!({
        "app": "phantom_vault",
        "name": name,
        "version": version,
        "port": P2P_PORT,
        "head_sha": head_sha,
    })
    .to_string()
}

/// Validate + parse a beacon datagram. Source IP comes from the socket, not
/// the payload (a beacon cannot lie about where it was heard).
pub fn parse_beacon(text: &str, from_ip: &str) -> Option<Peer> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    if v.get("app").and_then(|a| a.as_str()) != Some("phantom_vault") {
        return None;
    }
    // Never peer with ourselves (our own broadcast echo).
    if let Ok(local) = local_lan_ips() {
        if local.iter().any(|ip| ip == from_ip) {
            return None;
        }
    }
    Some(Peer {
        name: v.get("name").and_then(|n| n.as_str()).unwrap_or("Peer").to_string(),
        ip: from_ip.to_string(),
        version: v.get("version").and_then(|n| n.as_str()).unwrap_or("?").to_string(),
        head_sha: v.get("head_sha").and_then(|n| n.as_str()).unwrap_or("").to_string(),
    })
}

/// Best-effort local IPv4s (for self-echo filtering). Pure-ish, never fails.
fn local_lan_ips() -> Result<Vec<String>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    // No packet is sent — connect() only picks the outbound interface.
    sock.connect("8.8.8.8:80").map_err(|e| e.to_string())?;
    let ip = sock.local_addr().map_err(|e| e.to_string())?.ip().to_string();
    Ok(vec![ip, "127.0.0.1".to_string(), "::1".to_string()])
}

/// SHA-256 hex of bytes (head comparison without decryption).
pub fn sha_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex_encode(&sha2::Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// Local ciphertext head: (sha, mtime_secs). Missing file → ("", 0).
pub fn local_head() -> (String, u64) {
    let path = std::path::Path::new(crate::developer::vault_run::VAULT_FILE);
    let bytes = std::fs::read(path).unwrap_or_default();
    let sha = if bytes.is_empty() { String::new() } else { sha_hex(&bytes) };
    let mtime = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (sha, mtime)
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 framing (server + client share these)
// ---------------------------------------------------------------------------

/// Split a raw HTTP request into (method, path, body). Pure — unit tested.
pub fn parse_http_request(raw: &[u8]) -> Option<(String, String, Vec<u8>)> {
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..head_end]).ok()?;
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_uppercase();
    let path = parts.next().unwrap_or("/").to_string();
    let mut content_len = 0usize;
    for line in lines {
        if let Some(v) = line.strip_prefix("Content-Length:").or_else(|| line.strip_prefix("content-length:")) {
            content_len = v.trim().parse().unwrap_or(0);
        }
    }
    if content_len > MAX_BLOB_BYTES {
        return None;
    }
    let body = raw[head_end + 4..].to_vec();
    if body.len() < content_len {
        return None; // caller keeps reading
    }
    Some((method, path, body[..content_len.min(body.len())].to_vec()))
}

fn http_response(status: u16, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Route one request. Pure decision surface (no FS here — the caller adopts).
/// Returns (status, body, optional adoption).
pub fn route(
    method: &str,
    path: &str,
    body: &[u8],
    local_blob: &[u8],
    local_sha: &str,
    local_mtime: u64,
) -> (u16, String, Option<(String, Vec<u8>)>) {
    if method == "GET" && path == "/p2p/pull" {
        let body = serde_json::json!({
            "sha": local_sha,
            "mtime": local_mtime,
            "blob_b64": base64_encode(local_blob),
        })
        .to_string();
        return (200, body, None);
    }
    if method == "POST" && path == "/p2p/sync" {
        let v: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return (400, r#"{"ok":false,"error":"bad json"}"#.into(), None),
        };
        let sha = v.get("sha").and_then(|s| s.as_str()).unwrap_or("").to_string();
        let blob_b64 = v.get("blob_b64").and_then(|s| s.as_str()).unwrap_or("");
        if sha.is_empty() || blob_b64.is_empty() {
            return (400, r#"{"ok":false,"error":"sha and blob_b64 required"}"#.into(), None);
        }
        let blob = match base64_decode(blob_b64) {
            Some(b) if b.len() <= MAX_BLOB_BYTES => b,
            _ => return (400, r#"{"ok":false,"error":"bad blob"}"#.into(), None),
        };
        if sha_hex(&blob) != sha {
            return (400, r#"{"ok":false,"error":"sha mismatch"}"#.into(), None);
        }
        if sha == local_sha {
            return (200, r#"{"ok":true,"adopted":false,"reason":"already in sync"}"#.into(), None);
        }
        // Server-side freshness gate: adopt ONLY strictly-newer pushes.
        // Older-or-equal mtime = stale replay or same-age divergence → 409,
        // local kept. (A LAN attacker can still lie about mtime — pairing
        // trusts the LAN; enable discovery only on networks you trust.)
        let remote_mtime = v.get("mtime").and_then(|m| m.as_u64()).unwrap_or(0);
        if remote_mtime == 0 {
            return (400, r#"{"ok":false,"error":"mtime required"}"#.into(), None);
        }
        if remote_mtime <= local_mtime {
            return (409, r#"{"ok":false,"error":"stale or conflicting head — local kept"}"#.into(), None);
        }
        return (200, r#"{"ok":true,"adopted":true}"#.into(), Some((sha, blob)));
    }
    (404, r#"{"ok":false,"error":"unknown route"}"#.into(), None)
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn read_full_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > MAX_BLOB_BYTES + 8192 {
                    return None;
                }
                if let Some((_, _, _)) = parse_http_request(&buf) {
                    break;
                }
                // Header not complete yet — keep reading (body check inside).
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    // Headers done but body short: wait for more.
                    continue;
                }
            }
            Err(_) => break,
        }
        if buf.len() > 128 && parse_http_request(&buf).is_some() {
            break;
        }
    }
    if buf.is_empty() {
        return None;
    }
    Some(buf)
}

/// Serve ONE connection: route, optionally adopt via secure_write, respond.
fn serve_conn(mut stream: TcpStream) {
    let raw = match read_full_request(&mut stream) {
        Some(r) => r,
        None => return,
    };
    let (method, path, body) = match parse_http_request(&raw) {
        Some(t) => t,
        None => {
            let _ = stream.write_all(&http_response(400, r#"{"ok":false}"#));
            return;
        }
    };
    let blob = std::fs::read(crate::developer::vault_run::VAULT_FILE).unwrap_or_default();
    let (local_sha, local_mtime) = local_head();
    let (status, resp_body, adopt) = route(&method, &path, &body, &blob, &local_sha, local_mtime);
    if let Some((sha, data)) = adopt {
        // Newer-or-different remote head: adopt atomically. mtime comparison
        // happens client-side (sync_with_peer); the listener trusts the
        // pusher's decision, verified by SHA above.
        let path = std::path::Path::new(crate::developer::vault_run::VAULT_FILE);
        if crate::security::shredder::secure_write(path, &data).is_err() {
            let _ = stream.write_all(&http_response(400, r#"{"ok":false,"error":"adopt failed"}"#));
            return;
        }
        crate::security::access_log::log_event("p2p", &format!("adopted {sha}"));
    }
    let _ = stream.write_all(&http_response(status, &resp_body));
}

/// Blocking listener loop on `bind` (LAN or loopback). Exits on `stop`.
pub fn run_listener_on(stop: Arc<AtomicBool>, bind: SocketAddr) {
    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(_) => return,
    };
    let _ = listener.set_nonblocking(true);
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => serve_conn(stream),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Production listener on all LAN interfaces.
pub fn run_listener(stop: Arc<AtomicBool>) {
    run_listener_on(stop, SocketAddr::from(([0, 0, 0, 0], P2P_PORT)));
}

/// UDP beacon broadcaster (presence only — no secrets, ever).
pub fn run_beacon(stop: Arc<AtomicBool>) {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = sock.set_broadcast(true);
    let target = format!("255.255.255.255:{P2P_PORT}");
    while !stop.load(Ordering::Relaxed) {
        let (sha, _) = local_head();
        let msg = beacon_json(env!("CARGO_PKG_VERSION"), &sha);
        let _ = sock.send_to(msg.as_bytes(), &target);
        // Answer direct DISCOVER probes heard on our port.
        std::thread::sleep(BEACON_EVERY);
    }
}

/// Answer DISCOVER datagrams (runs inside the listener module so scans work
/// even between beacons). Call alongside run_listener, or standalone.
pub fn run_discover_responder(stop: Arc<AtomicBool>) {
    let sock = match UdpSocket::bind(format!("0.0.0.0:{P2P_PORT}")) {
        Ok(s) => s,
        Err(_) => return, // port busy (listener up?) — discovery still works via beacons
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0u8; 2048];
    while !stop.load(Ordering::Relaxed) {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]);
            if text.contains("\"DISCOVER\"") || text.contains("phantom_vault") {
                let (sha, _) = local_head();
                let reply = beacon_json(env!("CARGO_PKG_VERSION"), &sha);
                let _ = sock.send_to(reply.as_bytes(), from);
            }
        }
    }
}

/// Active LAN scan: broadcast DISCOVER, collect beacon replies for `wait`.
pub fn scan_peers(wait: Duration) -> Vec<Peer> {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = sock.set_broadcast(true);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(800)));
    let probe = r#"{"app":"phantom_vault","DISCOVER":true}"#;
    let _ = sock.send_to(probe.as_bytes(), format!("255.255.255.255:{P2P_PORT}"));
    let deadline = std::time::Instant::now() + wait;
    let mut peers = Vec::new();
    let mut buf = [0u8; 2048];
    while std::time::Instant::now() < deadline {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            if let Some(p) = parse_beacon(&text, &from.ip().to_string()) {
                if !peers.iter().any(|q: &Peer| q.ip == p.ip) {
                    peers.push(p);
                }
            }
        }
    }
    peers
}

/// Pull a peer's ciphertext head + blob.
pub fn pull_peer(addr: SocketAddr) -> Result<(String, u64, Vec<u8>), String> {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(8)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let req = "GET /p2p/pull HTTP/1.1\r\nHost: pv\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let body_start = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let v: serde_json::Value =
        serde_json::from_slice(&raw[body_start..]).map_err(|e| format!("bad pull body: {e}"))?;
    let sha = v.get("sha").and_then(|s| s.as_str()).unwrap_or("").to_string();
    let mtime = v.get("mtime").and_then(|m| m.as_u64()).unwrap_or(0);
    let blob_b64 = v.get("blob_b64").and_then(|s| s.as_str()).unwrap_or("");
    let blob = base64_decode(blob_b64).ok_or_else(|| "bad pull blob".to_string())?;
    if blob.len() > MAX_BLOB_BYTES || sha_hex(&blob) != sha {
        return Err("pull integrity failed".to_string());
    }
    Ok((sha, mtime, blob))
}

/// Push our ciphertext blob to a peer (it SHA-verifies + freshness-gates).
pub fn push_peer(addr: SocketAddr, sha: &str, mtime: u64, blob: &[u8]) -> Result<bool, String> {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(8)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let body = serde_json::json!({"sha": sha, "mtime": mtime, "blob_b64": base64_encode(blob)}).to_string();
    let req = format!(
        "POST /p2p/sync HTTP/1.1\r\nHost: pv\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let body_start = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let v: serde_json::Value =
        serde_json::from_slice(&raw[body_start..]).map_err(|e| format!("bad push body: {e}"))?;
    if v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false) {
        Ok(v.get("adopted").and_then(|a| a.as_bool()).unwrap_or(false))
    } else {
        Err(v
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("push refused")
            .to_string())
    }
}

/// Full sync against one peer IP: newer mtime wins; equal-mtime divergence
/// is a CONFLICT (local kept, loud report). Returns a human status line.
/// `adopt_local` persists an adopted remote blob (caller = secure_write).
pub fn sync_with_peer(
    ip: &str,
    adopt_local: &mut dyn FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<String, String> {
    let addr: SocketAddr = format!("{ip}:{P2P_PORT}").parse().map_err(|e| format!("bad peer ip: {e}"))?;
    let (local_sha, local_mtime) = local_head();
    let local_blob = std::fs::read(crate::developer::vault_run::VAULT_FILE).unwrap_or_default();
    let (remote_sha, remote_mtime, remote_blob) = pull_peer(addr)?;
    if remote_sha == local_sha {
        return Ok("📡 Already in sync (identical heads).".to_string());
    }
    if remote_mtime > local_mtime {
        adopt_local(remote_blob)?;
        crate::security::access_log::log_event("p2p", &format!("adopted {remote_sha} from {ip}"));
        return Ok("📡 Synced with local peer via Wi-Fi! (adopted newer remote)".to_string());
    }
    if local_mtime > remote_mtime {
        push_peer(addr, &local_sha, local_mtime, &local_blob)?;
        crate::security::access_log::log_event("p2p", &format!("pushed {local_sha} to {ip}"));
        return Ok("📡 Synced with local peer via Wi-Fi! (pushed newer local)".to_string());
    }
    Err("⚠️ Sync CONFLICT: same age, different vaults — local kept. Resolve manually.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_roundtrips_and_rejects_foreign() {
        let b = beacon_json("1.2.3", "abc123");
        // Loopback is self → filtered (echo guard). Use a fake LAN IP instead.
        let p = parse_beacon(&b, "192.168.1.99").unwrap();
        assert_eq!(p.version, "1.2.3");
        assert_eq!(p.head_sha, "abc123");
        assert_eq!(p.ip, "192.168.1.99");
        assert!(parse_beacon(r#"{"app":"something_else"}"#, "192.168.1.99").is_none());
        assert!(parse_beacon("garbage", "192.168.1.99").is_none());
    }

    #[test]
    fn http_request_parses_method_path_body() {
        let raw = b"POST /p2p/sync HTTP/1.1\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        let (m, p, body) = parse_http_request(raw).unwrap();
        assert_eq!(m, "POST");
        assert_eq!(p, "/p2p/sync");
        assert_eq!(body, b"{\"a\":1}");
        assert!(parse_http_request(b"GET /x HTTP/1.1\r\n\r\n").is_some());
        assert!(parse_http_request(b"junk").is_none());
    }

    #[test]
    fn route_pull_sync_and_rejections() {
        let blob = b"ciphertext-bytes";
        let sha = sha_hex(blob);
        // Pull mirrors the blob.
        let (st, body, adopt) = route("GET", "/p2p/pull", b"", blob, &sha, 99);
        assert_eq!(st, 200);
        assert!(adopt.is_none());
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["sha"], sha);
        assert_eq!(v["mtime"], 99);
        // Same-sha push → no adopt.
        let push = serde_json::json!({"sha": sha, "blob_b64": base64_encode(blob)}).to_string();
        let (st, _, adopt) = route("POST", "/p2p/sync", push.as_bytes(), blob, &sha, 1);
        assert_eq!(st, 200);
        assert!(adopt.is_none());
        // Newer blob → adopt with verified SHA (mtime must be strictly newer).
        let blob2 = b"newer-ciphertext";
        let sha2 = sha_hex(blob2);
        let push2 = serde_json::json!({"sha": sha2, "mtime": 2, "blob_b64": base64_encode(blob2)}).to_string();
        let (st, _, adopt) = route("POST", "/p2p/sync", push2.as_bytes(), blob, &sha, 1);
        assert_eq!(st, 200);
        let (got_sha, got_blob) = adopt.unwrap();
        assert_eq!(got_sha, sha2);
        assert_eq!(got_blob, blob2);
        // Stale push (older mtime) → 409, local kept.
        let stale = serde_json::json!({"sha": sha2, "mtime": 1, "blob_b64": base64_encode(blob2)}).to_string();
        let (st, _, adopt) = route("POST", "/p2p/sync", stale.as_bytes(), blob, &sha, 5);
        assert_eq!(st, 409);
        assert!(adopt.is_none());
        // Missing mtime → 400.
        let no_ts = serde_json::json!({"sha": sha2, "blob_b64": base64_encode(blob2)}).to_string();
        assert_eq!(route("POST", "/p2p/sync", no_ts.as_bytes(), blob, &sha, 1).0, 400);
        // Tampered body (sha lies) → 400, nothing adopted.
        let evil = serde_json::json!({"sha": sha, "blob_b64": base64_encode(blob2)}).to_string();
        let (st, _, adopt) = route("POST", "/p2p/sync", evil.as_bytes(), blob, &sha, 1);
        assert_eq!(st, 400);
        assert!(adopt.is_none());
        // Oversize body → refused at framing.
        let mut big = b"POST /p2p/sync HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n".to_vec();
        big.extend_from_slice(b"{}");
        assert!(parse_http_request(&big).is_none());
        assert_eq!(route("GET", "/nope", b"", blob, &sha, 1).0, 404);
    }

    #[test]
    fn loopback_pull_end_to_end() {
        // Ephemeral-port listener + real TCP pull (no LAN involved).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let blob = b"loopback-ct".to_vec();
        let sha = sha_hex(&blob);
        let server = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(false);
            if let Ok((stream, _)) = listener.accept() {
                serve_conn_with_blob(stream, blob, sha, 7);
            }
        });
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (got_sha, mtime, got_blob) = pull_peer(addr).unwrap();
        assert_eq!(mtime, 7);
        assert_eq!(got_blob, b"loopback-ct");
        assert!(!got_sha.is_empty());
        let _ = server.join();
    }

    /// Test-only serve with an injected blob (production serve_conn reads disk).
    fn serve_conn_with_blob(mut stream: TcpStream, blob: Vec<u8>, sha: String, mtime: u64) {
        let mut raw = Vec::new();
        let mut tmp = [0u8; 4096];
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&tmp[..n]);
                    if parse_http_request(&raw).is_some() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let (status, body, _) = match parse_http_request(&raw) {
            Some((m, p, b)) => route(&m, &p, &b, &blob, &sha, mtime),
            None => (400, r#"{"ok":false}"#.into(), None),
        };
        let _ = stream.write_all(&http_response(status, &body));
    }
}
