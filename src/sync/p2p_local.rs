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
    /// True when the peer enforces a pairing PIN (from its beacon).
    pub pin_required: bool,
}

// ---------------------------------------------------------------------------
// Optional pairing PIN: DPAPI-sealed 6-digit secret. When a PIN exists,
// BOTH endpoints refuse unauthenticated requests (403); when none exists
// the LAN stays open (backward compatible, user opted in by enabling P2P).
// ---------------------------------------------------------------------------

/// Sealed PIN file (override path via env for hermetic tests).
fn pin_path() -> std::path::PathBuf {
    std::env::var("PV_P2P_PIN_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("p2p_pin.dpapi"))
}

/// True when this device enforces PIN pairing (sealed PIN present).
pub fn pin_required() -> bool {
    load_pin().is_some()
}

fn load_pin() -> Option<String> {
    let blob = std::fs::read(pin_path()).ok()?;
    let secret = crate::core::memory::DpapiGuard::unprotect(&blob).ok()?;
    let pin = String::from_utf8_lossy(secret.expose()).into_owned();
    if pin.len() == 6 && pin.chars().all(|c| c.is_ascii_digit()) {
        Some(pin)
    } else {
        None
    }
}

/// Fetch the sealed PIN, generating + sealing one on first call.
pub fn get_or_create_pin() -> Result<String, String> {
    if let Some(pin) = load_pin() {
        return Ok(pin);
    }
    // H13: rejection sampling removes the `% 1_000_000` modulo bias
    // (2^32 % 1M != 0). NOTE residual: pairing HTTP is still plaintext LAN
    // (rustls + fingerprint pinning is the full fix, tracked separately);
    // throttle (5 fails/30s per IP) + DPAPI-sealed PIN + constant-time
    // compare are already in place below.
    use rand_core::RngCore as _;
    let mut rng = rand_core::OsRng;
    let pin_val = loop {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let v = u32::from_le_bytes(buf);
        if v < 4_294_000_000 {
            break v % 1_000_000;
        }
    };
    let pin = format!("{pin_val:06}");
    let blob = crate::core::memory::DpapiGuard::protect(pin.as_bytes())
        .map_err(|e| format!("pin seal failed: {e}"))?;
    std::fs::write(pin_path(), blob).map_err(|e| format!("pin store failed: {e}"))?;
    Ok(pin)
}

/// Regenerate the PIN (old pairings break immediately).
pub fn regenerate_pin() -> Result<String, String> {
    let _ = std::fs::remove_file(pin_path());
    get_or_create_pin()
}

/// Length-first + full compare (interactive-attempt-rate path).
pub fn verify_pin(candidate: &str) -> bool {
    let Some(expected) = load_pin() else {
        // No PIN configured → pairing check disabled (open LAN).
        return true;
    };
    let candidate = candidate.trim();
    expected.len() == candidate.len()
        && expected
            .as_bytes()
            .iter()
            .zip(candidate.as_bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

// ---------------------------------------------------------------------------
// PIN brute-force brake: 5 consecutive failures from one IP lock it out for
// 30 seconds (429/403 + loud log). Success resets the counter. Successive
// legitimate typos (≤4) never trigger. In-memory only — restarts clear it.
// ---------------------------------------------------------------------------

/// Consecutive-failure budget per IP before lockout.
pub const PIN_MAX_FAILS: u32 = 5;
/// Lockout window per offending IP.
pub const PIN_LOCKOUT_SECS: u64 = 30;

struct PinThrottle {
    fails: u32,
    locked_until: Option<std::time::Instant>,
}

fn pin_throttle_map() -> &'static std::sync::Mutex<std::collections::HashMap<String, PinThrottle>> {
    static MAP: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, PinThrottle>>> =
        std::sync::OnceLock::new();
    MAP.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// True when `ip` is currently locked out (caller returns 429).
pub fn pin_locked_out(ip: &str) -> bool {
    let now = std::time::Instant::now();
    pin_throttle_map()
        .lock()
        .ok()
        .and_then(|m| m.get(ip).and_then(|t| t.locked_until))
        .map(|until| now < until)
        .unwrap_or(false)
}

/// Record one PIN verdict for `ip`. Success clears failures + lockout.
pub fn pin_record(ip: &str, ok: bool) {
    let Ok(mut m) = pin_throttle_map().lock() else {
        return;
    };
    if ok {
        m.remove(ip);
        return;
    }
    let e = m.entry(ip.to_string()).or_insert(PinThrottle { fails: 0, locked_until: None });
    e.fails = e.fails.saturating_add(1);
    if e.fails >= PIN_MAX_FAILS {
        e.locked_until = Some(std::time::Instant::now() + std::time::Duration::from_secs(PIN_LOCKOUT_SECS));
    }
}

#[cfg(test)]
pub(crate) fn pin_throttle_test_set(ip: &str, fails: u32, locked_secs_from_now: i64) {
    // Test hook: plant exact throttle state (negative = already expired).
    let until = if locked_secs_from_now > 0 {
        Some(std::time::Instant::now() + std::time::Duration::from_secs(locked_secs_from_now as u64))
    } else {
        None
    };
    if let Ok(mut m) = pin_throttle_map().lock() {
        m.insert(ip.to_string(), PinThrottle { fails, locked_until: until });
    }
}

#[cfg(test)]
pub(crate) fn pin_throttle_test_clear() {
    if let Ok(mut m) = pin_throttle_map().lock() {
        m.clear();
    }
}

/// Presence beacon. `head_sha`/`mtime` describe the CIPHERTEXT only.
/// M5: carries a `ts` send-time; receivers reject beacons older than 120 s
/// so stale replays die. Residual: live LAN spoofing is still possible on
/// plaintext UDP — the UI must show peer IP+name for out-of-band check and
/// the PIN stays plaintext-checked + throttled (full mDNS/TLS tracked sep).
pub fn beacon_json(version: &str, head_sha: &str) -> String {
    let name = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "PC".to_string());
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    serde_json::json!({
        "app": "phantom_vault",
        "name": name,
        "version": version,
        "port": P2P_PORT,
        "head_sha": head_sha,
        "pin_required": pin_required(),
        "ts": ts,
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
    // M5: freshness — replayed beacons older than 120 s (or clock-skewed
    // future stamps) are dropped. Beacons without `ts` are pre-upgrade and
    // accepted once (interim compat).
    if let Some(ts) = v.get("ts").and_then(|t| t.as_u64()) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(ts);
        if now.saturating_sub(ts) > 120 || ts.saturating_sub(now) > 60 {
            return None;
        }
    }
    Some(Peer {
        name: v.get("name").and_then(|n| n.as_str()).unwrap_or("Peer").to_string(),
        ip: from_ip.to_string(),
        version: v.get("version").and_then(|n| n.as_str()).unwrap_or("?").to_string(),
        head_sha: v.get("head_sha").and_then(|n| n.as_str()).unwrap_or("").to_string(),
        pin_required: v.get("pin_required").and_then(|b| b.as_bool()).unwrap_or(false),
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
/// Returns (status, body, optional adoption). Pairing PIN (when configured)
/// gates BOTH endpoints: GET reads `?pin=`, POST reads the `pin` field.
/// `peer_ip` feeds the brute-force brake (5 fails → 30s lockout, 429).
pub fn route(
    method: &str,
    path: &str,
    body: &[u8],
    local_blob: &[u8],
    local_sha: &str,
    local_mtime: u64,
    peer_ip: &str,
) -> (u16, String, Option<(String, Vec<u8>)>) {
    // Split query string (?pin=…) — minimal HTTP only.
    let (clean_path, query_pin) = match path.split_once('?') {
        Some((p, q)) => {
            let pin = q.split('&').find_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                (k == "pin").then(|| v.to_string())
            });
            (p, pin)
        }
        None => (path, None),
    };
    if method == "GET" && clean_path == "/p2p/pull" {
        if pin_required() {
            if pin_locked_out(peer_ip) {
                return (429, r#"{"ok":false,"error":"too many bad PINs — retry in 30s"}"#.into(), None);
            }
            let ok = verify_pin(query_pin.as_deref().unwrap_or(""));
            pin_record(peer_ip, ok);
            if !ok {
                crate::security::access_log::log_event("p2p", &format!("bad PIN from {peer_ip}"));
                return (403, r#"{"ok":false,"error":"pairing PIN required"}"#.into(), None);
            }
        }
        let body = serde_json::json!({
            "sha": local_sha,
            "mtime": local_mtime,
            "blob_b64": base64_encode(local_blob),
        })
        .to_string();
        return (200, body, None);
    }
    if method == "POST" && clean_path == "/p2p/sync" {
        let v: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return (400, r#"{"ok":false,"error":"bad json"}"#.into(), None),
        };
        if pin_required() {
            if pin_locked_out(peer_ip) {
                return (429, r#"{"ok":false,"error":"too many bad PINs — retry in 30s"}"#.into(), None);
            }
            let ok = verify_pin(v.get("pin").and_then(|p| p.as_str()).unwrap_or(""));
            pin_record(peer_ip, ok);
            if !ok {
                crate::security::access_log::log_event("p2p", &format!("bad PIN from {peer_ip}"));
                return (403, r#"{"ok":false,"error":"pairing PIN required"}"#.into(), None);
            }
        }
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
    // Peer IP for the PIN brake; unresolvable → throttle key falls back.
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
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
    let (status, resp_body, adopt) = route(&method, &path, &body, &blob, &local_sha, local_mtime, &peer_ip);
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

/// Pull a peer's ciphertext head + blob (PIN sent as query when set).
pub fn pull_peer(addr: SocketAddr, pin: &str) -> Result<(String, u64, Vec<u8>), String> {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(8)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let target = if pin.trim().is_empty() {
        "/p2p/pull".to_string()
    } else {
        format!("/p2p/pull?pin={}", pin.trim())
    };
    let req = format!("GET {target} HTTP/1.1\r\nHost: pv\r\nConnection: close\r\n\r\n");
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
pub fn push_peer(addr: SocketAddr, sha: &str, mtime: u64, blob: &[u8], pin: &str) -> Result<bool, String> {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(8)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let body = serde_json::json!({"sha": sha, "mtime": mtime, "blob_b64": base64_encode(blob), "pin": pin.trim()}).to_string();
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
    pin: &str,
    adopt_local: &mut dyn FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<String, String> {
    let addr: SocketAddr = format!("{ip}:{P2P_PORT}").parse().map_err(|e| format!("bad peer ip: {e}"))?;
    let (local_sha, local_mtime) = local_head();
    let local_blob = std::fs::read(crate::developer::vault_run::VAULT_FILE).unwrap_or_default();
    let (remote_sha, remote_mtime, remote_blob) = pull_peer(addr, pin)?;
    if remote_sha == local_sha {
        return Ok("📡 Already in sync (identical heads).".to_string());
    }
    if remote_mtime > local_mtime {
        adopt_local(remote_blob)?;
        crate::security::access_log::log_event("p2p", &format!("adopted {remote_sha} from {ip}"));
        return Ok("📡 Synced with local peer via Wi-Fi! (adopted newer remote)".to_string());
    }
    if local_mtime > remote_mtime {
        push_peer(addr, &local_sha, local_mtime, &local_blob, pin)?;
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
        // M5: stale replays die; fresh beacons pass.
        let stale = serde_json::json!({"app": "phantom_vault", "name": "X",
            "version": "1", "port": P2P_PORT, "ts": 1}).to_string();
        assert!(parse_beacon(&stale, "192.168.1.99").is_none());
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
        // Ambient PIN env from a racing PIN test would 403 everything here.
        let _guard = pin_env_lock();
        let blob = b"ciphertext-bytes";
        let sha = sha_hex(blob);
        // Pull mirrors the blob.
        let (st, body, adopt) = route("GET", "/p2p/pull", b"", blob, &sha, 99, "192.0.2.10");
        assert_eq!(st, 200);
        assert!(adopt.is_none());
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["sha"], sha);
        assert_eq!(v["mtime"], 99);
        // Same-sha push → no adopt.
        let push = serde_json::json!({"sha": sha, "blob_b64": base64_encode(blob)}).to_string();
        let (st, _, adopt) = route("POST", "/p2p/sync", push.as_bytes(), blob, &sha, 1, "192.0.2.10");
        assert_eq!(st, 200);
        assert!(adopt.is_none());
        // Newer blob → adopt with verified SHA (mtime must be strictly newer).
        let blob2 = b"newer-ciphertext";
        let sha2 = sha_hex(blob2);
        let push2 = serde_json::json!({"sha": sha2, "mtime": 2, "blob_b64": base64_encode(blob2)}).to_string();
        let (st, _, adopt) = route("POST", "/p2p/sync", push2.as_bytes(), blob, &sha, 1, "192.0.2.10");
        assert_eq!(st, 200);
        let (got_sha, got_blob) = adopt.unwrap();
        assert_eq!(got_sha, sha2);
        assert_eq!(got_blob, blob2);
        // Stale push (older mtime) → 409, local kept.
        let stale = serde_json::json!({"sha": sha2, "mtime": 1, "blob_b64": base64_encode(blob2)}).to_string();
        let (st, _, adopt) = route("POST", "/p2p/sync", stale.as_bytes(), blob, &sha, 5, "192.0.2.10");
        assert_eq!(st, 409);
        assert!(adopt.is_none());
        // Missing mtime → 400.
        let no_ts = serde_json::json!({"sha": sha2, "blob_b64": base64_encode(blob2)}).to_string();
        assert_eq!(route("POST", "/p2p/sync", no_ts.as_bytes(), blob, &sha, 1, "192.0.2.10").0, 400);
        // Tampered body (sha lies) → 400, nothing adopted.
        let evil = serde_json::json!({"sha": sha, "blob_b64": base64_encode(blob2)}).to_string();
        let (st, _, adopt) = route("POST", "/p2p/sync", evil.as_bytes(), blob, &sha, 1, "192.0.2.10");
        assert_eq!(st, 400);
        assert!(adopt.is_none());
        // Oversize body → refused at framing.
        let mut big = b"POST /p2p/sync HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n".to_vec();
        big.extend_from_slice(b"{}");
        assert!(parse_http_request(&big).is_none());
        assert_eq!(route("GET", "/nope", b"", blob, &sha, 1, "192.0.2.10").0, 404);
    }

    #[test]
    fn loopback_pull_end_to_end() {
        // Same ambient-PIN exclusion as the route test above.
        let _guard = pin_env_lock();
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
        let (got_sha, mtime, got_blob) = pull_peer(addr, "").unwrap();
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
            Some((m, p, b)) => route(&m, &p, &b, &blob, &sha, mtime, "127.0.0.1"),
            None => (400, r#"{"ok":false}"#.into(), None),
        };
        let _ = stream.write_all(&http_response(status, &body));
    }

    /// Hermetic PIN sandbox: point PV_P2P_PIN_FILE at a temp path.
    /// Serialized: tests share one process env, so PIN tests take this lock.
    /// Non-PIN route tests take `pin_env_lock()` to exclude the window where
    /// a PIN test has the env pointed at a LIVE pin file (else ambient 403s).
    static PIN_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn pin_env_lock() -> std::sync::MutexGuard<'static, ()> {
        PIN_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn with_pin_file(path: &str) -> std::sync::MutexGuard<'static, ()> {
        let guard = pin_env_lock();
        std::env::set_var("PV_P2P_PIN_FILE", path);
        guard
    }

    fn clear_pin_file() {
        std::env::remove_var("PV_P2P_PIN_FILE");
    }

    #[test]
    fn pin_create_verify_wrong_and_regen() {
        let sandbox = std::env::temp_dir().join(format!("pv-pin-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&sandbox);
        let pinfile = sandbox.join("p2p_pin.dpapi");
        let _ = std::fs::remove_file(&pinfile);
        let _guard = with_pin_file(pinfile.to_str().unwrap());
        // No PIN configured yet → open (verify-all) AND not required.
        assert!(!pin_required());
        assert!(verify_pin("anything"));
        let pin = get_or_create_pin().unwrap();
        assert_eq!(pin.len(), 6);
        assert!(pin_required());
        assert!(verify_pin(&pin));
        assert!(!verify_pin("000000"));
        // Regenerate rotates.
        let pin2 = regenerate_pin().unwrap();
        assert!(verify_pin(&pin2));
        assert!(!verify_pin(&pin));
        clear_pin_file();
        let _ = std::fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn pin_gates_both_endpoints() {
        let sandbox = std::env::temp_dir().join(format!("pv-pin-gate-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&sandbox);
        let pinfile = sandbox.join("p2p_pin.dpapi");
        let _ = std::fs::remove_file(&pinfile);
        let _guard = with_pin_file(pinfile.to_str().unwrap());
        let pin = get_or_create_pin().unwrap();
        let blob = b"gate-ct";
        let sha = sha_hex(blob);
        // GET without pin → 403; with pin → 200.
        assert_eq!(route("GET", "/p2p/pull", b"", blob, &sha, 1, "192.0.2.20").0, 403);
        let (st, _, _) = route("GET", &format!("/p2p/pull?pin={pin}"), b"", blob, &sha, 1, "192.0.2.20");
        assert_eq!(st, 200);
        // POST without pin → 403; wrong pin → 403; right pin → proceeds.
        let mk = |pin_val: &str| {
            serde_json::json!({"sha": sha_hex(b"x"), "mtime": 9, "blob_b64": base64_encode(b"x"), "pin": pin_val}).to_string()
        };
        assert_eq!(route("POST", "/p2p/sync", mk("").as_bytes(), blob, &sha, 1, "192.0.2.20").0, 403);
        assert_eq!(route("POST", "/p2p/sync", mk("000000").as_bytes(), blob, &sha, 1, "192.0.2.20").0, 403);
        let (st, _, adopt) = route("POST", "/p2p/sync", mk(&pin).as_bytes(), blob, &sha, 1, "192.0.2.20");
        assert_eq!(st, 200);
        assert!(adopt.is_some());
        clear_pin_file();
        let _ = std::fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn pin_lockout_after_five_fails() {
        pin_throttle_test_clear();
        let ip = "198.51.100.7";
        let other = "198.51.100.8";
        // 4 fails: still allowed through to 403 (not yet locked).
        for _ in 0..4 {
            assert!(!pin_locked_out(ip));
            pin_record(ip, false);
        }
        assert!(!pin_locked_out(ip));
        // 5th fail trips the 30s lockout; other IPs unaffected.
        pin_record(ip, false);
        assert!(pin_locked_out(ip));
        assert!(!pin_locked_out(other));
        // Success clears failures + lockout.
        pin_record(ip, true);
        assert!(!pin_locked_out(ip));
        // Pre-seeded expired lockout reads as open.
        pin_throttle_test_set(ip, 9, -5);
        assert!(!pin_locked_out(ip));
        pin_throttle_test_clear();
    }
}
