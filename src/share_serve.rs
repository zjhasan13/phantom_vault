//! A20 slice 2: expiring-share HTTP transport (LAN or loopback).
//!
//! `GET /<share-id>` returns the `PVSH1` ciphertext exactly until the store's
//! TTL/max-views refuse it. There is **no pairing/auth here by design**: the id
//! is 128-bit random, the key never travels in the request, and the payload is
//! already end-to-end encrypted. This endpoint is separate from the A15 P2P
//! vault sync surface.

use crate::share_store;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_REQUEST_BYTES: usize = 8 * 1024;

pub struct ServeHandle {
    pub port: u16,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ServeHandle {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Bind (use `0.0.0.0:0` for LAN, `127.0.0.1:0` for tests).
pub fn serve(bind: &str) -> Result<ServeHandle, String> {
    let listener = TcpListener::bind(bind).map_err(|e| format!("share bind {bind}: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("share address: {e}"))?
        .port();
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("share nonblocking: {e}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let join = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    serve_conn(stream);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    Ok(ServeHandle {
        port,
        stop,
        join: Some(join),
    })
}

fn serve_conn(mut stream: TcpStream) {
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
    let Some((method, path, _body, _headers)) =
        crate::sync::p2p_local::parse_http_request_headers(&buf)
    else {
        let _ = stream.write_all(&response(400, b"bad request"));
        return;
    };
    if method != "GET" {
        let _ = stream.write_all(&response(405, b"only GET"));
        return;
    }
    let path = path.split('?').next().unwrap_or(&path);
    if path == "/health" {
        let _ = stream.write_all(&response(200, b"ok"));
        return;
    }
    let id = path.trim_start_matches('/');
    if id.is_empty() || id.contains('/') {
        let _ = stream.write_all(&response(404, b"not found"));
        return;
    }
    match share_store::take(id) {
        Ok(bundle) => {
            let _ = stream.write_all(&response(200, &bundle));
            crate::security::access_log::log_event("share", &format!("served {id}"));
        }
        Err(_) => {
            let _ = stream.write_all(&response(404, b"not found or already viewed"));
        }
    }
}

fn response(status: u16, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// Best-effort LAN IPv4 (UDP connect does not send a packet).
pub fn local_ipv4() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{now_secs, CreatedShare};
    use secrecy::SecretString;

    fn fetch(port: u16, path: &str) -> (u16, Vec<u8>) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw);
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, body.as_bytes().to_vec())
    }

    #[test]
    fn served_share_is_one_view_and_revocable() {
        let _guard = crate::share_store::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("pv-share-serve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PV_SHARE_DIR", &dir);
        let created = CreatedShare {
            bundle: b"PVSH1bundle-bytes".to_vec(),
            id: "deadbeef".to_string(),
            key: SecretString::new("k".to_string()),
            expires_at: now_secs() + 60,
            max_views: 1,
        };
        share_store::save(&created).unwrap();
        let server = serve("127.0.0.1:0").unwrap();
        assert_eq!(fetch(server.port, "/health").0, 200);
        let (code, body) = fetch(server.port, "/deadbeef");
        assert_eq!(code, 200);
        assert_eq!(body, b"PVSH1bundle-bytes");
        assert_eq!(fetch(server.port, "/deadbeef").0, 404, "one view");
        assert_eq!(fetch(server.port, "/nope").0, 404);

        // Revoke removes an unviewed share.
        let other = CreatedShare {
            bundle: b"PVSH1other".to_vec(),
            id: "cafebabe".to_string(),
            key: SecretString::new("k".to_string()),
            expires_at: now_secs() + 60,
            max_views: 0,
        };
        share_store::save(&other).unwrap();
        share_store::revoke("cafebabe").unwrap();
        assert_eq!(fetch(server.port, "/cafebabe").0, 404);

        server.stop();
        std::env::remove_var("PV_SHARE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
