//! A23: scoped local-API token storage (`pv_api_token.dpapi`, DPAPI-sealed).
//!
//! The token is a bearer secret for the loopback API. It is DPAPI-sealed for
//! the current user, expires after 24h, and is revoked when the API is
//! disabled. Every request still requires an explicit in-app approval, so a
//! stolen token alone cannot silently drain secrets.

use crate::core::memory::DpapiGuard;
use rand_core::{OsRng, RngCore};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const TOKEN_FILE: &str = "pv_api_token.dpapi";
pub const PORT_FILE: &str = "pv_api_port";
/// Tokens live for one day; re-enabling the API mints a fresh one.
pub const TOKEN_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    token: String,
    expires: u64,
}

#[derive(Debug)]
pub struct ApiToken {
    pub value: SecretString,
    pub expires: u64,
}

fn token_path() -> PathBuf {
    std::env::var("PV_API_TOKEN_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(TOKEN_FILE))
}

pub fn port_path() -> PathBuf {
    std::env::var("PV_API_PORT_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(PORT_FILE))
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_atomic(target: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = target.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("API token write: {e}"))?;
    std::fs::rename(&tmp, target).map_err(|e| format!("API token swap: {e}"))?;
    Ok(())
}

pub fn create() -> Result<ApiToken, String> {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = hex(&raw);
    let expires = now_secs() + TOKEN_TTL_SECS;
    let json = serde_json::to_vec(&Stored {
        token: token.clone(),
        expires,
    })
    .map_err(|e| format!("API token encode: {e}"))?;
    let sealed = DpapiGuard::protect(&json).map_err(|e| format!("API token seal: {e}"))?;
    write_atomic(&token_path(), &sealed)?;
    Ok(ApiToken {
        value: SecretString::new(token),
        expires,
    })
}

/// Load and validate the token. Missing, corrupt or expired all fail closed.
pub fn load() -> Result<ApiToken, String> {
    let blob = std::fs::read(token_path()).map_err(|_| "API token is missing".to_string())?;
    let secret = DpapiGuard::unprotect(&blob)
        .map_err(|_| "API token cannot be unsealed".to_string())?;
    let stored: Stored = serde_json::from_slice(secret.expose())
        .map_err(|_| "API token is corrupt".to_string())?;
    if stored.expires <= now_secs() {
        return Err("API token expired".to_string());
    }
    Ok(ApiToken {
        value: SecretString::new(stored.token),
        expires: stored.expires,
    })
}

pub fn write_port(port: u16) -> Result<(), String> {
    std::fs::write(port_path(), port.to_string()).map_err(|e| format!("API port write: {e}"))
}

/// Revoke = delete the token + port files (idempotent).
pub fn revoke() {
    let _ = std::fs::remove_file(token_path());
    let _ = std::fs::remove_file(token_path().with_extension("tmp"));
    let _ = std::fs::remove_file(port_path());
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn token_roundtrips_expires_and_revokes() {
        let _guard = crate::api::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("pv-api-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PV_API_TOKEN_FILE", dir.join("t.dpapi"));
        std::env::set_var("PV_API_PORT_FILE", dir.join("port"));
        revoke();
        assert!(load().is_err());

        let tok = create().unwrap();
        assert_eq!(tok.value.expose_secret().len(), 64);
        let loaded = load().unwrap();
        assert_eq!(loaded.value.expose_secret(), tok.value.expose_secret());
        assert_eq!(loaded.expires, tok.expires);
        write_port(51234).unwrap();
        assert_eq!(
            std::fs::read_to_string(port_path()).unwrap().trim(),
            "51234"
        );

        // Expired token fails closed.
        let expired = Stored {
            token: "aa".repeat(32),
            expires: now_secs() - 1,
        };
        let blob = DpapiGuard::protect(&serde_json::to_vec(&expired).unwrap()).unwrap();
        std::fs::write(token_path(), blob).unwrap();
        assert!(load().unwrap_err().contains("expired"));

        revoke();
        assert!(!token_path().exists());
        assert!(!port_path().exists());
        std::env::remove_var("PV_API_TOKEN_FILE");
        std::env::remove_var("PV_API_PORT_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
