//! A20 slice 2: on-disk share store with TTL + view accounting.
//!
//! Only ciphertext (`.pvsh`) and non-secret metadata (`.meta.json`) live here;
//! the key never touches disk. `take()` enforces expiry/max_views before it
//! returns the bundle, so a LAN relay cannot serve a share twice.

use crate::share::{now_secs, CreatedShare};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

pub const SHARE_DIR: &str = "pvshares";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareMeta {
    pub expires_at: u64,
    /// `0` = unlimited.
    pub max_views: u32,
    pub views: u32,
    /// A20a: the bundle needs a recipient passphrase.
    #[serde(default)]
    pub passphrase: bool,
    /// A20b: the published secret-gist id, when this share has an async link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_gist: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ShareRecord {
    pub id: String,
    pub expires_at: u64,
    pub max_views: u32,
    pub views: u32,
    pub passphrase: bool,
    pub relay_gist: Option<String>,
    pub bundle_path: PathBuf,
}

fn dir() -> PathBuf {
    std::env::var("PV_SHARE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(SHARE_DIR))
}

fn bundle_path(id: &str) -> PathBuf {
    dir().join(format!("{id}.pvsh"))
}

fn meta_path(id: &str) -> PathBuf {
    dir().join(format!("{id}.meta.json"))
}

fn store_lock() -> &'static Mutex<()> {
    static L: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

/// Share tests mutate the process-wide `PV_SHARE_DIR`.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

fn write_meta(id: &str, meta: &ShareMeta) -> Result<(), String> {
    let path = meta_path(id);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec(meta).map_err(|e| format!("share meta encode: {e}"))?;
    std::fs::write(&tmp, json).map_err(|e| format!("share meta write: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("share meta swap: {e}"))?;
    Ok(())
}

fn read_meta(id: &str) -> Option<ShareMeta> {
    let bytes = std::fs::read(meta_path(id)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn save(created: &CreatedShare) -> Result<ShareRecord, String> {
    let _guard = store_lock().lock().unwrap_or_else(|p| p.into_inner());
    std::fs::create_dir_all(dir()).map_err(|e| format!("share dir: {e}"))?;
    std::fs::write(bundle_path(&created.id), &created.bundle)
        .map_err(|e| format!("share bundle write: {e}"))?;
    write_meta(
        &created.id,
        &ShareMeta {
            expires_at: created.expires_at,
            max_views: created.max_views,
            views: 0,
            passphrase: created.passphrase,
            relay_gist: None,
        },
    )?;
    Ok(ShareRecord {
        id: created.id.clone(),
        expires_at: created.expires_at,
        max_views: created.max_views,
        views: 0,
        passphrase: created.passphrase,
        relay_gist: None,
        bundle_path: bundle_path(&created.id),
    })
}

pub fn get(id: &str) -> Option<ShareRecord> {
    let _guard = store_lock().lock().unwrap_or_else(|p| p.into_inner());
    let meta = read_meta(id)?;
    let bundle_path = bundle_path(id);
    // A20b: keep relay metadata even if the local ciphertext is gone, so the
    // sender can still delete the remote gist.
    if !bundle_path.is_file() && meta.relay_gist.is_none() {
        return None;
    }
    Some(ShareRecord {
        id: id.to_string(),
        expires_at: meta.expires_at,
        max_views: meta.max_views,
        views: meta.views,
        passphrase: meta.passphrase,
        relay_gist: meta.relay_gist,
        bundle_path,
    })
}

/// Record the secret-gist id after a successful A20b publish.
pub fn set_relay_gist(id: &str, gist_id: &str) -> Result<(), String> {
    let _guard = store_lock().lock().unwrap_or_else(|p| p.into_inner());
    let mut meta = read_meta(id).ok_or_else(|| "share not found".to_string())?;
    meta.relay_gist = Some(gist_id.to_string());
    write_meta(id, &meta)
}

pub fn list() -> Vec<ShareRecord> {
    let _guard = store_lock().lock().unwrap_or_else(|p| p.into_inner());
    let Ok(rd) = std::fs::read_dir(dir()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(".meta.json") else {
            continue;
        };
        let Some(meta) = read_meta(id) else {
            continue;
        };
        let bundle_path = bundle_path(id);
        if !bundle_path.is_file() && meta.relay_gist.is_none() {
            continue;
        }
        out.push(ShareRecord {
            id: id.to_string(),
            expires_at: meta.expires_at,
            max_views: meta.max_views,
            views: meta.views,
            passphrase: meta.passphrase,
            relay_gist: meta.relay_gist,
            bundle_path,
        });
    }
    out.sort_by_key(|r| r.expires_at);
    out
}

/// Return the bundle once, enforcing expiry and max_views. Increments `views`
/// before returning, so a crash cannot hand out an extra view.
pub fn take(id: &str) -> Result<Vec<u8>, String> {
    let _guard = store_lock().lock().unwrap_or_else(|p| p.into_inner());
    let Some(mut meta) = read_meta(id) else {
        return Err("share not found".to_string());
    };
    if meta.expires_at <= now_secs() {
        let _ = std::fs::remove_file(meta_path(id));
        let _ = std::fs::remove_file(bundle_path(id));
        return Err("share has expired".to_string());
    }
    if meta.max_views > 0 && meta.views >= meta.max_views {
        return Err("share has already been viewed".to_string());
    }
    let bytes = std::fs::read(bundle_path(id)).map_err(|_| "share bundle is missing".to_string())?;
    meta.views = meta.views.saturating_add(1);
    write_meta(id, &meta)?;
    Ok(bytes)
}

pub fn revoke(id: &str) -> Result<(), String> {
    let _guard = store_lock().lock().unwrap_or_else(|p| p.into_inner());
    let _ = std::fs::remove_file(bundle_path(id));
    let _ = std::fs::remove_file(meta_path(id));
    Ok(())
}

pub fn purge_expired() {
    let now = now_secs();
    for rec in list() {
        // A20b: keep an expired relay share on disk so the sender can still
        // delete its gist (the gist itself does not auto-expire). Local-only
        // shares are safe to purge.
        if rec.expires_at <= now && rec.relay_gist.is_none() {
            let _ = revoke(&rec.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{now_secs, CreatedShare};
    use secrecy::SecretString;

    fn dummy(id: &str, expires_at: u64, max_views: u32) -> CreatedShare {
        CreatedShare {
            bundle: b"PVSH1ciphertext".to_vec(),
            id: id.to_string(),
            key: SecretString::new("k".to_string()),
            expires_at,
            max_views,
            passphrase: false,
        }
    }

    #[test]
    fn store_enforces_one_view_expiry_and_revoke() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("pv-share-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PV_SHARE_DIR", &dir);
        let future = now_secs() + 60;
        let rec = save(&dummy("a1", future, 1)).unwrap();
        assert_eq!(rec.views, 0);
        assert_eq!(take("a1").unwrap(), b"PVSH1ciphertext");
        assert!(take("a1").unwrap_err().contains("already"));
        revoke("a1").unwrap();
        assert!(get("a1").is_none());

        // Expired shares are refused and purged.
        save(&dummy("a2", now_secs() - 1, 0)).unwrap();
        assert!(take("a2").unwrap_err().contains("expired"));
        assert!(get("a2").is_none());

        // Unlimited views keep working.
        save(&dummy("a3", future, 0)).unwrap();
        assert!(take("a3").is_ok());
        assert!(take("a3").is_ok());
        assert_eq!(list().len(), 1);
        revoke("a3").unwrap();

        // An expired relay share is kept so the sender can still delete the
        // remote gist; local-only expired shares are purged.
        save(&dummy("a4", now_secs() - 1, 0)).unwrap();
        set_relay_gist("a4", "0123456789abcdef0123456789abcdef").unwrap();
        purge_expired();
        assert!(get("a4").is_some());
        revoke("a4").unwrap();

        // Even if the local ciphertext is gone, relay metadata stays visible
        // for remote cleanup (the gist itself is still on GitHub).
        save(&dummy("a5", future, 0)).unwrap();
        set_relay_gist("a5", "fedcba9876543210fedcba9876543210").unwrap();
        std::fs::remove_file(dir.join("a5.pvsh")).unwrap();
        assert!(get("a5").is_some());
        assert!(list().iter().any(|r| r.id == "a5"));
        revoke("a5").unwrap();

        std::env::remove_var("PV_SHARE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn passphrase_flag_persists_and_old_meta_still_loads() {
        let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("pv-share-pass-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PV_SHARE_DIR", &dir);
        let mut created = dummy("p1", now_secs() + 60, 1);
        created.passphrase = true;
        save(&created).unwrap();
        assert!(get("p1").unwrap().passphrase);
        assert!(list().iter().any(|r| r.id == "p1" && r.passphrase));

        // A20b: the published gist id survives a reload.
        set_relay_gist("p1", "0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            get("p1").unwrap().relay_gist.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );

        // Metadata written before A20a/A20b has neither field; it must still
        // load and default to "no passphrase" / "local only" rather than error.
        let raw = std::fs::read(dir.join("p1.meta.json")).unwrap();
        let legacy = String::from_utf8(raw)
            .unwrap()
            .replace(",\"passphrase\":true", "")
            .replace(",\"relay_gist\":\"0123456789abcdef0123456789abcdef\"", "");
        std::fs::write(dir.join("p1.meta.json"), legacy).unwrap();
        let rec = get("p1").unwrap();
        assert!(!rec.passphrase);
        assert!(rec.relay_gist.is_none());

        std::env::remove_var("PV_SHARE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
