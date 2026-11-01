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
}

#[derive(Debug, Clone)]
pub struct ShareRecord {
    pub id: String,
    pub expires_at: u64,
    pub max_views: u32,
    pub views: u32,
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
        },
    )?;
    Ok(ShareRecord {
        id: created.id.clone(),
        expires_at: created.expires_at,
        max_views: created.max_views,
        views: 0,
        bundle_path: bundle_path(&created.id),
    })
}

pub fn get(id: &str) -> Option<ShareRecord> {
    let _guard = store_lock().lock().unwrap_or_else(|p| p.into_inner());
    let meta = read_meta(id)?;
    let bundle_path = bundle_path(id);
    if !bundle_path.is_file() {
        return None;
    }
    Some(ShareRecord {
        id: id.to_string(),
        expires_at: meta.expires_at,
        max_views: meta.max_views,
        views: meta.views,
        bundle_path,
    })
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
        if !bundle_path.is_file() {
            continue;
        }
        out.push(ShareRecord {
            id: id.to_string(),
            expires_at: meta.expires_at,
            max_views: meta.max_views,
            views: meta.views,
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
        if rec.expires_at <= now {
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
        std::env::remove_var("PV_SHARE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
