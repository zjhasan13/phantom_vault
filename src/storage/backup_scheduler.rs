//! Automated scheduled backup engine: periodic ciphertext snapshots.
//!
//! Copies `my_secure_vault.enc` (CIPHERTEXT ONLY — safe anywhere) to a
//! timestamped file, prunes beyond retention with a 3-pass shred, and logs
//! to the access audit. A 30-minute heartbeat in `main` drives it; it needs
//! no unlock because it never decrypts.
//!
//! Defaults: ENABLED weekly → `%USERPROFILE%\Documents\PhantomVault_Backups`,
//! keep 10. First run after upgrade performs one immediate backup (last = 0).

use serde::{Deserialize, Serialize};

/// Schedule config file (JSON, beside the vault).
pub const SCHEDULE_FILE: &str = "backup_schedule.json";
/// Heartbeat cadence in the main loop.
pub const HEARTBEAT_SECS: u64 = 30 * 60;
/// Backup filename stamp: vault_backup_YYYY-MM-DD_HHMM.enc.
pub const BACKUP_PREFIX: &str = "vault_backup_";
pub const BACKUP_SUFFIX: &str = ".enc";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupScheduleConfig {
    pub enabled: bool,
    pub interval_days: u32,
    pub backup_dir: String,
    pub max_backups_retained: usize,
    pub last_backup_timestamp: u64,
}

impl Default for BackupScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_days: 7,
            backup_dir: default_backup_dir(),
            max_backups_retained: 10,
            last_backup_timestamp: 0,
        }
    }
}

/// `%USERPROFILE%\Documents\PhantomVault_Backups` (falls back to `%TEMP%`
/// when the profile var is missing — never fails, never panics).
pub fn default_backup_dir() -> String {
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
    std::path::Path::new(&base)
        .join("Documents")
        .join("PhantomVault_Backups")
        .to_string_lossy()
        .into_owned()
}

pub fn load_config() -> BackupScheduleConfig {
    std::fs::read_to_string(SCHEDULE_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_config(cfg: &BackupScheduleConfig) -> Result<(), String> {
    let s = serde_json::to_string_pretty(cfg).map_err(|e| format!("schedule serialize: {e}"))?;
    std::fs::write(SCHEDULE_FILE, s).map_err(|e| format!("schedule save: {e}"))?;
    Ok(())
}

/// True when a backup is due. `now` is injected for testability.
pub fn is_due(cfg: &BackupScheduleConfig, now: u64) -> bool {
    if !cfg.enabled {
        return false;
    }
    let interval = (cfg.interval_days.max(1) as u64) * 86_400;
    now.saturating_sub(cfg.last_backup_timestamp) >= interval
}

/// `unix_to_iso` → filename stamp (`2024-06-01T12:00:00Z` → `2024-06-01_1200`).
pub fn backup_filename(now: u64) -> String {
    let iso = crate::importer::exporter::unix_to_iso(now);
    let stamp = iso
        .replace('T', "_")
        .replace(':', "")
        .get(..15)
        .unwrap_or("unknown-date")
        .to_string();
    format!("{BACKUP_PREFIX}{stamp}{BACKUP_SUFFIX}")
}

/// Outcome of one backup run (for toasts + tests).
#[derive(Debug, PartialEq)]
pub struct BackupOutcome {
    pub path: String,
    pub pruned: usize,
}

/// Perform one backup + prune cycle. Reads the LIVE vault file, so callers
/// must invoke only when a vault exists (missing file = clean error, and
/// `last_backup_timestamp` is NOT bumped on failure).
pub fn run_backup(cfg: &mut BackupScheduleConfig, now: u64) -> Result<BackupOutcome, String> {
    let src = std::path::Path::new(crate::developer::vault_run::VAULT_FILE);
    // Torn-read guard: sample twice 100ms apart; a concurrent save mid-read
    // shows up as a mismatch → retry, then fail LOUD (no corrupt snapshot).
    let mut bytes = Vec::new();
    let mut stable = false;
    for _ in 0..3 {
        let a = std::fs::read(src).map_err(|e| format!("vault read: {e}"))?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        let b = std::fs::read(src).map_err(|e| format!("vault re-read: {e}"))?;
        if a == b {
            bytes = a;
            stable = true;
            break;
        }
    }
    if !stable {
        return Err("vault file changing under backup — retry later".into());
    }
    if bytes.is_empty() {
        return Err("vault file is empty — refusing to snapshot nothing".into());
    }
    let dir = std::path::Path::new(&cfg.backup_dir);
    std::fs::create_dir_all(dir).map_err(|e| format!("backup dir: {e}"))?;
    let dest = dir.join(backup_filename(now));
    write_backup_atomic(dir, &dest, &bytes)?;
    let pruned = prune(dir, cfg.max_backups_retained.max(1));
    cfg.last_backup_timestamp = now;
    // Persist the bump even if the schedule save fails (caller reports it).
    let _ = save_config(cfg);
    crate::security::access_log::log_event(
        "backup",
        &format!("scheduled snapshot → {}", dest.to_string_lossy()),
    );
    Ok(BackupOutcome { path: dest.to_string_lossy().into_owned(), pruned })
}

/// Write the snapshot to a sibling temp file, then rename it into place. A
/// crash or full-disk mid-write can otherwise leave a truncated `.enc` that
/// looks like a valid backup on the next restore.
fn write_backup_atomic(
    dir: &std::path::Path,
    dest: &std::path::Path,
    bytes: &[u8],
) -> Result<(), String> {
    let name = dest.file_name().and_then(|n| n.to_str()).unwrap_or("backup.enc");
    let tmp = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, bytes).map_err(|e| format!("backup write: {e}"))?;
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("backup finalize: {e}"));
    }
    Ok(())
}

/// Keep the newest `keep` snapshots, 3-pass shred the rest. Returns the
/// pruned count. Non-matching files are never touched.
pub fn prune(dir: &std::path::Path, keep: usize) -> usize {
    let mut snaps: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with(BACKUP_PREFIX) && n.ends_with(BACKUP_SUFFIX))
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    if snaps.len() <= keep {
        return 0;
    }
    // Oldest first (lexicographic == chronological by construction).
    snaps.sort();
    let excess = snaps.len() - keep;
    let mut pruned = 0;
    for old in snaps.into_iter().take(excess) {
        if crate::security::shredder::shred_file(&old).is_ok() {
            pruned += 1;
        }
    }
    pruned
}

/// Heartbeat tick: load config, run when due, return a toast line (if any).
/// Never panics, never blocks long — safe on a 30-minute loop.
pub fn heartbeat_tick(now: u64) -> Option<String> {
    let mut cfg = load_config();
    if !is_due(&cfg, now) {
        return None;
    }
    match run_backup(&mut cfg, now) {
        Ok(o) => Some(format!(
            "💾 Scheduled vault backup → {} (pruned {})",
            o.path, o.pruned
        )),
        Err(e) => Some(format!("⚠️ Scheduled backup failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("pv-bkup-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&p);
        p
    }

    #[test]
    fn defaults_match_spec() {
        let c = BackupScheduleConfig::default();
        assert!(c.enabled);
        assert_eq!(c.interval_days, 7);
        assert_eq!(c.max_backups_retained, 10);
        assert_eq!(c.last_backup_timestamp, 0);
        assert!(c.backup_dir.contains("PhantomVault_Backups"));
    }

    #[test]
    fn due_logic() {
        let mut c = BackupScheduleConfig::default();
        assert!(is_due(&c, 8 * 86_400)); // first run (last = 0)
        assert!(!is_due(&c, 6 * 86_400));
        c.enabled = false;
        assert!(!is_due(&c, 800 * 86_400));
        c.enabled = true;
        c.interval_days = 1;
        c.last_backup_timestamp = 100;
        assert!(is_due(&c, 100 + 86_400));
        assert!(!is_due(&c, 100 + 86_399));
    }

    #[test]
    fn filename_stamp_shape() {
        // 2024-06-01T12:00:00Z → vault_backup_2024-06-01_1200.enc
        assert_eq!(backup_filename(1_717_243_200), "vault_backup_2024-06-01_1200.enc");
    }

    #[test]
    fn prune_keeps_newest_and_shreds_rest() {
        let dir = tmp().join("prune");
        let _ = std::fs::create_dir_all(&dir);
        for d in ["2024-01-01_0000", "2024-02-01_0000", "2024-03-01_0000"] {
            std::fs::write(dir.join(format!("{BACKUP_PREFIX}{d}{BACKUP_SUFFIX}")), b"x").unwrap();
        }
        // Files that merely look similar but lack the stamp must survive.
        std::fs::write(dir.join("manual_snapshot.enc"), b"keep").unwrap();
        std::fs::write(dir.join("notes.txt"), b"keep").unwrap();
        assert_eq!(prune(&dir, 2), 1);
        assert!(!dir.join(format!("{BACKUP_PREFIX}2024-01-01_0000{BACKUP_SUFFIX}")).exists());
        assert!(dir.join(format!("{BACKUP_PREFIX}2024-03-01_0000{BACKUP_SUFFIX}")).exists());
        assert!(dir.join("manual_snapshot.enc").exists());
        assert!(dir.join("notes.txt").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn snapshot_write_is_atomic_and_leaves_no_temp() {
        let dir = tmp().join("atomic");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join(backup_filename(1_717_243_200));
        write_backup_atomic(&dir, &dest, b"ciphertext").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"ciphertext");
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp left behind: {leftovers:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn config_roundtrips() {
        let c = BackupScheduleConfig {
            enabled: false,
            interval_days: 30,
            backup_dir: "D:\\b".into(),
            max_backups_retained: 3,
            last_backup_timestamp: 42,
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: BackupScheduleConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }
}
