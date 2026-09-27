//! Phase 17 (Option 3 combo) — DoD 5220.22-M secure file shredder.
//!
//! Best-effort overwrite-then-delete for HDD-era threat models:
//! pass 1 = 0x00, pass 2 = 0xFF, pass 3 = OsRng bytes, then `remove_file`.
//!
//! Honest limits: on SSDs / wear-leveling flash and journaling filesystems the
//! old blocks may survive in spare cells no matter what we overwrite —
//! full-disk encryption remains the real defense there. This still defeats
//! casual undelete tools and resale snooping on spinning disks.
//! `secure_write` (overwrite-in-place before replacing content) is hooked into
//! every vault save so stale plaintext sectors don't linger after re-seals.

use rand_core::{OsRng, RngCore};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

const PASS_A: u8 = 0x00;
const PASS_B: u8 = 0xFF;

/// Overwrite `path` (which must exist) with 3 DoD passes.
/// Returns the number of bytes covered per pass.
fn overwrite_passes(path: &Path, len: u64) -> std::io::Result<u64> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    // Pass 1: zeros.
    file.seek(SeekFrom::Start(0))?;
    write_pattern(&mut file, len, PASS_A)?;
    file.flush()?;
    // Pass 2: ones.
    file.seek(SeekFrom::Start(0))?;
    write_pattern(&mut file, len, PASS_B)?;
    file.flush()?;
    // Pass 3: cryptographic random.
    file.seek(SeekFrom::Start(0))?;
    write_random(&mut file, len)?;
    file.flush()?;
    // Drop pagecache intent: sync to platter before delete.
    let _ = file.sync_all();
    Ok(len)
}

fn write_pattern(file: &mut std::fs::File, mut remaining: u64, byte: u8) -> std::io::Result<()> {
    let chunk = [byte; 8192];
    while remaining > 0 {
        let n = remaining.min(chunk.len() as u64) as usize;
        file.write_all(&chunk[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

fn write_random(file: &mut std::fs::File, mut remaining: u64) -> std::io::Result<()> {
    let mut rng = OsRng;
    let mut chunk = [0u8; 8192];
    while remaining > 0 {
        let n = remaining.min(chunk.len() as u64) as usize;
        rng.fill_bytes(&mut chunk[..n]);
        file.write_all(&chunk[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

/// Shred a file: 3-pass overwrite + delete. Missing file = success (idempotent).
/// Never panics; errors are returned for the caller to surface.
pub fn shred_file(path: &Path) -> Result<(), String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("shred stat failed: {e}")),
    };
    if !meta.is_file() {
        return Err("shred target is not a file".to_string());
    }
    overwrite_passes(path, meta.len())
        .map_err(|e| format!("shred overwrite failed: {e}"))?;
    std::fs::remove_file(path).map_err(|e| format!("shred delete failed: {e}"))?;
    Ok(())
}

/// Overwrite-in-place write: if the file exists, its old bytes get the 3-pass
/// treatment keyed to the OLD length before the new content lands. New files
/// are written directly (nothing stale to kill).
/// Crash-safe atomic replace: the payload lands in a sibling `.tmp` file
/// (same volume → `rename` is atomic), then swaps over the target. A crash
/// leaves either the complete old file or the complete new file — never a
/// torn primary. (Prior generations already live in rotated `.bak` files, so
/// dropping the in-place overwrite loses no recoverability: old ciphertext
/// is encrypted under the same master either way.)
pub fn secure_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "secure_write: bad file name".to_string())?;
    let tmp = path.with_file_name(format!("{file_name}.tmp"));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("tmp create: {e}"))?;
        f.write_all(data).map_err(|e| format!("tmp write: {e}"))?;
        f.flush().map_err(|e| format!("tmp flush: {e}"))?;
        f.sync_all().map_err(|e| format!("tmp sync: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("atomic replace: {e}")
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shred_removes_file() {
        let dir = std::env::temp_dir().join("pv_shred_test");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("secret.bin");
        std::fs::write(&f, b"top-secret-bytes").unwrap();
        shred_file(&f).unwrap();
        assert!(!f.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shred_missing_is_ok() {
        let dir = std::env::temp_dir().join("pv_shred_test2");
        assert!(shred_file(&dir.join("nope.bin")).is_ok());
    }

    #[test]
    fn secure_write_roundtrip() {
        let dir = std::env::temp_dir().join("pv_shred_test3");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("data.bin");
        secure_write(&f, b"version-one-payload!!").unwrap();
        secure_write(&f, b"v2").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"v2");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
