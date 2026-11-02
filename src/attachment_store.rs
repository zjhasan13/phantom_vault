//! A24a: chunked, separately encrypted attachment sidecars (`PVAB1`).
//!
//! This slice defines and tests the on-disk format only; it is not wired into
//! the vault yet (A24b does the migration + UI, A24c the export/sync bundle).
//! The goal is to stop re-encrypting the whole vault for every attachment byte:
//! each file gets its own random key (wrapped by the vault attachment root) and
//! is sealed in 1 MiB chunks with a fresh nonce and an id/index AAD.
//!
//! Honest limits: the sidecar is only as strong as the vault attachment root,
//! which lives inside the encrypted vault JSON. A copied sidecar without the
//! root is unreadable; a deleted sidecar is unrecoverable unless the vault is
//! restored with it. There is no compression and no deduplication.

#![allow(dead_code)] // slice A24a: wired into the vault in A24b

use crate::models::{
    AttachmentStorage, EncryptedAttachment, SidecarMeta, Vault,
};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use rand_core::{OsRng, RngCore};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const SIDECAR_MAGIC: &[u8; 5] = b"PVAB1";
pub const SIDECAR_EXT: &str = "pvab";
/// 1 MiB keeps peak memory predictable for large files.
pub const CHUNK_SIZE: u32 = 1024 * 1024;
/// Ceiling for one attachment sidecar (kept in sync with models).
pub const MAX_SIDECAR_BYTES: u64 = crate::models::MAX_SIDECAR_ATTACHMENT_BYTES as u64;
const FLAGS: u8 = 0;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const WRAPPED_KEY_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
const HEADER_LEN: usize = 5 + 1 + 4 + 4 + 8 + WRAPPED_KEY_LEN;

/// Vault-side metadata for one sidecar. The sidecar header must match this.
/// (The type lives in `models` because it is serialized into the vault.)
fn chunk_len(meta: &SidecarMeta, index: u32) -> Result<usize, String> {
    if index >= meta.chunk_count {
        return Err("attachment chunk index out of range".to_string());
    }
    let start = u64::from(index) * u64::from(meta.chunk_size);
    let left = meta.size_bytes.saturating_sub(start);
    Ok(left.min(u64::from(meta.chunk_size)) as usize)
}

fn key_aad(id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(9 + id.len());
    aad.extend_from_slice(b"PVAB1-key");
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn chunk_aad(id: &str, index: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(9 + id.len());
    aad.extend_from_slice(SIDECAR_MAGIC);
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&index.to_le_bytes());
    aad
}

fn wrap_file_key(root: &[u8; 32], id: &str, file_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(root));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: file_key,
                aad: &key_aad(id),
            },
        )
        .map_err(|_| "attachment key wrap failed".to_string())?;
    let mut out = Vec::with_capacity(WRAPPED_KEY_LEN);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unwrap_file_key(root: &[u8; 32], id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err("attachment wrapped key has the wrong length".to_string());
    }
    let (nonce, ct) = wrapped.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(root));
    let plain = cipher
        .decrypt(
            chacha20poly1305::XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &key_aad(id),
            },
        )
        .map_err(|_| "attachment key cannot be unwrapped (wrong vault/root?)".to_string())?;
    if plain.len() != KEY_LEN {
        return Err("attachment file key has the wrong length".to_string());
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plain);
    let mut plain = plain;
    plain.zeroize();
    Ok(key)
}

fn seal_chunk(file_key: &[u8; 32], id: &str, index: u32, plain: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(file_key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plain,
                aad: &chunk_aad(id, index),
            },
        )
        .map_err(|_| "attachment chunk seal failed".to_string())?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_chunk(
    file_key: &[u8; 32],
    id: &str,
    index: u32,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if payload.len() < NONCE_LEN + TAG_LEN {
        return Err("attachment chunk is truncated".to_string());
    }
    let (nonce, ct) = payload.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(file_key));
    cipher
        .decrypt(
            chacha20poly1305::XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &chunk_aad(id, index),
            },
        )
        .map_err(|_| "attachment chunk is corrupt or was reordered".to_string())
}

/// Validate the declared geometry without touching a file.
fn validate_geometry(size_bytes: u64, chunk_size: u32, chunk_count: u32) -> Result<(), String> {
    if size_bytes > MAX_SIDECAR_BYTES {
        return Err(format!(
            "attachment is too large ({size_bytes} bytes; max {MAX_SIDECAR_BYTES})"
        ));
    }
    if !(1..=8 * 1024 * 1024).contains(&chunk_size) {
        return Err("attachment chunk size is out of range".to_string());
    }
    let want = if size_bytes == 0 {
        0
    } else {
        size_bytes.div_ceil(u64::from(chunk_size))
    };
    if u64::from(chunk_count) != want {
        return Err("attachment chunk count does not match its size".to_string());
    }
    Ok(())
}

/// Write `reader` as a `PVAB1` sidecar. `size_bytes` must be the exact length;
/// the reader is checked for a short or over-long stream. Returns the metadata
/// the vault must persist.
pub fn write_sidecar<R: Read>(
    path: &Path,
    mut reader: R,
    size_bytes: u64,
    root: &[u8; 32],
    id: &str,
) -> Result<SidecarMeta, String> {
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("attachment id must be short hex".to_string());
    }
    let chunk_size = CHUNK_SIZE;
    let chunk_count = if size_bytes == 0 {
        0
    } else {
        size_bytes.div_ceil(u64::from(chunk_size)) as u32
    };
    validate_geometry(size_bytes, chunk_size, chunk_count)?;

    let mut file_key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut file_key);
    let wrapped_key = wrap_file_key(root, id, &file_key)?;

    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("attachment.pvab")
    ));
    let result = (|| -> Result<SidecarMeta, String> {
        let file = std::fs::File::create(&tmp)
            .map_err(|e| format!("attachment temp create: {e}"))?;
        let mut out = std::io::BufWriter::new(file);
        out.write_all(SIDECAR_MAGIC)
            .and_then(|_| out.write_all(&[FLAGS]))
            .and_then(|_| out.write_all(&chunk_size.to_le_bytes()))
            .and_then(|_| out.write_all(&chunk_count.to_le_bytes()))
            .and_then(|_| out.write_all(&size_bytes.to_le_bytes()))
            .and_then(|_| out.write_all(&wrapped_key))
            .map_err(|e| format!("attachment header write: {e}"))?;

        let mut remaining = size_bytes;
        for index in 0..chunk_count {
            let want = remaining.min(u64::from(chunk_size)) as usize;
            let mut buf = vec![0u8; want];
            reader
                .read_exact(&mut buf)
                .map_err(|e| format!("attachment read (chunk {index}): {e}"))?;
            let sealed = seal_chunk(&file_key, id, index, &buf);
            buf.zeroize();
            out.write_all(&sealed?)
                .map_err(|e| format!("attachment chunk write: {e}"))?;
            remaining -= want as u64;
        }
        // A reader that hands out more bytes than declared is a bug/hostile.
        let mut extra = [0u8; 1];
        match reader.read(&mut extra) {
            Ok(0) => {}
            Ok(_) => return Err("attachment stream is longer than declared".to_string()),
            Err(e) => return Err(format!("attachment read tail: {e}")),
        }
        out.flush()
            .map_err(|e| format!("attachment flush: {e}"))?;
        out.get_ref()
            .sync_all()
            .map_err(|e| format!("attachment sync: {e}"))?;
        Ok(SidecarMeta {
            chunk_size,
            chunk_count,
            size_bytes,
            wrapped_key,
        })
    })();

    file_key.zeroize();
    match result {
        Ok(meta) => {
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
            std::fs::rename(&tmp, path)
                .map_err(|e| format!("attachment swap: {e}"))?;
            Ok(meta)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Convenience wrapper for callers that already hold the file in memory.
pub fn write_sidecar_bytes(
    path: &Path,
    plaintext: &[u8],
    root: &[u8; 32],
    id: &str,
) -> Result<SidecarMeta, String> {
    write_sidecar(
        path,
        std::io::Cursor::new(plaintext),
        plaintext.len() as u64,
        root,
        id,
    )
}

fn read_header(path: &Path) -> Result<(SidecarMeta, std::fs::File), String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("attachment open: {e}"))?;
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|_| "attachment header is truncated".to_string())?;
    if &header[..5] != SIDECAR_MAGIC {
        return Err("not a PhantomVault attachment sidecar".to_string());
    }
    if header[5] != FLAGS {
        return Err("unsupported attachment flags".to_string());
    }
    let chunk_size = u32::from_le_bytes(header[6..10].try_into().unwrap());
    let chunk_count = u32::from_le_bytes(header[10..14].try_into().unwrap());
    let size_bytes = u64::from_le_bytes(header[14..22].try_into().unwrap());
    let wrapped_key = header[22..HEADER_LEN].to_vec();
    validate_geometry(size_bytes, chunk_size, chunk_count)?;
    Ok((
        SidecarMeta {
            chunk_size,
            chunk_count,
            size_bytes,
            wrapped_key,
        },
        file,
    ))
}

/// Read and decrypt a sidecar. `meta` must be the vault-side metadata; the
/// header is additionally checked to match it byte-for-byte.
pub fn read_sidecar(
    path: &Path,
    root: &[u8; 32],
    id: &str,
    meta: &SidecarMeta,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(meta.size_bytes as usize);
    copy_sidecar_to_writer(path, root, id, meta, &mut out)?;
    Ok(out)
}

/// Stream-decrypt a sidecar into `out` (bounded 1 MiB chunks; no full-file
/// allocation). Returns the number of plaintext bytes written.
pub fn copy_sidecar_to_writer<W: Write>(
    path: &Path,
    root: &[u8; 32],
    id: &str,
    meta: &SidecarMeta,
    out: &mut W,
) -> Result<u64, String> {
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("attachment id must be short hex".to_string());
    }
    let (header, mut file) = read_header(path)?;
    if &header != meta {
        return Err("attachment metadata does not match its sidecar".to_string());
    }
    let mut file_key = unwrap_file_key(root, id, &header.wrapped_key)?;
    let mut written = 0u64;
    for index in 0..header.chunk_count {
        let want = chunk_len(&header, index)?;
        let record_len = NONCE_LEN + want + TAG_LEN;
        let mut record = vec![0u8; record_len];
        file.read_exact(&mut record)
            .map_err(|_| "attachment chunk is truncated".to_string())?;
        let plain = open_chunk(&file_key, id, index, &record);
        record.zeroize();
        let mut plain = plain?;
        out.write_all(&plain)
            .map_err(|e| format!("attachment write: {e}"))?;
        written += plain.len() as u64;
        plain.zeroize();
    }
    // Reject trailing records/bytes even if the geometry says otherwise.
    let mut extra = [0u8; 1];
    match file.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => return Err("attachment has trailing data".to_string()),
        Err(e) => return Err(format!("attachment tail read: {e}")),
    }
    file_key.zeroize();
    if written != header.size_bytes {
        return Err("attachment plaintext length mismatch".to_string());
    }
    Ok(written)
}

/// 32-byte attachment root from the vault. Fails closed when a sidecar exists
/// but the root was lost (never mint a new root silently).
pub fn root_from_vault(vault: &Vault) -> Result<[u8; 32], String> {
    if vault.attachment_root.len() != 32 {
        return Err(
            "attachment key missing or malformed — restore the vault backup".to_string(),
        );
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&vault.attachment_root);
    Ok(root)
}

/// Generate the root on first use (only for a vault that has no sidecars yet).
pub fn ensure_root(vault: &mut Vault) -> Result<[u8; 32], String> {
    if vault.attachment_root.is_empty() {
        let mut root = [0u8; 32];
        OsRng.fill_bytes(&mut root);
        vault.attachment_root = root.to_vec();
        Ok(root)
    } else {
        root_from_vault(vault)
    }
}

pub fn sidecar_dir(vault_path: &Path) -> PathBuf {
    // Test/portable override; production uses the vault's sibling directory.
    if let Ok(dir) = std::env::var("PV_ATTACH_DIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    vault_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("attachments")
}

pub fn sidecar_path(vault_path: &Path, id: &str) -> PathBuf {
    sidecar_dir(vault_path).join(format!("{id}.{SIDECAR_EXT}"))
}

/// Attachment ids are short hex (random 16 bytes rendered as hex).
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Local encrypted sidecars `(id, path)`; ignores temp/tombstone files.
pub fn sidecar_files(vault_path: &Path) -> Vec<(String, PathBuf)> {
    let Ok(rd) = std::fs::read_dir(sidecar_dir(vault_path)) else {
        return Vec::new();
    };
    let mut out: Vec<(String, PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some(SIDECAR_EXT) {
                return None;
            }
            let id = path.file_stem()?.to_str()?.to_string();
            if id.is_empty()
                || id.len() > 128
                || !id.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return None;
            }
            Some((id, path))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Store an already-encrypted sidecar downloaded from a relay. Temp+rename;
/// refuses empty/oversized payloads and non-hex ids.
pub fn write_sidecar_raw(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_SIDECAR_BYTES {
        return Err("downloaded attachment sidecar has an invalid size".to_string());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("attachment folder: {e}"))?;
    }
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("attachment.pvab")
    ));
    std::fs::write(&tmp, bytes).map_err(|e| format!("attachment temp write: {e}"))?;
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("attachment swap: {e}")
    })
}

fn deleted_path(vault_path: &Path) -> PathBuf {
    sidecar_dir(vault_path).join(".deleted")
}

/// Record a sidecar id for remote deletion on the next sync (delete-on-revoke).
pub fn append_deleted(vault_path: &Path, id: &str) {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return;
    }
    let path = deleted_path(vault_path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{id}");
    }
}

/// Pending remote-delete ids (does not clear them; call `clear_deleted` after
/// the relay delete succeeds).
pub fn pending_deleted(vault_path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(deleted_path(vault_path)) else {
        return Vec::new();
    };
    let mut out: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn clear_deleted(vault_path: &Path, id: &str) {
    let path = deleted_path(vault_path);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let rest: Vec<&str> = text.lines().filter(|l| l.trim() != id).collect();
    if rest.is_empty() {
        let _ = std::fs::remove_file(&path);
    } else {
        let _ = std::fs::write(&path, rest.join("\n") + "\n");
    }
}

/// True when the on-disk attachment directory has any sidecar (used to block
/// sync/P2P until A24c can transfer sidecars). Conservative: orphans count.
pub fn dir_has_sidecars(vault_path: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(sidecar_dir(vault_path)) else {
        return false;
    };
    rd.flatten().any(|e| {
        e.path()
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| x.eq_ignore_ascii_case(SIDECAR_EXT))
            .unwrap_or(false)
    })
}

fn list_has_sidecar<'a>(mut items: impl Iterator<Item = &'a EncryptedAttachment>) -> bool {
    items.any(|a| a.storage == AttachmentStorage::Sidecar)
}

pub fn has_sidecars(vault: &Vault) -> bool {
    list_has_sidecar(vault.credentials.iter().flat_map(|i| i.attachments.iter()))
        || list_has_sidecar(vault.licenses.iter().flat_map(|i| i.attachments.iter()))
        || list_has_sidecar(vault.notes.iter().flat_map(|i| i.attachments.iter()))
        || list_has_sidecar(vault.cards.iter().flat_map(|i| i.attachments.iter()))
        || list_has_sidecar(vault.identities.iter().flat_map(|i| i.attachments.iter()))
        || list_has_sidecar(vault.ssh_keys.iter().flat_map(|i| i.attachments.iter()))
}

/// Decrypt/read one attachment's bytes (inline legacy or sidecar).
pub fn attachment_bytes(
    vault: &Vault,
    att: &EncryptedAttachment,
    vault_path: &Path,
) -> Result<Vec<u8>, String> {
    match att.storage {
        AttachmentStorage::Inline => Ok(att.data.clone()),
        AttachmentStorage::Sidecar => {
            let meta = att
                .sidecar
                .as_ref()
                .ok_or_else(|| "attachment sidecar metadata is missing".to_string())?;
            let root = root_from_vault(vault)?;
            read_sidecar(
                &sidecar_path(vault_path, &att.id),
                &root,
                &att.id,
                meta,
            )
        }
    }
}

/// Stream one attachment (inline or sidecar) into `out`.
pub fn attachment_write_to<W: Write>(
    vault: &Vault,
    att: &EncryptedAttachment,
    vault_path: &Path,
    out: &mut W,
) -> Result<u64, String> {
    match att.storage {
        AttachmentStorage::Inline => {
            out.write_all(&att.data)
                .map_err(|e| format!("attachment write: {e}"))?;
            Ok(att.data.len() as u64)
        }
        AttachmentStorage::Sidecar => {
            let meta = att
                .sidecar
                .as_ref()
                .ok_or_else(|| "attachment sidecar metadata is missing".to_string())?;
            let root = root_from_vault(vault)?;
            copy_sidecar_to_writer(
                &sidecar_path(vault_path, &att.id),
                &root,
                &att.id,
                meta,
                out,
            )
        }
    }
}

fn inline_list(
    list: &mut [EncryptedAttachment],
    root: &[u8; 32],
    vault_path: &Path,
) -> Result<(), String> {
    for att in list {
        if att.storage != AttachmentStorage::Sidecar {
            continue;
        }
        let meta = att
            .sidecar
            .as_ref()
            .ok_or_else(|| "attachment sidecar metadata is missing".to_string())?;
        let bytes = read_sidecar(
            &sidecar_path(vault_path, &att.id),
            root,
            &att.id,
            meta,
        )?;
        att.data = bytes;
        att.storage = AttachmentStorage::Inline;
        att.sidecar = None;
    }
    Ok(())
}

fn count_list(list: &[EncryptedAttachment], sidecar: bool) -> usize {
    list.iter()
        .filter(|a| (a.storage == AttachmentStorage::Sidecar) == sidecar)
        .count()
}

pub fn attachment_counts(vault: &Vault) -> (usize, usize) {
    let mut inline = 0;
    let mut sidecar = 0;
    for item in &vault.credentials {
        inline += count_list(&item.attachments, false);
        sidecar += count_list(&item.attachments, true);
    }
    for item in &vault.licenses {
        inline += count_list(&item.attachments, false);
        sidecar += count_list(&item.attachments, true);
    }
    for item in &vault.notes {
        inline += count_list(&item.attachments, false);
        sidecar += count_list(&item.attachments, true);
    }
    for item in &vault.cards {
        inline += count_list(&item.attachments, false);
        sidecar += count_list(&item.attachments, true);
    }
    for item in &vault.identities {
        inline += count_list(&item.attachments, false);
        sidecar += count_list(&item.attachments, true);
    }
    for item in &vault.ssh_keys {
        inline += count_list(&item.attachments, false);
        sidecar += count_list(&item.attachments, true);
    }
    (inline, sidecar)
}

fn migrate_list(
    list: &mut [EncryptedAttachment],
    root: &[u8; 32],
    vault_path: &Path,
    written: &mut Vec<PathBuf>,
) -> Result<usize, String> {
    if list.iter().any(|a| a.storage == AttachmentStorage::Inline) {
        std::fs::create_dir_all(sidecar_dir(vault_path))
            .map_err(|e| format!("attachment folder: {e}"))?;
    }
    let mut moved = 0;
    for att in list {
        if att.storage != AttachmentStorage::Inline {
            continue;
        }
        if !valid_id(&att.id) {
            let mut raw = [0u8; 16];
            OsRng.fill_bytes(&mut raw);
            att.id = raw.iter().map(|b| format!("{b:02x}")).collect();
        }
        let path = sidecar_path(vault_path, &att.id);
        let meta = write_sidecar_bytes(&path, &att.data, root, &att.id)?;
        written.push(path);
        att.data.zeroize();
        att.data.clear();
        att.sidecar = Some(meta);
        att.storage = AttachmentStorage::Sidecar;
        moved += 1;
    }
    Ok(moved)
}

/// A24d: one-time move of every inline attachment into a sidecar. The vault is
/// cloned first, so a failure leaves the original unchanged; newly written
/// sidecars are removed on failure. Returns the number moved.
pub fn migrate_inline_all(vault: &mut Vault, vault_path: &Path) -> Result<usize, String> {
    if attachment_counts(vault).0 == 0 {
        return Ok(0);
    }
    let mut out = vault.clone();
    let root = if out.attachment_root.is_empty() {
        if has_sidecars(&out) {
            return Err("attachment root missing — restore the vault backup".to_string());
        }
        ensure_root(&mut out)?
    } else {
        root_from_vault(&out)?
    };
    let mut written: Vec<PathBuf> = Vec::new();
    let result = (|| -> Result<usize, String> {
        let mut moved = 0;
        for item in &mut out.credentials {
            moved += migrate_list(&mut item.attachments, &root, vault_path, &mut written)?;
        }
        for item in &mut out.licenses {
            moved += migrate_list(&mut item.attachments, &root, vault_path, &mut written)?;
        }
        for item in &mut out.notes {
            moved += migrate_list(&mut item.attachments, &root, vault_path, &mut written)?;
        }
        for item in &mut out.cards {
            moved += migrate_list(&mut item.attachments, &root, vault_path, &mut written)?;
        }
        for item in &mut out.identities {
            moved += migrate_list(&mut item.attachments, &root, vault_path, &mut written)?;
        }
        for item in &mut out.ssh_keys {
            moved += migrate_list(&mut item.attachments, &root, vault_path, &mut written)?;
        }
        Ok(moved)
    })();
    match result {
        Ok(moved) => {
            *vault = out;
            Ok(moved)
        }
        Err(e) => {
            for path in written {
                let _ = std::fs::remove_file(path);
            }
            Err(e)
        }
    }
}
/// Return a clone with every sidecar decrypted back into `data` — used by the
/// legacy single-blob `.pvx` export so old files stay readable. The clone can
/// be large; export is an explicit, infrequent action.
pub fn inline_all(vault: &Vault, vault_path: &Path) -> Result<Vault, String> {
    if !has_sidecars(vault) {
        return Ok(vault.clone());
    }
    let root = root_from_vault(vault)?;
    let mut out = vault.clone();
    for item in &mut out.credentials {
        inline_list(&mut item.attachments, &root, vault_path)?;
    }
    for item in &mut out.licenses {
        inline_list(&mut item.attachments, &root, vault_path)?;
    }
    for item in &mut out.notes {
        inline_list(&mut item.attachments, &root, vault_path)?;
    }
    for item in &mut out.cards {
        inline_list(&mut item.attachments, &root, vault_path)?;
    }
    for item in &mut out.identities {
        inline_list(&mut item.attachments, &root, vault_path)?;
    }
    for item in &mut out.ssh_keys {
        inline_list(&mut item.attachments, &root, vault_path)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pv-a24-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}.pvab"))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) & 0xff) as u8).collect()
    }

    #[test]
    fn chunks_roundtrip_and_empty_files_work() {
        let root = [9u8; 32];
        let data = pattern(CHUNK_SIZE as usize * 2 + 777);
        let path = tmp("roundtrip");
        let meta = write_sidecar_bytes(&path, &data, &root, "a1").unwrap();
        assert_eq!(meta.chunk_size, CHUNK_SIZE);
        assert_eq!(meta.chunk_count, 3);
        assert_eq!(meta.size_bytes, data.len() as u64);
        assert_eq!(read_sidecar(&path, &root, "a1", &meta).unwrap(), data);

        let empty_path = tmp("empty");
        let empty = write_sidecar_bytes(&empty_path, &[], &root, "a2").unwrap();
        assert_eq!(empty.chunk_count, 0);
        assert!(read_sidecar(&empty_path, &root, "a2", &empty).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(empty_path.parent().unwrap());
    }

    #[test]
    fn wrong_root_id_tamper_and_reorder_fail_closed() {
        let root = [9u8; 32];
        let data = pattern(CHUNK_SIZE as usize * 2 + 17);
        let path = tmp("failclosed");
        let meta = write_sidecar_bytes(&path, &data, &root, "a1").unwrap();

        assert!(read_sidecar(&path, &[8u8; 32], "a1", &meta).is_err());
        assert!(read_sidecar(&path, &root, "a2", &meta).is_err());
        let mut wrong = meta.clone();
        wrong.size_bytes += 1;
        assert!(read_sidecar(&path, &root, "a1", &wrong).is_err());

        // Tamper the first chunk's ciphertext.
        let mut bytes = std::fs::read(&path).unwrap();
        let first_chunk = HEADER_LEN + NONCE_LEN + 8;
        bytes[first_chunk] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(read_sidecar(&path, &root, "a1", &meta).is_err());

        // Restore, then swap chunk 0 and 1 (same length) — the id/index AAD
        // must reject it even though both chunks authenticate individually.
        let path2 = tmp("reorder");
        let meta2 = write_sidecar_bytes(&path2, &data, &root, "a1").unwrap();
        let mut bytes = std::fs::read(&path2).unwrap();
        let record = NONCE_LEN + CHUNK_SIZE as usize + TAG_LEN;
        let a = HEADER_LEN;
        let b = HEADER_LEN + record;
        let first: Vec<u8> = bytes[a..a + record].to_vec();
        let second: Vec<u8> = bytes[b..b + record].to_vec();
        bytes[a..a + record].copy_from_slice(&second);
        bytes[b..b + record].copy_from_slice(&first);
        std::fs::write(&path2, &bytes).unwrap();
        assert!(read_sidecar(&path2, &root, "a1", &meta2).is_err());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(path2.parent().unwrap());
    }

    #[test]
    fn oversized_and_wrong_length_streams_are_refused() {
        let root = [1u8; 32];
        let path = tmp("oversize");
        assert!(write_sidecar(
            &path,
            std::io::empty(),
            MAX_SIDECAR_BYTES + 1,
            &root,
            "a1"
        )
        .is_err());
        // Declared 3 bytes but the reader has 4 → refuse and leave no file.
        assert!(write_sidecar(
            &path,
            std::io::Cursor::new(vec![0u8; 4]),
            3,
            &root,
            "a1"
        )
        .is_err());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    #[ignore = "50 MiB manual QA: run with --ignored"]
    fn fifty_mib_sidecar_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pv-a24-50m-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.pvab");
        let root = [7u8; 32];
        let data = vec![0xABu8; 50 * 1024 * 1024];
        let meta = write_sidecar_bytes(&path, &data, &root, "a1").unwrap();
        assert_eq!(meta.chunk_count, 50);
        assert_eq!(meta.size_bytes, 50 * 1024 * 1024);
        let got = read_sidecar(&path, &root, "a1", &meta).unwrap();
        assert_eq!(got.len(), data.len());
        assert_eq!(&got[..1024], &data[..1024]);
        assert_eq!(&got[data.len() - 1024..], &data[data.len() - 1024..]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inline_migration_moves_bytes_without_loss() {
        let dir = std::env::temp_dir().join(format!("pv-a24-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.enc");
        let root = [4u8; 32];
        let data = pattern(1234);
        let mut list = vec![EncryptedAttachment {
            // Legacy ids were not hex (`att<millis>`); migration must remap.
            id: "att123".into(),
            filename: "x.bin".into(),
            mime_type: "application/octet-stream".into(),
            size_bytes: data.len(),
            data: data.clone(),
            storage: AttachmentStorage::Inline,
            sidecar: None,
        }];
        let mut written = Vec::new();
        assert_eq!(migrate_list(&mut list, &root, &vault_path, &mut written).unwrap(), 1);
        assert!(list[0].data.is_empty());
        assert_eq!(list[0].storage, AttachmentStorage::Sidecar);
        assert!(valid_id(&list[0].id));
        let meta = list[0].sidecar.as_ref().unwrap();
        let got = read_sidecar(&written[0], &root, &list[0].id, meta).unwrap();
        assert_eq!(got, data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_files_and_delete_tombstones_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pv-a24-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.enc");
        std::fs::create_dir_all(sidecar_dir(&vault_path)).unwrap();
        std::fs::write(sidecar_path(&vault_path, "a1"), b"x").unwrap();
        std::fs::write(sidecar_path(&vault_path, "b2"), b"y").unwrap();
        std::fs::write(sidecar_dir(&vault_path).join(".deleted"), b"").unwrap();
        let files = sidecar_files(&vault_path);
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|(id, _)| id == "a1" || id == "b2"));

        append_deleted(&vault_path, "a1");
        append_deleted(&vault_path, "a1");
        append_deleted(&vault_path, "bad!");
        assert_eq!(pending_deleted(&vault_path), vec!["a1".to_string()]);
        clear_deleted(&vault_path, "a1");
        assert!(pending_deleted(&vault_path).is_empty());
        assert!(!dir.join("attachments/.deleted").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_generation_and_export_inlining_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pv-a24-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.enc");

        let mut vault = Vault::default();
        assert!(root_from_vault(&vault).is_err(), "no silent root");
        let root = ensure_root(&mut vault).unwrap();
        assert_eq!(root_from_vault(&vault).unwrap(), root);

        let data = pattern(4096);
        let path = sidecar_path(&vault_path, "ab12");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let meta = write_sidecar_bytes(&path, &data, &root, "ab12").unwrap();
        assert!(dir_has_sidecars(&vault_path));
        assert!(!has_sidecars(&vault));

        let mut list = vec![EncryptedAttachment {
            id: "ab12".into(),
            filename: "x.bin".into(),
            mime_type: "application/octet-stream".into(),
            size_bytes: data.len(),
            data: Vec::new(),
            storage: AttachmentStorage::Sidecar,
            sidecar: Some(meta),
        }];
        inline_list(&mut list, &root, &vault_path).unwrap();
        assert_eq!(list[0].data, data);
        assert_eq!(list[0].storage, AttachmentStorage::Inline);
        assert!(list[0].sidecar.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
