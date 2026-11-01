//! A22 Phase D1: CNG-backed sealing of the PQ device key.
//!
//! Production target: the Microsoft **Platform Crypto Provider** (TPM 2.0).
//! Tests use the Microsoft **Software Key Storage Provider** — the same NCrypt
//! code path without a TPM, so CI can exercise it.
//!
//! Scheme: a persisted RSA-2048 key wraps a random 32-byte key with RSA-OAEP
//! (SHA-256); that random key seals the ML-KEM decapsulation key with
//! XChaCha20-Poly1305. The TPM never sees the 2400-byte DK directly.
//!
//! Blob (`PVT1`):
//! `magic 4 | version 1 | backend 1 | name_len 1 | name N | rsa_ct_len 2 LE |
//! rsa_ct 256 | nonce 24 | sealed_dk 2416`
//!
//! Honest limits (D0): same-user malware can still call NCryptDecrypt because
//! user-presence (`NCRYPT_UI_PROTECT_KEY_FLAG`) is deliberately off; losing the
//! TPM key (TPM clear, Windows reinstall) means the DK is unrecoverable.

use rand_core::{OsRng, RngCore};
use windows::core::{w, PCWSTR};
use windows::Win32::Security::Cryptography::{
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, MS_KEY_STORAGE_PROVIDER,
    MS_PLATFORM_CRYPTO_PROVIDER, NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt,
    NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, CERT_KEY_SPEC, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY,
    NCRYPT_PAD_OAEP_FLAG, NCRYPT_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM, NCRYPT_SILENT_FLAG,
};
use zeroize::Zeroize;

pub const BLOB_MAGIC: &[u8; 4] = b"PVT1";
pub const BLOB_VERSION: u8 = 1;
/// Persisted CNG key name. One device key per Windows user profile.
pub const KEY_NAME: &str = "PhantomVault-PQ-Device-v1";
const KEY_NAME_W: PCWSTR = w!("PhantomVault-PQ-Device-v1");
/// RSA-2048 ciphertext length (fixed by the key size).
pub const RSA_CT_LEN: usize = 256;
const RSA_BITS: u32 = 2048;
/// Sealed-DK payload: 24-byte nonce + 2400-byte DK + 16-byte tag.
pub const SEALED_LEN: usize = 24 + crate::core::pq_hybrid::DK_LEN + 16;

const TAG_TPM: u8 = 2;
/// Software KSP blobs are test-only and must never be accepted as production
/// hardware custody.
const TAG_SOFTWARE: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Tpm,
    Software,
}

impl Backend {
    fn provider(self) -> PCWSTR {
        match self {
            Self::Tpm => MS_PLATFORM_CRYPTO_PROVIDER,
            Self::Software => MS_KEY_STORAGE_PROVIDER,
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Tpm => TAG_TPM,
            Self::Software => TAG_SOFTWARE,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, String> {
        match tag {
            TAG_TPM => Ok(Self::Tpm),
            TAG_SOFTWARE => Ok(Self::Software),
            other => Err(format!("unknown PQ key backend tag: {other}")),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::Software => "software",
        }
    }
}

/// Read the backend tag without unsealing (used by the Settings status line).
pub fn blob_backend_label(blob: &[u8]) -> Option<&'static str> {
    if blob.len() < 7 || &blob[..4] != BLOB_MAGIC || blob[4] != BLOB_VERSION {
        return None;
    }
    Backend::from_tag(blob[5]).ok().map(|b| b.label())
}

/// RAII for a CNG provider handle.
struct Prov(NCRYPT_PROV_HANDLE);

impl Drop for Prov {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(prov_handle(self.0));
        }
    }
}

/// RAII for a CNG key handle.
struct Key(NCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(handle(self.0));
        }
    }
}

fn handle(h: NCRYPT_KEY_HANDLE) -> NCRYPT_HANDLE {
    NCRYPT_HANDLE(h.0)
}

fn prov_handle(h: NCRYPT_PROV_HANDLE) -> NCRYPT_HANDLE {
    NCRYPT_HANDLE(h.0)
}

fn open_provider(backend: Backend) -> Result<Prov, String> {
    let mut prov = NCRYPT_PROV_HANDLE::default();
    // SAFETY: the provider name is a static wide string; `prov` is valid.
    unsafe { NCryptOpenStorageProvider(&mut prov, backend.provider(), 0) }
        .map_err(|e| format!("CNG provider {:?} unavailable: {e}", backend))?;
    Ok(Prov(prov))
}

/// True when the provider can be opened. A TPM provider may open while key
/// creation still fails (no TPM / policy); the enable flow treats a later seal
/// error as the authoritative signal.
pub fn provider_available(backend: Backend) -> bool {
    open_provider(backend).is_ok()
}

fn open_key(prov: &Prov) -> Result<Key, String> {
    let mut key = NCRYPT_KEY_HANDLE::default();
    // SAFETY: provider + static key name are valid.
    unsafe {
        NCryptOpenKey(
            prov.0,
            &mut key,
            KEY_NAME_W,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| format!("CNG device key not found: {e}"))?;
    Ok(Key(key))
}

fn open_or_create_key(prov: &Prov) -> Result<Key, String> {
    if let Ok(key) = open_key(prov) {
        return Ok(key);
    }
    let mut raw = NCRYPT_KEY_HANDLE::default();
    // SAFETY: provider handle and static algorithm/key names are valid.
    unsafe {
        NCryptCreatePersistedKey(
            prov.0,
            &mut raw,
            NCRYPT_RSA_ALGORITHM,
            KEY_NAME_W,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| format!("CNG device key creation failed: {e}"))?;
    let key = Key(raw);
    let bits = RSA_BITS.to_le_bytes();
    // SAFETY: `key` is a live persisted-key handle.
    unsafe {
        NCryptSetProperty(
            key.0,
            NCRYPT_LENGTH_PROPERTY,
            &bits,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| format!("CNG key length rejected: {e}"))?;
    // SAFETY: same handle, finalized exactly once.
    unsafe { NCryptFinalizeKey(key.0, NCRYPT_FLAGS(0)) }
        .map_err(|e| format!("CNG key finalize failed: {e}"))?;
    Ok(key)
}

fn oaep_padding() -> BCRYPT_OAEP_PADDING_INFO {
    BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    }
}

fn rsa_encrypt(key: &Key, input: &[u8]) -> Result<Vec<u8>, String> {
    let padding = oaep_padding();
    let mut out = vec![0u8; RSA_CT_LEN];
    let mut written = 0u32;
    // SAFETY: input/padding/output buffers are valid for the call duration.
    unsafe {
        NCryptEncrypt(
            key.0,
            Some(input),
            Some(&padding as *const _ as *const core::ffi::c_void),
            Some(out.as_mut_slice()),
            &mut written,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|e| format!("CNG RSA wrap failed: {e}"))?;
    out.truncate(written as usize);
    if out.len() != RSA_CT_LEN {
        return Err("CNG RSA wrap returned an unexpected length".to_string());
    }
    Ok(out)
}

fn rsa_decrypt(key: &Key, ciphertext: &[u8]) -> Result<[u8; 32], String> {
    let padding = oaep_padding();
    // The wrap key is 32 bytes; leave headroom for provider quirks.
    let mut out = vec![0u8; 64];
    let mut written = 0u32;
    // SAFETY: ciphertext/padding/output buffers are valid for the call duration.
    unsafe {
        NCryptDecrypt(
            key.0,
            Some(ciphertext),
            Some(&padding as *const _ as *const core::ffi::c_void),
            Some(out.as_mut_slice()),
            &mut written,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|e| format!("CNG RSA unwrap failed: {e}"))?;
    out.truncate(written as usize);
    if out.len() != 32 {
        out.zeroize();
        return Err("CNG RSA unwrap returned an unexpected length".to_string());
    }
    let mut wrap_key = [0u8; 32];
    wrap_key.copy_from_slice(&out);
    out.zeroize();
    Ok(wrap_key)
}

/// Seal a device key with the TPM (or the software KSP in tests).
pub fn seal(backend: Backend, decapsulation: &[u8]) -> Result<Vec<u8>, String> {
    if decapsulation.len() != crate::core::pq_hybrid::DK_LEN {
        return Err("bad PQ decapsulation key length".to_string());
    }
    let prov = open_provider(backend)?;
    let key = open_or_create_key(&prov)?;

    let mut wrap_key = [0u8; 32];
    OsRng.fill_bytes(&mut wrap_key);
    let rsa_ct = match rsa_encrypt(&key, &wrap_key) {
        Ok(v) => v,
        Err(e) => {
            wrap_key.zeroize();
            return Err(e);
        }
    };
    let sealed = crate::crypto::seal_with_raw_key(&wrap_key, decapsulation);
    wrap_key.zeroize();
    let sealed = sealed?;
    if sealed.len() != SEALED_LEN {
        return Err("sealed device key has an unexpected length".to_string());
    }

    let mut out = Vec::with_capacity(
        4 + 3 + KEY_NAME.len() + 2 + RSA_CT_LEN + SEALED_LEN,
    );
    out.extend_from_slice(BLOB_MAGIC);
    out.push(BLOB_VERSION);
    out.push(backend.tag());
    out.push(KEY_NAME.len() as u8);
    out.extend_from_slice(KEY_NAME.as_bytes());
    out.extend_from_slice(&(rsa_ct.len() as u16).to_le_bytes());
    out.extend_from_slice(&rsa_ct);
    out.extend_from_slice(&sealed);
    Ok(out)
}

struct Parsed<'a> {
    backend: Backend,
    rsa_ct: &'a [u8],
    sealed: &'a [u8],
}

fn parse(blob: &[u8]) -> Result<Parsed<'_>, String> {
    let min = 4 + 3 + KEY_NAME.len() + 2 + RSA_CT_LEN + SEALED_LEN;
    if blob.len() != min {
        return Err("PQ TPM sidecar has an unexpected length".to_string());
    }
    if &blob[..4] != BLOB_MAGIC {
        return Err("PQ TPM sidecar has a bad magic".to_string());
    }
    if blob[4] != BLOB_VERSION {
        return Err("PQ TPM sidecar has an unsupported version".to_string());
    }
    let backend = Backend::from_tag(blob[5])?;
    let name_len = blob[6] as usize;
    if name_len != KEY_NAME.len() || &blob[7..7 + name_len] != KEY_NAME.as_bytes() {
        return Err("PQ TPM sidecar names an unknown device key".to_string());
    }
    let mut off = 7 + name_len;
    let rsa_len = u16::from_le_bytes([blob[off], blob[off + 1]]) as usize;
    off += 2;
    if rsa_len != RSA_CT_LEN {
        return Err("PQ TPM sidecar has an unexpected RSA length".to_string());
    }
    let rsa_ct = &blob[off..off + rsa_len];
    off += rsa_len;
    let sealed = &blob[off..];
    if sealed.len() != SEALED_LEN {
        return Err("PQ TPM sidecar has an unexpected sealed length".to_string());
    }
    Ok(Parsed {
        backend,
        rsa_ct,
        sealed,
    })
}

/// Unseal a `PVT1` blob. Never falls back to DPAPI; any failure is final.
pub fn unseal(blob: &[u8]) -> Result<Vec<u8>, String> {
    let parsed = parse(blob)?;
    let prov = open_provider(parsed.backend)?;
    let key = open_key(&prov)?;
    let mut wrap_key = rsa_decrypt(&key, parsed.rsa_ct)?;
    let opened = crate::crypto::open_with_raw_key(&wrap_key, parsed.sealed);    wrap_key.zeroize();
    let dk = opened?;
    if dk.len() != crate::core::pq_hybrid::DK_LEN {
        return Err("unsealed PQ device key has an unexpected length".to_string());
    }
    Ok(dk)
}

#[cfg(test)]
/// The persisted CNG key name is process-global; tests must not race on it.
pub(crate) static TEST_KEY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_parser_rejects_truncation_and_foreign_names() {
        assert!(parse(b"PVT1").is_err());
        let mut fake = Vec::from(*BLOB_MAGIC);
        fake.extend_from_slice(&[BLOB_VERSION, TAG_TPM, 3]);
        fake.extend_from_slice(b"xxx");
        fake.extend_from_slice(&(RSA_CT_LEN as u16).to_le_bytes());
        fake.extend_from_slice(&[0u8; RSA_CT_LEN + SEALED_LEN]);
        assert!(parse(&fake).is_err());
    }

    #[test]
    fn software_ksp_seals_and_unseals() {
        if !provider_available(Backend::Software) {
            eprintln!("software KSP unavailable; skipping");
            return;
        }
        let _guard = TEST_KEY_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dk = vec![7u8; crate::core::pq_hybrid::DK_LEN];
        let blob = seal(Backend::Software, &dk).expect("seal");
        assert_eq!(&blob[..4], BLOB_MAGIC);
        assert_eq!(blob[5], TAG_SOFTWARE);
        let back = unseal(&blob).expect("unseal");
        assert_eq!(back, dk);

        // Tamper and truncation fail closed.
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(unseal(&bad).is_err());
        assert!(unseal(&blob[..blob.len() - 1]).is_err());
    }
}
