use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::RngCore;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

use crate::core::pq_hybrid::{PqDecapsulationBytes, PqHybridEngine, PqSharedSecret, CT_LEN};
use hkdf::Hkdf;
use sha2::Sha256;

// Salt সাইজ (16 bytes) এবং Nonce সাইজ (24 bytes for XChaCha20)
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

/// Phase 14/17: versioned container magics.
/// - v1 (legacy classical): no magic, raw salt first.
/// - v2-legacy (Phase 14 hybrid, machine-bound DK): `PV2` (3 bytes).
/// - v2-portable (self-contained, key-wrapped DK): `PV2\0` (4 bytes).
/// - v3-paranoid (A22, device-bound decapsulation key): `PV3\0` (4 bytes).
///   The device DK never travels in the container; only an ML-KEM ciphertext
///   encapsulated to this device's key does.
/// - v4 (A-03): `PV4\0` + a one-byte profile, and every header byte before the
///   ciphertext is authenticated as AEAD associated data. v2/v3 stay readable;
///   only v4 is written.
pub const V2_MAGIC: &[u8; 3] = b"PV2";
pub const V2_PORTABLE_MAGIC: &[u8; 4] = b"PV2\x00";
pub const V3_PARANOID_MAGIC: &[u8; 4] = b"PV3\x00";
pub const V4_MAGIC: &[u8; 4] = b"PV4\x00";
/// A-03: profile byte that follows [`V4_MAGIC`]. A container cannot be
/// re-labelled from one profile to the other without breaking the AEAD tag.
pub const V4_MODE_PORTABLE: u8 = 0;
pub const V4_MODE_PARANOID: u8 = 1;
/// `PV4\0` + mode: the bytes both v4 layouts share before the salt.
pub const V4_PREFIX_LEN: usize = 5;

/// A22: HKDF info for the paranoid hybrid key. Distinct from the legacy
/// [`crate::core::pq_hybrid::HYBRID_INFO`] so the two key chains can never
/// be confused even if both inputs happened to match.
pub const PARANOID_INFO: &[u8] = b"phantom_vault_paranoid_v1";

/// Wrapped-DK blob length: DK (2400B) + Poly1305 tag (16B).
pub const WRAPPED_DK_LEN: usize = crate::core::pq_hybrid::DK_LEN + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultVersion {
    V1Classical,
    /// Phase-14 layout: needs the DPAPI `pq_decapsulation.dpapi` sidecar.
    V2Legacy,
    /// Self-contained portable layout: DK wrapped by the Argon2id key.
    V2Portable,
    /// A22 PQ-paranoid layout: Argon2id + this device's ML-KEM decapsulation
    /// key (DPAPI sidecar). The password alone cannot open it.
    V3Paranoid,
    /// A-03: portable hybrid with an AAD-bound header.
    V4Portable,
    /// A-03: paranoid profile with an AAD-bound header.
    V4Paranoid,
}

impl VaultVersion {
    /// True for every device-bound layout: those never travel to another
    /// machine, so sync and P2P must refuse them.
    pub fn is_paranoid(self) -> bool {
        matches!(self, VaultVersion::V3Paranoid | VaultVersion::V4Paranoid)
    }
}

/// Detect container version by magic prefix (4-byte check first).
pub fn detect_version(payload: &[u8]) -> VaultVersion {
    if payload.len() >= 5 && &payload[..4] == V4_MAGIC {
        // A-03: the mode byte decides the profile. An unknown mode is not a
        // container this build understands; fall through to the legacy checks
        // so a corrupted byte cannot be mistaken for a valid v4 file.
        return match payload[4] {
            V4_MODE_PARANOID => VaultVersion::V4Paranoid,
            V4_MODE_PORTABLE => VaultVersion::V4Portable,
            _ => VaultVersion::V1Classical,
        };
    }
    if payload.len() >= 4 && &payload[..4] == V3_PARANOID_MAGIC {
        VaultVersion::V3Paranoid
    } else if payload.len() >= 4 && &payload[..4] == V2_PORTABLE_MAGIC {
        VaultVersion::V2Portable
    } else if payload.len() >= 3 && &payload[..3] == V2_MAGIC {
        VaultVersion::V2Legacy
    } else {
        VaultVersion::V1Classical
    }
}

/// মাস্টার পাসওয়ার্ড এবং Salt থেকে Argon2id ব্যবহার করে ৩২ বাইটের কি (Key) ডেরাইভ করা.
/// Secret-owning variant: the password never materializes as `&str`.
/// `expose_secret()` lives ONLY inside this call scope.
pub fn derive_key_secret(master_password: &SecretString, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut derived_key = [0u8; 32];

    // মেমোরি-হার্ড প্যারামিটার (OWASP স্ট্যান্ডার্ড: 64MB RAM, 3 Iterations, 4 Parallel threads)
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(master_password.expose_secret().as_bytes(), salt, &mut derived_key)
        .map_err(|e| format!("Key derivation error: {}", e))?;

    Ok(derived_key)
}

/// Legacy `&str` entrypoint — prefer [`derive_key_secret`]. All production
/// call sites are migrated; only compat tests still use this path
/// (under `#[allow(deprecated)]` in `mod tests`).
#[deprecated(note = "use derive_key_secret with a SecretString")]
pub fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    derive_key_secret(&SecretString::new(master_password.to_string()), salt)
}

/// XChaCha20-Poly1305 দিয়ে প্লেইনটেক্সট এনক্রিপ্ট করা
/// রিটার্ন করবে: [16 bytes Salt] + [24 bytes Nonce] + [Ciphertext + Auth Tag]
/// Secret-owning variant — see [`derive_key_secret`].
pub fn encrypt_vault_secret(master_password: &SecretString, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    // ১. ১৬ বাইটের ক্রিপ্টোগ্রাফিক ট্রু র‍্যান্ডম Salt জেনারেট করা
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // ২. কি (Key) তৈরি করা
    let mut key_bytes = derive_key_secret(master_password, &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    // ৩. ২৪ বাইটের ইউনিক Nonce জেনারেট করা
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    // ৪. ডেটা এনক্রিপ্ট করা
    // An encrypt error must still wipe the derived key: `?` would drop the
    // plain `[u8; 32]` without zeroizing it.
    let ciphertext = match cipher.encrypt(&nonce, plaintext) {
        Ok(v) => v,
        Err(e) => {
            key_bytes.zeroize();
            return Err(format!("Encryption error: {}", e));
        }
    };

    // মেমোরি থেকে সিক্রেট কি সাথে সাথে মুছে ফেলা
    key_bytes.zeroize();

    // ৫. সবকিছু একসাথে প্যাক করা: [Salt] + [Nonce] + [Ciphertext]
    let mut final_payload = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    final_payload.extend_from_slice(&salt);
    final_payload.extend_from_slice(&nonce);
    final_payload.extend_from_slice(&ciphertext);

    Ok(final_payload)
}

/// Legacy `&str` entrypoint — prefer [`encrypt_vault_secret`].
/// (Compat tests only — see [`derive_key`].)
#[deprecated(note = "use encrypt_vault_secret with a SecretString")]
pub fn encrypt_vault(master_password: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_vault_secret(&SecretString::new(master_password.to_string()), plaintext)
}

/// এনক্রিপ্ট করা পেলোড থেকে ডিক্রিপ্ট করে আসল ডাটা বের করা
/// Secret-owning variant — see [`derive_key_secret`].
pub fn decrypt_vault_secret(master_password: &SecretString, encrypted_payload: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted_payload.len() < SALT_LEN + NONCE_LEN {
        return Err("Invalid payload: data is too short!".to_string());
    }

    // ১. Salt ও Nonce আলাদা করে নেওয়া
    let salt = &encrypted_payload[..SALT_LEN];
    let nonce = XNonce::from_slice(&encrypted_payload[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let ciphertext = &encrypted_payload[SALT_LEN + NONCE_LEN..];

    // ২. একই মাস্টার পাসওয়ার্ড ও Salt দিয়ে কি রিকনস্ট্রাক্ট করা
    let mut key_bytes = derive_key_secret(master_password, salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    // ৩. ডিক্রিপ্ট করা
    let result = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed! Wrong password or corrupted file.".to_string());

    // মেমোরি সিকিউরিটি: মেমোরি থেকে কি মুছে ফেলা — the error path included
    // (`?` used to return above this line, leaving the derived key in the heap).
    key_bytes.zeroize();

    result
}

/// Legacy `&str` entrypoint — prefer [`decrypt_vault_secret`].
/// (Compat tests only — see [`derive_key`].)
#[deprecated(note = "use decrypt_vault_secret with a SecretString")]
pub fn decrypt_vault(master_password: &str, encrypted_payload: &[u8]) -> Result<Vec<u8>, String> {
    decrypt_vault_secret(&SecretString::new(master_password.to_string()), encrypted_payload)
}

/// A11: seal arbitrary bytes with a raw 32-byte key. Returns
/// `nonce (24) || ciphertext+tag`, the same primitive used for the vault DK.
pub fn seal_with_raw_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let (nonce, ct) = wrap_with_key(key, plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// A11: open bytes sealed by [`seal_with_raw_key`]. A wrong key or a tampered
/// blob fails the AEAD tag.
pub fn open_with_raw_key(key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() < NONCE_LEN {
        return Err("cache payload is truncated".to_string());
    }
    let (nonce, ct) = payload.split_at(NONCE_LEN);
    unwrap_with_key(key, nonce, ct)
}

/// Phase 17: wrap arbitrary bytes (the DK) with a raw 32B key + fresh nonce.
/// Returns (nonce, ciphertext+tag). Caller packs both into the container.
fn wrap_with_key(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>), String> {
    wrap_with_key_aad(key_bytes, &[], plaintext)
}

/// A-03: same as [`wrap_with_key`], with associated data. Every header byte
/// that precedes the wrapped blob is passed as `aad`, so moving the blob into
/// another container (or editing the salt/mode/magic) fails the tag.
fn wrap_with_key_aad(
    key_bytes: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), String> {
    use chacha20poly1305::aead::Payload;
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&nonce);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|e| format!("Wrap error: {}", e))?;
    Ok((nonce_bytes, ct))
}

/// Phase 17: unwrap bytes sealed by [`wrap_with_key`].
/// Wrong password ⇒ Argon2 mismatch ⇒ tag failure here (fast, before any KEM work).
fn unwrap_with_key(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    if nonce_bytes.len() != NONCE_LEN {
        return Err("Invalid wrap nonce".to_string());
    }
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed! Wrong password or corrupted file.".to_string())
}

/// A-03: [`unwrap_with_key`] counterpart that also authenticates `aad`.
fn open_with_aad(
    key_bytes: &[u8; 32],
    aad: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::Payload;
    if nonce_bytes.len() != NONCE_LEN {
        return Err("Invalid wrap nonce".to_string());
    }
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| "Decryption failed! Wrong password or corrupted file.".to_string())
}

/// Phase 14 (legacy): hybrid decryption of a 3-byte-magic v2 payload.
/// Kept ONLY for opening already-migrated vaults; new saves never use it.
/// Secret-owning variant — see [`derive_key_secret`].
pub fn decrypt_vault_hybrid_legacy_secret(
    master_password: &SecretString,
    payload: &[u8],
    decapsulation_key: &[u8],
) -> Result<Vec<u8>, String> {
    let min = 3 + SALT_LEN + CT_LEN + NONCE_LEN;
    if payload.len() < min {
        return Err("Invalid payload: data is too short!".to_string());
    }
    let salt = &payload[3..3 + SALT_LEN];
    let pq_ct = &payload[3 + SALT_LEN..3 + SALT_LEN + CT_LEN];
    let nonce = XNonce::from_slice(&payload[3 + SALT_LEN + CT_LEN..3 + SALT_LEN + CT_LEN + NONCE_LEN]);
    let ciphertext = &payload[3 + SALT_LEN + CT_LEN + NONCE_LEN..];

    let mut argon2_key = derive_key_secret(master_password, salt)?;
    // `?` here would drop the plain `[u8; 32]` un-zeroized; `pq_secret` is
    // ZeroizeOnDrop, the Argon2 key is not.
    let pq_secret = match PqHybridEngine::decapsulate(decapsulation_key, pq_ct) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("PQ decapsulate: {e}"));
        }
    };
    let hybrid = match PqHybridEngine::combine(&argon2_key, &pq_secret) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("Hybrid combine: {e}"));
        }
    };
    argon2_key.zeroize();
    drop(pq_secret);

    let key = Key::from_slice(hybrid.expose());
    let cipher = XChaCha20Poly1305::new(key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed! Wrong password or corrupted file.".to_string())?;
    Ok(plaintext)
}

/// Legacy `&str` entrypoint — prefer [`decrypt_vault_hybrid_legacy_secret`].
/// (Compat tests only — see [`derive_key`].)
#[deprecated(note = "use decrypt_vault_hybrid_legacy_secret with a SecretString")]
pub fn decrypt_vault_hybrid_legacy(
    master_password: &str,
    payload: &[u8],
    decapsulation_key: &[u8],
) -> Result<Vec<u8>, String> {
    decrypt_vault_hybrid_legacy_secret(
        &SecretString::new(master_password.to_string()),
        payload,
        decapsulation_key,
    )
}

/// A-03: portable hybrid container with an AAD-bound header.
/// Layout: `[PV4\0 4B] + [mode 1B] + [salt 16B] + [wrap_nonce 24B]
/// + [wrapped_dk 2416B] + [kem_ct 1088B] + [payload_nonce 24B] + [ct+tag]`.
///
/// Fresh ML-KEM keypair per save; the DK travels INSIDE the container,
/// sealed by the Argon2id key — no machine-bound sidecar needed.
///
/// H5 NOTE (honest scope): the DK is wrapped under the Argon2id key, so the
/// chain argon2_key ⇒ dk ⇒ pq_secret ⇒ hybrid means a guessed master
/// password yields the full key without touching ML-KEM. The PQ layer is a
/// key-rotation / harvest-now-decrypt-later hedge on the container key, NOT
/// a second factor. A machine-bound DPAPI pepper was deliberately NOT mixed
/// into this portable container (it would brick cross-device sync); Argon2id
/// stays at 64 MiB/t=3/p=4 for unlock-latency + test-suite reasons — a param
/// bump needs container versioning and is tracked separately.
///
/// The DK wrap authenticates `magic|mode|salt`; the payload authenticates every
/// header byte that precedes its nonce. A flipped magic, a swapped mode byte or
/// a blob lifted from another container therefore fails the tag instead of
/// silently changing what the file means. Nonces are bound implicitly (they key
/// the tag), so they are not repeated inside the AAD.
///
/// Secret-owning variant — see [`derive_key_secret`].
pub fn encrypt_vault_portable_secret(
    master_password: &SecretString,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::core::pq_hybrid::PqHybridEngine as PQ;
    use chacha20poly1305::aead::Payload;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut argon2_key = derive_key_secret(master_password, &salt)?;

    // Fresh PQ keypair every save (per-save forward secrecy on the PQ half).
    let kp = PQ::generate_keypair();
    let (pq_ct, pq_secret) = match PQ::encapsulate(&kp.encapsulation) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("PQ encapsulate: {e}"));
        }
    };
    if pq_ct.len() != CT_LEN {
        argon2_key.zeroize();
        return Err("PQ ciphertext malformed".to_string());
    }
    let hybrid = match PQ::combine(&argon2_key, &pq_secret) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("Hybrid combine: {e}"));
        }
    };
    drop(pq_secret);

    // A-03: the prefix the wrapped DK lives in, authenticated as AAD.
    let mut prefix = Vec::with_capacity(V4_PREFIX_LEN + SALT_LEN);
    prefix.extend_from_slice(V4_MAGIC);
    prefix.push(V4_MODE_PORTABLE);
    prefix.extend_from_slice(&salt);

    let (wrap_nonce, wrapped_dk) =
        match wrap_with_key_aad(&argon2_key, &prefix, kp.decapsulation.expose()) {
            Ok(v) => v,
            Err(e) => {
                argon2_key.zeroize();
                return Err(e);
            }
        };
    if wrapped_dk.len() != WRAPPED_DK_LEN {
        argon2_key.zeroize();
        return Err("Wrapped DK malformed".to_string());
    }
    drop(kp);
    argon2_key.zeroize();

    // Every header byte the payload must be bound to.
    let mut header =
        Vec::with_capacity(V4_PREFIX_LEN + SALT_LEN + NONCE_LEN + WRAPPED_DK_LEN + CT_LEN);
    header.extend_from_slice(&prefix);
    header.extend_from_slice(&wrap_nonce);
    header.extend_from_slice(&wrapped_dk);
    header.extend_from_slice(&pq_ct);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(hybrid.expose()));
    let payload_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let sealed = cipher.encrypt(&payload_nonce, Payload { msg: plaintext, aad: &header });
    drop(hybrid);
    let ciphertext = sealed.map_err(|e| format!("Encryption error: {}", e))?;

    let mut out = header;
    out.extend_from_slice(&payload_nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Phase 17 legacy writer: a `PV2\0` container with no AAD. Kept so the
/// migration tests can still produce the old shape and prove v4 reads both.
/// Production code writes [`encrypt_vault_portable_secret`] (v4) only.
/// Secret-owning variant — see [`derive_key_secret`].
#[allow(dead_code)] // only the compat/migration tests call it
pub fn encrypt_vault_portable_v2_secret(
    master_password: &SecretString,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::core::pq_hybrid::PqHybridEngine as PQ;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut argon2_key = derive_key_secret(master_password, &salt)?;

    // Fresh PQ keypair every save (per-save forward secrecy on the PQ half).
    let kp = PQ::generate_keypair();
    let (pq_ct, pq_secret) = match PQ::encapsulate(&kp.encapsulation) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("PQ encapsulate: {e}"));
        }
    };
    if pq_ct.len() != CT_LEN {
        argon2_key.zeroize();
        return Err("PQ ciphertext malformed".to_string());
    }
    let hybrid = match PQ::combine(&argon2_key, &pq_secret) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("Hybrid combine: {e}"));
        }
    };
    drop(pq_secret);

    // Seal the DK with the password-derived key (this is what travels).
    let (wrap_nonce, wrapped_dk) = match wrap_with_key(&argon2_key, kp.decapsulation.expose()) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(e);
        }
    };
    if wrapped_dk.len() != WRAPPED_DK_LEN {
        argon2_key.zeroize();
        return Err("Wrapped DK malformed".to_string());
    }
    drop(kp);
    argon2_key.zeroize();

    let key = Key::from_slice(hybrid.expose());
    let cipher = XChaCha20Poly1305::new(key);
    let payload_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&payload_nonce, plaintext)
        .map_err(|e| format!("Encryption error: {}", e))?;
    drop(hybrid);

    let mut out = Vec::with_capacity(
        4 + SALT_LEN + NONCE_LEN + WRAPPED_DK_LEN + CT_LEN + NONCE_LEN + ciphertext.len(),
    );
    out.extend_from_slice(V2_PORTABLE_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&wrap_nonce);
    out.extend_from_slice(&wrapped_dk);
    out.extend_from_slice(&pq_ct);
    out.extend_from_slice(&payload_nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Legacy `&str` entrypoint — prefer [`encrypt_vault_portable_secret`].
/// (Compat tests only — see [`derive_key`].) This one writes the pre-A-03
/// `PV2\0` shape, so the legacy read path keeps its own coverage.
#[deprecated(note = "use encrypt_vault_portable_secret with a SecretString")]
pub fn encrypt_vault_portable(
    master_password: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    encrypt_vault_portable_v2_secret(&SecretString::new(master_password.to_string()), plaintext)
}

/// Phase 17: portable hybrid decryption. Password failures surface at the
/// DK-unwrap step, before any lattice math runs.
/// Secret-owning variant — see [`derive_key_secret`].
pub fn decrypt_vault_portable_secret(
    master_password: &SecretString,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::core::pq_hybrid::PqHybridEngine as PQ;

    let min = 4 + SALT_LEN + NONCE_LEN + WRAPPED_DK_LEN + CT_LEN + NONCE_LEN;
    if payload.len() < min {
        return Err("Invalid payload: data is too short!".to_string());
    }
    let mut off = 4;
    let salt = &payload[off..off + SALT_LEN];
    off += SALT_LEN;
    let wrap_nonce = &payload[off..off + NONCE_LEN];
    off += NONCE_LEN;
    let wrapped_dk = &payload[off..off + WRAPPED_DK_LEN];
    off += WRAPPED_DK_LEN;
    let pq_ct = &payload[off..off + CT_LEN];
    off += CT_LEN;
    let payload_nonce = XNonce::from_slice(&payload[off..off + NONCE_LEN]);
    off += NONCE_LEN;
    let ciphertext = &payload[off..];

    let mut argon2_key = derive_key_secret(master_password, salt)?;
    let dk_bytes = match unwrap_with_key(&argon2_key, wrap_nonce, wrapped_dk) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(e);
        }
    };
    // H6: the 2400B decapsulation key must zeroize on EVERY path, including
    // the decapsulate-failure early return (corrupt/tampered pq_ct).
    let dk_guard = crate::core::pq_hybrid::PqDecapsulationBytes(dk_bytes);
    let pq_secret = match PQ::decapsulate(dk_guard.expose(), pq_ct) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("PQ decapsulate: {e}"));
        }
    };
    drop(dk_guard);
    let hybrid = match PQ::combine(&argon2_key, &pq_secret) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("Hybrid combine: {e}"));
        }
    };
    argon2_key.zeroize();
    drop(pq_secret);

    let key = Key::from_slice(hybrid.expose());
    let cipher = XChaCha20Poly1305::new(key);
    let plaintext = cipher
        .decrypt(payload_nonce, ciphertext)
        .map_err(|_| "Decryption failed! Wrong password or corrupted file.".to_string())?;
    drop(hybrid);
    Ok(plaintext)
}

/// A-03: open a portable container of either generation. Production loads
/// dispatch on [`detect_version`] themselves; this helper exists for callers
/// that hold bytes of unknown age (tests, migration proofs).
pub fn decrypt_vault_portable_any_secret(
    master_password: &SecretString,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if detect_version(payload) == VaultVersion::V4Portable {
        decrypt_vault_portable_v4_secret(master_password, payload)
    } else {
        decrypt_vault_portable_secret(master_password, payload)
    }
}

/// Legacy `&str` entrypoint — prefer [`decrypt_vault_portable_secret`].
/// (Compat tests only — see [`derive_key`].)
#[deprecated(note = "use decrypt_vault_portable_secret with a SecretString")]
pub fn decrypt_vault_portable(
    master_password: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    decrypt_vault_portable_any_secret(&SecretString::new(master_password.to_string()), payload)
}

/// A-03: open a `PV4\0` portable container. Every header byte before the payload
/// nonce is reconstructed from the file itself and re-supplied as AAD, so any
/// edit to the magic, the mode byte, the salt, the wrap nonce, the wrapped DK or
/// the KEM ciphertext fails the tag instead of changing the meaning.
/// Secret-owning variant — see [`derive_key_secret`].
pub fn decrypt_vault_portable_v4_secret(
    master_password: &SecretString,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::core::pq_hybrid::PqHybridEngine as PQ;

    let min = V4_PREFIX_LEN + SALT_LEN + NONCE_LEN + WRAPPED_DK_LEN + CT_LEN + NONCE_LEN;
    if payload.len() < min {
        return Err("Invalid payload: data is too short!".to_string());
    }
    if &payload[..4] != V4_MAGIC || payload[4] != V4_MODE_PORTABLE {
        return Err("Not a portable v4 container.".to_string());
    }
    let mut off = V4_PREFIX_LEN;
    let salt = &payload[off..off + SALT_LEN];
    off += SALT_LEN;
    let wrap_nonce = &payload[off..off + NONCE_LEN];
    off += NONCE_LEN;
    let wrapped_dk = &payload[off..off + WRAPPED_DK_LEN];
    off += WRAPPED_DK_LEN;
    let pq_ct = &payload[off..off + CT_LEN];
    off += CT_LEN;
    // Everything up to here is the payload's AAD; `off` is also the payload
    // nonce offset, so the header is exactly `payload[..off]`.
    let header = &payload[..off];
    let payload_nonce = XNonce::from_slice(&payload[off..off + NONCE_LEN]);
    off += NONCE_LEN;
    let ciphertext = &payload[off..];

    let mut argon2_key = derive_key_secret(master_password, salt)?;
    // The wrap authenticates magic|mode|salt only.
    let dk_bytes = match open_with_aad(&argon2_key, &payload[..V4_PREFIX_LEN + SALT_LEN], wrap_nonce, wrapped_dk) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(e);
        }
    };
    // H6: the 2400B decapsulation key must zeroize on EVERY path.
    let dk_guard = crate::core::pq_hybrid::PqDecapsulationBytes(dk_bytes);
    let pq_secret = match PQ::decapsulate(dk_guard.expose(), pq_ct) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("PQ decapsulate: {e}"));
        }
    };
    drop(dk_guard);
    let hybrid = match PQ::combine(&argon2_key, &pq_secret) {
        Ok(v) => v,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("Hybrid combine: {e}"));
        }
    };
    argon2_key.zeroize();
    drop(pq_secret);

    use chacha20poly1305::aead::Payload;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(hybrid.expose()));
    let opened = cipher.decrypt(payload_nonce, Payload { msg: ciphertext, aad: header });
    drop(hybrid);
    opened.map_err(|_| "Decryption failed! Wrong password or corrupted file.".to_string())
}

/// A22: hybrid key for the paranoid profile.
/// `HKDF-SHA256(salt = PQ shared secret, ikm = Argon2id key)` with a
/// profile-specific info string. Both halves are mandatory: a password guess
/// without the device key cannot decapsulate, and the device key alone cannot
/// reproduce the Argon2id half.
fn combine_paranoid(argon2_key: &[u8; 32], pq: &PqSharedSecret) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(Some(pq.expose()), argon2_key);
    let mut okm = [0u8; 32];
    hk.expand(PARANOID_INFO, &mut okm)
        .map_err(|_| "HKDF expansion failed".to_string())?;
    Ok(okm)
}

fn encrypt_paranoid_with_argon(
    argon2_key: &[u8; 32],
    salt: &[u8],
    encapsulation_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::core::pq_hybrid::PqHybridEngine as PQ;
    use chacha20poly1305::aead::Payload;

    let (pq_ct, pq_secret) =
        PQ::encapsulate(encapsulation_key).map_err(|e| format!("PQ encapsulate: {e}"))?;
    if pq_ct.len() != CT_LEN {
        return Err("PQ ciphertext malformed".to_string());
    }
    let mut hybrid = combine_paranoid(argon2_key, &pq_secret)?;
    drop(pq_secret);

    // A-03: the whole header is the payload's AAD.
    let mut header = Vec::with_capacity(V4_PREFIX_LEN + SALT_LEN + CT_LEN);
    header.extend_from_slice(V4_MAGIC);
    header.push(V4_MODE_PARANOID);
    header.extend_from_slice(salt);
    header.extend_from_slice(&pq_ct);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&hybrid));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, Payload { msg: plaintext, aad: &header });
    hybrid.zeroize();
    let ciphertext = encrypted.map_err(|e| format!("Encryption error: {e}"))?;

    let mut out = header;
    out.reserve(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// A22 + A-03: PQ-paranoid encryption.
///
/// Layout: `[PV4\0 4B]`, `[mode 1B]`, `[salt 16B]`, `[kem_ct 1088B]`,
/// `[nonce 24B]`, `[ct+tag]`. The whole header is the payload's AAD, so a
/// flipped mode byte or a swapped KEM ciphertext fails the tag.
///
/// The decapsulation key stays in the DPAPI sidecar; only the encapsulated
/// ciphertext travels. A fresh salt + fresh encapsulation are used per save.
pub fn encrypt_vault_paranoid_secret(
    master_password: &SecretString,
    encapsulation_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut argon2_key = derive_key_secret(master_password, &salt)?;
    let result = encrypt_paranoid_with_argon(&argon2_key, &salt, encapsulation_key, plaintext);
    argon2_key.zeroize();
    result
}

/// A22 PQ-paranoid decryption. Fails closed if the container is not `PV3\0`,
/// if the device key does not decapsulate the stored ciphertext, or if the
/// AEAD tag does not verify. Never falls back to the portable path.
pub fn decrypt_vault_paranoid_secret(
    master_password: &SecretString,
    decapsulation: &PqDecapsulationBytes,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::core::pq_hybrid::PqHybridEngine as PQ;

    let min = 4 + SALT_LEN + CT_LEN + NONCE_LEN;
    if payload.len() < min {
        return Err("Invalid payload: data is too short!".to_string());
    }
    if &payload[..4] != V3_PARANOID_MAGIC {
        return Err("Not a PQ-paranoid container.".to_string());
    }
    let salt = &payload[4..4 + SALT_LEN];
    let pq_ct = &payload[4 + SALT_LEN..4 + SALT_LEN + CT_LEN];
    let nonce = XNonce::from_slice(&payload[4 + SALT_LEN + CT_LEN..min]);
    let ciphertext = &payload[min..];

    let mut argon2_key = derive_key_secret(master_password, salt)?;
    let pq_secret = match PQ::decapsulate(decapsulation.expose(), pq_ct) {
        Ok(s) => s,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("PQ decapsulate: {e}"));
        }
    };
    let mut hybrid = match combine_paranoid(&argon2_key, &pq_secret) {
        Ok(k) => k,
        Err(e) => {
            argon2_key.zeroize();
            return Err(e);
        }
    };
    argon2_key.zeroize();
    drop(pq_secret);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&hybrid));
    let result = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed! Wrong password, wrong device key, or corrupted file.".to_string());
    hybrid.zeroize();
    result
}

/// A-03: open a `PV4\0` paranoid container. The header before the nonce is the
/// AAD, so a flipped mode byte, a swapped salt or a lifted KEM ciphertext fails
/// the tag instead of being silently accepted.
pub fn decrypt_vault_paranoid_v4_secret(
    master_password: &SecretString,
    decapsulation: &PqDecapsulationBytes,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::core::pq_hybrid::PqHybridEngine as PQ;
    use chacha20poly1305::aead::Payload;

    let min = V4_PREFIX_LEN + SALT_LEN + CT_LEN + NONCE_LEN;
    if payload.len() < min {
        return Err("Invalid payload: data is too short!".to_string());
    }
    if &payload[..4] != V4_MAGIC || payload[4] != V4_MODE_PARANOID {
        return Err("Not a PQ-paranoid v4 container.".to_string());
    }
    let salt = &payload[V4_PREFIX_LEN..V4_PREFIX_LEN + SALT_LEN];
    let pq_ct = &payload[V4_PREFIX_LEN + SALT_LEN..V4_PREFIX_LEN + SALT_LEN + CT_LEN];
    // `min` is the payload-nonce offset, so the header is `payload[..min]`.
    let header = &payload[..min - NONCE_LEN];
    let nonce = XNonce::from_slice(&payload[min - NONCE_LEN..min]);
    let ciphertext = &payload[min..];

    let mut argon2_key = derive_key_secret(master_password, salt)?;
    let pq_secret = match PQ::decapsulate(decapsulation.expose(), pq_ct) {
        Ok(s) => s,
        Err(e) => {
            argon2_key.zeroize();
            return Err(format!("PQ decapsulate: {e}"));
        }
    };
    let mut hybrid = match combine_paranoid(&argon2_key, &pq_secret) {
        Ok(k) => k,
        Err(e) => {
            argon2_key.zeroize();
            return Err(e);
        }
    };
    argon2_key.zeroize();
    drop(pq_secret);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&hybrid));
    let result = cipher.decrypt(nonce, Payload { msg: ciphertext, aad: header });
    hybrid.zeroize();
    result.map_err(|_| {
        "Decryption failed! Wrong password, wrong device key, or corrupted file.".to_string()
    })
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_and_decryption_flow() {
        let master_pass = "SuperSecretPassword123!#";
        let original_data = b"My Google Password is: 123456789";

        // এনক্রিপ্ট করা হলো
        let encrypted = encrypt_vault(master_pass, original_data).expect("Encryption failed");

        // ডিক্রিপ্ট করা হলো
        let decrypted = decrypt_vault(master_pass, &encrypted).expect("Decryption failed");

        assert_eq!(original_data, decrypted.as_slice());

        // ভুল পাসওয়ার্ড দিয়ে টেস্ট (ফেল মারতে হবে)
        let wrong_pass = "WrongPassword999";
        assert!(decrypt_vault(wrong_pass, &encrypted).is_err());
    }

    #[test]
    fn secret_variants_match_legacy_paths_both_directions() {
        let pw = SecretString::new("Phase1-Secret-Path!".to_string());
        let data = b"scope-check payload";
        // Secret encrypt → legacy (&str) decrypt.
        let enc = encrypt_vault_secret(&pw, data).expect("secret encrypt");
        let dec = decrypt_vault("Phase1-Secret-Path!", &enc).expect("legacy decrypt");
        assert_eq!(data, dec.as_slice());
        // Legacy encrypt → secret decrypt.
        let enc2 = encrypt_vault("Phase1-Secret-Path!", data).expect("legacy encrypt");
        let dec2 = decrypt_vault_secret(&pw, &enc2).expect("secret decrypt");
        assert_eq!(data, dec2.as_slice());
        // Portable pair, same cross-check.
        let penc = encrypt_vault_portable_secret(&pw, data).expect("secret portable encrypt");
        let pdec = decrypt_vault_portable("Phase1-Secret-Path!", &penc).expect("legacy portable decrypt");
        assert_eq!(data, pdec.as_slice());
        // KDF parity: same password + salt ⇒ same key on both paths.
        let salt = [7u8; SALT_LEN];
        assert_eq!(
            derive_key_secret(&pw, &salt).expect("secret kdf"),
            derive_key("Phase1-Secret-Path!", &salt).expect("legacy kdf")
        );
    }

    #[test]
    fn test_portable_roundtrip_and_version() {
        let master_pass = "HybridMaster!2026";
        let data = b"pq protected vault bytes";
        let enc = encrypt_vault_portable(master_pass, data).expect("portable encrypt");
        assert_eq!(detect_version(&enc), super::VaultVersion::V2Portable);
        // Self-contained: decrypts with password alone, no sidecar.
        let dec = decrypt_vault_portable(master_pass, &enc).expect("portable decrypt");
        assert_eq!(data, dec.as_slice());
        assert!(decrypt_vault_portable("wrong-password!", &enc).is_err());
    }

    #[test]
    fn test_v1_detected_as_classical() {
        let enc = encrypt_vault("pw12345678", b"hello").expect("v1 encrypt");
        assert_eq!(detect_version(&enc), super::VaultVersion::V1Classical);
    }

    #[test]
    fn a03_v4_portable_binds_every_header_region() {
        let pw = SecretString::new("AadMaster!2026".to_string());
        let data = b"aad bound vault bytes";
        let enc = encrypt_vault_portable_secret(&pw, data).expect("v4 encrypt");
        assert_eq!(detect_version(&enc), super::VaultVersion::V4Portable);
        assert_eq!(
            decrypt_vault_portable_v4_secret(&pw, &enc).expect("v4 decrypt"),
            data
        );

        // One byte per header region: magic, mode, salt, wrap nonce, wrapped DK,
        // KEM ciphertext. Each edit must fail the tag (or the magic/mode check)
        // instead of silently changing what the file means.
        let header_end = V4_PREFIX_LEN + SALT_LEN + NONCE_LEN + WRAPPED_DK_LEN + CT_LEN;
        let probes = [0usize, 4, V4_PREFIX_LEN, V4_PREFIX_LEN + SALT_LEN, 45, header_end - 1];
        for off in probes {
            let mut bad = enc.clone();
            bad[off] ^= 0x01;
            assert!(
                decrypt_vault_portable_v4_secret(&pw, &bad).is_err(),
                "header byte {off} is not authenticated"
            );
        }

        // A swapped mode byte is a different profile, never a portable file.
        let mut relabelled = enc.clone();
        relabelled[4] = V4_MODE_PARANOID;
        assert_eq!(detect_version(&relabelled), super::VaultVersion::V4Paranoid);
        assert!(decrypt_vault_portable_v4_secret(&pw, &relabelled).is_err());
    }

    #[test]
    fn a03_v2_container_still_opens_and_is_never_read_as_v4() {
        let pw = SecretString::new("AadMaster!2026".to_string());
        let data = b"pre-aad bytes";
        let old = encrypt_vault_portable_v2_secret(&pw, data).expect("v2 encrypt");
        assert_eq!(detect_version(&old), super::VaultVersion::V2Portable);
        assert_eq!(
            decrypt_vault_portable_secret(&pw, &old).expect("legacy open"),
            data
        );
        // The v4 reader refuses a v2 file instead of guessing at its layout.
        assert!(decrypt_vault_portable_v4_secret(&pw, &old).is_err());
    }

    #[test]
    fn a03_v4_paranoid_binds_its_header() {
        let kp = PqHybridEngine::generate_keypair();
        let pw = SecretString::new("ParanoidAad!2026".to_string());
        let data = b"aad bound paranoid bytes";
        let enc = encrypt_vault_paranoid_secret(&pw, &kp.encapsulation, data).expect("encrypt");
        assert_eq!(detect_version(&enc), super::VaultVersion::V4Paranoid);
        assert_eq!(
            decrypt_vault_paranoid_v4_secret(&pw, &kp.decapsulation, &enc).expect("decrypt"),
            data
        );
        for off in [0usize, 4, V4_PREFIX_LEN, V4_PREFIX_LEN + SALT_LEN] {
            let mut bad = enc.clone();
            bad[off] ^= 0x01;
            assert!(
                decrypt_vault_paranoid_v4_secret(&pw, &kp.decapsulation, &bad).is_err(),
                "header byte {off} is not authenticated"
            );
        }
    }

    #[test]
    fn test_legacy_v2_still_opens() {
        // Hand-build a Phase-14 (3-byte magic) container: the loader must
        // keep opening already-migrated vaults with the DPAPI-sidecar key.
        use crate::core::pq_hybrid::PqHybridEngine;
        let kp = PqHybridEngine::generate_keypair();
        let master_pass = "LegacyMaster!2026";
        let data = b"legacy hybrid bytes";
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let argon2_key = derive_key(master_pass, &salt).expect("kdf");
        let (pq_ct, pq_secret) = PqHybridEngine::encapsulate(&kp.encapsulation).expect("encap");
        let hybrid = PqHybridEngine::combine(&argon2_key, &pq_secret).expect("combine");
        let key = Key::from_slice(hybrid.expose());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher.encrypt(&nonce, data.as_slice()).expect("enc");
        let mut payload = Vec::new();
        payload.extend_from_slice(V2_MAGIC);
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&pq_ct);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ct);
        assert_eq!(detect_version(&payload), super::VaultVersion::V2Legacy);
        let dec = decrypt_vault_hybrid_legacy(master_pass, &payload, kp.decapsulation.expose())
            .expect("legacy decrypt");
        assert_eq!(data, dec.as_slice());
    }

    #[test]
    fn paranoid_roundtrip_needs_password_and_device_key() {
        let kp = PqHybridEngine::generate_keypair();
        let pw = SecretString::new("ParanoidMaster!2026".to_string());
        let data = b"paranoid payload";

        let enc = encrypt_vault_paranoid_secret(&pw, &kp.encapsulation, data).expect("encrypt");
        assert_eq!(detect_version(&enc), super::VaultVersion::V4Paranoid);
        let dec = decrypt_vault_paranoid_v4_secret(&pw, &kp.decapsulation, &enc).expect("decrypt");
        assert_eq!(dec, data);

        // The password alone is not an API: without the matching device key the
        // decapsulated secret differs and the AEAD tag fails.
        let other = PqHybridEngine::generate_keypair();
        assert!(decrypt_vault_paranoid_v4_secret(&pw, &other.decapsulation, &enc).is_err());

        // Even with the device key, a wrong password fails.
        let bad = SecretString::new("wrong-password".to_string());
        assert!(decrypt_vault_paranoid_v4_secret(&bad, &kp.decapsulation, &enc).is_err());

        // Tampering / truncation / a portable container all fail closed.
        let mut tampered = enc.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt_vault_paranoid_v4_secret(&pw, &kp.decapsulation, &tampered).is_err());
        assert!(decrypt_vault_paranoid_v4_secret(&pw, &kp.decapsulation, &enc[..20]).is_err());
        let portable = encrypt_vault_portable_secret(&pw, b"x").expect("portable");
        assert!(decrypt_vault_paranoid_v4_secret(&pw, &kp.decapsulation, &portable).is_err());
    }
}
