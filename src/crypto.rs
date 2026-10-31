use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::RngCore;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

use crate::core::pq_hybrid::{PqHybridEngine, CT_LEN};

// Salt সাইজ (16 bytes) এবং Nonce সাইজ (24 bytes for XChaCha20)
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

/// Phase 14/17: versioned container magics.
/// - v1 (legacy classical): no magic, raw salt first.
/// - v2-legacy (Phase 14 hybrid, machine-bound DK): `PV2` (3 bytes).
/// - v2-portable (self-contained, key-wrapped DK): `PV2\0` (4 bytes).
pub const V2_MAGIC: &[u8; 3] = b"PV2";
pub const V2_PORTABLE_MAGIC: &[u8; 4] = b"PV2\x00";

/// Wrapped-DK blob length: DK (2400B) + Poly1305 tag (16B).
pub const WRAPPED_DK_LEN: usize = crate::core::pq_hybrid::DK_LEN + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultVersion {
    V1Classical,
    /// Phase-14 layout: needs the DPAPI `pq_decapsulation.dpapi` sidecar.
    V2Legacy,
    /// Self-contained portable layout: DK wrapped by the Argon2id key.
    V2Portable,
}

/// Detect container version by magic prefix (4-byte check first).
pub fn detect_version(payload: &[u8]) -> VaultVersion {
    if payload.len() >= 4 && &payload[..4] == V2_PORTABLE_MAGIC {
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
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("Encryption error: {}", e))?;

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
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&nonce);
    let ct = cipher
        .encrypt(&nonce, plaintext)
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
    let pq_secret = PqHybridEngine::decapsulate(decapsulation_key, pq_ct)
        .map_err(|e| format!("PQ decapsulate: {e}"))?;
    let hybrid = PqHybridEngine::combine(&argon2_key, &pq_secret)
        .map_err(|e| format!("Hybrid combine: {e}"))?;
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

/// Phase 17: portable self-contained hybrid encryption.
/// Layout: [PV2\0 4B] + [salt 16B] + [wrap_nonce 24B] + [wrapped_dk 2416B]
///       + [kem_ct 1088B] + [payload_nonce 24B] + [ct+tag].
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
/// Secret-owning variant — see [`derive_key_secret`].
pub fn encrypt_vault_portable_secret(
    master_password: &SecretString,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::core::pq_hybrid::PqHybridEngine as PQ;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut argon2_key = derive_key_secret(master_password, &salt)?;

    // Fresh PQ keypair every save (per-save forward secrecy on the PQ half).
    let kp = PQ::generate_keypair();
    let (pq_ct, pq_secret) = PQ::encapsulate(&kp.encapsulation)
        .map_err(|e| format!("PQ encapsulate: {e}"))?;
    if pq_ct.len() != CT_LEN {
        argon2_key.zeroize();
        return Err("PQ ciphertext malformed".to_string());
    }
    let hybrid = PQ::combine(&argon2_key, &pq_secret)
        .map_err(|e| format!("Hybrid combine: {e}"))?;
    drop(pq_secret);

    // Seal the DK with the password-derived key (this is what travels).
    let (wrap_nonce, wrapped_dk) = wrap_with_key(&argon2_key, kp.decapsulation.expose())?;
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
/// (Compat tests only — see [`derive_key`].)
#[deprecated(note = "use encrypt_vault_portable_secret with a SecretString")]
pub fn encrypt_vault_portable(
    master_password: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    encrypt_vault_portable_secret(&SecretString::new(master_password.to_string()), plaintext)
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
    let dk_bytes = unwrap_with_key(&argon2_key, wrap_nonce, wrapped_dk)?;
    // H6: the 2400B decapsulation key must zeroize on EVERY path, including
    // the decapsulate-failure early return (corrupt/tampered pq_ct).
    let dk_guard = crate::core::pq_hybrid::PqDecapsulationBytes(dk_bytes);
    let pq_secret = PQ::decapsulate(dk_guard.expose(), pq_ct)
        .map_err(|e| format!("PQ decapsulate: {e}"))?;
    drop(dk_guard);
    let hybrid = PQ::combine(&argon2_key, &pq_secret)
        .map_err(|e| format!("Hybrid combine: {e}"))?;
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

/// Legacy `&str` entrypoint — prefer [`decrypt_vault_portable_secret`].
/// (Compat tests only — see [`derive_key`].)
#[deprecated(note = "use decrypt_vault_portable_secret with a SecretString")]
pub fn decrypt_vault_portable(
    master_password: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    decrypt_vault_portable_secret(&SecretString::new(master_password.to_string()), payload)
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
}