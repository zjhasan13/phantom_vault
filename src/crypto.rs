use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::RngCore;
use zeroize::Zeroize;

// Salt সাইজ (16 bytes) এবং Nonce সাইজ (24 bytes for XChaCha20)
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

/// মাস্টার পাসওয়ার্ড এবং Salt থেকে Argon2id ব্যবহার করে ৩২ বাইটের কি (Key) ডেরাইভ করা
pub fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut derived_key = [0u8; 32];

    // মেমোরি-হার্ড প্যারামিটার (OWASP স্ট্যান্ডার্ড: 64MB RAM, 3 Iterations, 4 Parallel threads)
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut derived_key)
        .map_err(|e| format!("Key derivation error: {}", e))?;

    Ok(derived_key)
}

/// XChaCha20-Poly1305 দিয়ে প্লেইনটেক্সট এনক্রিপ্ট করা
/// রিটার্ন করবে: [16 bytes Salt] + [24 bytes Nonce] + [Ciphertext + Auth Tag]
pub fn encrypt_vault(master_password: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    // ১. ১৬ বাইটের ক্রিপ্টোগ্রাফিক ট্রু র‍্যান্ডম Salt জেনারেট করা
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // ২. কি (Key) তৈরি করা
    let mut key_bytes = derive_key(master_password, &salt)?;
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

/// এনক্রিপ্ট করা পেলোড থেকে ডিক্রিপ্ট করে আসল ডাটা বের করা
pub fn decrypt_vault(master_password: &str, encrypted_payload: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted_payload.len() < SALT_LEN + NONCE_LEN {
        return Err("Invalid payload: data is too short!".to_string());
    }

    // ১. Salt ও Nonce আলাদা করে নেওয়া
    let salt = &encrypted_payload[..SALT_LEN];
    let nonce = XNonce::from_slice(&encrypted_payload[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let ciphertext = &encrypted_payload[SALT_LEN + NONCE_LEN..];

    // ২. একই মাস্টার পাসওয়ার্ড ও Salt দিয়ে কি রিকনস্ট্রাক্ট করা
    let mut key_bytes = derive_key(master_password, salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    // ৩. ডিক্রিপ্ট করা
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed! Wrong password or corrupted file.".to_string())?;

    // মেমোরি সিকিউরিটি: মেমোরি থেকে কি মুছে ফেলা
    key_bytes.zeroize();

    Ok(plaintext)
}

#[cfg(test)]
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
}