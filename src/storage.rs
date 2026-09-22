use crate::crypto::{decrypt_vault, encrypt_vault};
use crate::models::Vault;
use std::fs;
use std::path::Path;

/// ভল্ট ডাটাকে bincode দিয়ে সংকুচিত করে XChaCha20 দিয়ে এনক্রিপ্ট করে ফাইলে সেভ করা
pub fn save_vault<P: AsRef<Path>>(vault: &Vault, master_password: &str, file_path: P) -> Result<(), String> {
    // ১. বাইনারিতে সিরিয়ালাইজ করা (অতি ক্ষুদ্র সাইজ হবে)
    let serialized_bytes = bincode::serialize(vault)
        .map_err(|e| format!("Serialization error: {}", e))?;

    // ২. এনক্রিপ্ট করা
    let encrypted_payload = encrypt_vault(master_password, &serialized_bytes)?;

    // ৩. হার্ডডিস্কে সরাসরি বাইনারি ফাইল রাইট করা
    fs::write(file_path, encrypted_payload)
        .map_err(|e| format!("File write error: {}", e))?;

    Ok(())
}

/// হার্ডডিস্ক থেকে এনক্রিপ্ট করা ফাইল পড়ে ডিক্রিপ্ট করে ভল্ট মেমরিতে লোড করা
pub fn load_vault<P: AsRef<Path>>(master_password: &str, file_path: P) -> Result<Vault, String> {
    // ১. ডিস্ক থেকে বাইনারি পড়া
    let encrypted_payload = fs::read(file_path)
        .map_err(|e| format!("File read error: {}", e))?;

    // ২. ডিক্রিপ্ট করা
    let decrypted_bytes = decrypt_vault(master_password, &encrypted_payload)?;

    // ৩. ডিসিরিয়ালাইজ করে মেমরিতে স্ট্রাকচার বানিয়ে নেওয়া
    let vault: Vault = bincode::deserialize(&decrypted_bytes)
        .map_err(|e| format!("Deserialization error: {}", e))?;

    Ok(vault)
}