use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};

/// একটি সিক্রেট কি (Secret Key) থেকে লাইভ ৬ ডিজিটের TOTP কোড এবং বাকি সময় বের করা
pub fn generate_live_code(secret_base32: &str) -> Result<(String, u64), String> {
    // স্পেস বা ড্যাশ থাকলে তা পরিষ্কার করে নেওয়া
    let clean_secret = secret_base32.replace([' ', '-'], "").to_uppercase();

    // Base32 সিক্রেট থেকে বাইট রিড করা
    let secret_bytes = Secret::Encoded(clean_secret)
        .to_bytes()
        .map_err(|e| format!("Invalid Base32 Secret: {:?}", e))?;

    // RFC 6238 কনফিগারেশন
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,  // ৬ ডিজিটের কোড
        1,  // Skew tolerance
        30, // ৩০ সেকেন্ডের পিরিয়ড
        secret_bytes,
    ).map_err(|e| format!("TOTP init error: {}", e))?;

    // বর্তমান ইউনিক্স টাইমস্ট্যাম্প
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_secs();

    // কোড এবং এক্সপায়ারি কাউন্টডাউন
    let code = totp.generate(current_time);
    let remaining_seconds = 30 - (current_time % 30);

    Ok((code, remaining_seconds))
}