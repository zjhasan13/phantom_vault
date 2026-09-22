use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// পাসওয়ার্ড ও লগইন আইটেম
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Credential {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

/// 2FA অথেনটিকেটর অ্যাকাউন্ট (Google/Proton TOTP)
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TotpAccount {
    pub id: String,
    pub account_name: String,
    pub issuer: String,
    pub secret: String, // Base32 Secret Key
    pub digits: u32,    // 6 or 8 digits
    pub period: u64,    // Default 30s
}

/// সফটওয়্যার ও গেম লাইসেন্স কি
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SoftwareLicense {
    pub id: String,
    pub app_name: String,
    pub license_key: String,
    pub expiry_date: Option<String>,
}

/// সিকিউর নোটস
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecureNote {
    pub id: String,
    pub title: String,
    pub content: String,
}

/// সম্পূর্ণ মূল ভল্ট কন্টেইনার
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Vault {
    pub version: u32,
    pub credentials: Vec<Credential>,
    pub totp_accounts: Vec<TotpAccount>,
    pub licenses: Vec<SoftwareLicense>,
    pub notes: Vec<SecureNote>,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            version: 1,
            credentials: Vec::new(),
            totp_accounts: Vec::new(),
            licenses: Vec::new(),
            notes: Vec::new(),
        }
    }
}