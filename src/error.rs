use thiserror::Error;

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum VaultError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Generator invalid parameters: {0}")]
    GeneratorInvalidParams(String),
    #[error("Biometric error: {0}")]
    Biometric(String),
    #[error("Sync error: {0}")]
    Sync(String),
    #[error("Auto-Type error: {0}")]
    AutoType(String),
    #[error("Security violation: {0}")]
    Security(String),
}

/// A26/B2: Bengali wrapper for user-facing error toasts. Technical payloads
/// (serde/COM/OS text) stay as-is; the Auto-Type messages we own are mapped.
impl VaultError {
    pub fn localized(&self) -> String {
        if !crate::i18n::is_bn() {
            return self.to_string();
        }
        match self {
            VaultError::Crypto(m) => format!("ক্রিপ্টো ত্রুটি: {m}"),
            VaultError::Storage(m) => format!("স্টোরেজ ত্রুটি: {m}"),
            VaultError::GeneratorInvalidParams(m) => format!("জেনারেটরের প্যারামিটার ভুল: {m}"),
            VaultError::Biometric(m) => format!("বায়োমেট্রিক ত্রুটি: {m}"),
            VaultError::Sync(m) => format!("সিঙ্ক ত্রুটি: {m}"),
            VaultError::AutoType(m) => format!("Auto-Type ত্রুটি: {}", auto_type_bn(m)),
            VaultError::Security(m) => format!("নিরাপত্তা লঙ্ঘন: {m}"),
        }
    }
}

/// Known Auto-Type payload strings (we author these, so they can be mapped).
fn auto_type_bn(msg: &str) -> &str {
    match msg {
        "nothing to type" => "টাইপ করার কিছু নেই",
        "no foreground window - aborted" => "কোনো foreground উইন্ডো নেই — বাতিল",
        "focus moved mid-type - aborted for safety" => {
            "টাইপিংয়ের মাঝে focus সরে গেছে — নিরাপত্তার জন্য বাতিল"
        }
        "focus moved to another control - aborted for safety" => {
            "focus অন্য কন্ট্রোলে চলে গেছে — নিরাপত্তার জন্য বাতিল"
        }
        "password field is focused - focus the username field or bind this item to the app" => {
            "পাসওয়ার্ড ফিল্ডে focus আছে — ইউজারনেম ফিল্ডে focus করুন বা আইটেমটি অ্যাপে bind করুন"
        }
        "Tab did not reach a password field - aborted for safety" => {
            "Tab পাসওয়ার্ড ফিল্ডে পৌঁছায়নি — নিরাপত্তার জন্য বাতিল"
        }
        "typing aborted unexpectedly" => "টাইপিং অপ্রত্যাশিতভাবে বাতিল হয়েছে",
        _ => msg,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_type_payloads_have_bengali_mappings() {
        assert_eq!(auto_type_bn("nothing to type"), "টাইপ করার কিছু নেই");
        assert_eq!(
            auto_type_bn("focus moved mid-type - aborted for safety"),
            "টাইপিংয়ের মাঝে focus সরে গেছে — নিরাপত্তার জন্য বাতিল"
        );
        // Unknown payloads fall through unchanged (no fabricated translation).
        assert_eq!(auto_type_bn("COM custom text"), "COM custom text");
    }
}
