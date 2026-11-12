use crate::error::{Result, VaultError};
use windows::core::HSTRING;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};

pub enum BiometricAvailability {
    Available,
    DeviceNotPresent,
    NotConfiguredForUser,
    DisabledByPolicy,
    Unknown,
}

/// Pure mapping from the WinRT availability enum. Kept out of the async path so
/// the decision table is testable without a biometric device.
fn availability_from(result: UserConsentVerifierAvailability) -> BiometricAvailability {
    match result {
        UserConsentVerifierAvailability::Available => BiometricAvailability::Available,
        UserConsentVerifierAvailability::DeviceNotPresent => {
            BiometricAvailability::DeviceNotPresent
        }
        UserConsentVerifierAvailability::NotConfiguredForUser => {
            BiometricAvailability::NotConfiguredForUser
        }
        UserConsentVerifierAvailability::DisabledByPolicy => {
            BiometricAvailability::DisabledByPolicy
        }
        _ => BiometricAvailability::Unknown,
    }
}

/// Pure mapping for the consent result: Verified = true, Canceled/unknown =
/// false, everything else carries the user-facing reason.
fn verification_from(result: UserConsentVerificationResult) -> Result<bool> {
    match result {
        UserConsentVerificationResult::Verified => Ok(true),
        UserConsentVerificationResult::DeviceNotPresent => Err(VaultError::Biometric(
            "Biometric device not found".into(),
        )),
        UserConsentVerificationResult::NotConfiguredForUser => Err(VaultError::Biometric(
            "Windows Hello not configured for this user".into(),
        )),
        UserConsentVerificationResult::DisabledByPolicy => Err(VaultError::Biometric(
            "Biometrics disabled by Windows Group Policy".into(),
        )),
        UserConsentVerificationResult::DeviceBusy => {
            Err(VaultError::Biometric("Biometric sensor is busy".into()))
        }
        UserConsentVerificationResult::Canceled => Ok(false),
        _ => Ok(false),
    }
}

pub struct WindowsHello;

impl WindowsHello {
    /// Blocking WinRT check. Must be called from a background thread
    /// (via Tokio `spawn_blocking`), never from the Slint event loop.
    pub fn check_availability_blocking() -> Result<BiometricAvailability> {
        let op = UserConsentVerifier::CheckAvailabilityAsync()
            .map_err(|e| VaultError::Biometric(format!("CheckAvailabilityAsync failed: {e}")))?;
        let result = op
            .get()
            .map_err(|e| VaultError::Biometric(format!("CheckAvailability task failed: {e}")))?;

        Ok(availability_from(result))
    }

    /// Async wrapper: bridges the WinRT operation into the Tokio runtime
    /// via `spawn_blocking`, keeping the Slint UI thread free.
    pub async fn check_availability() -> Result<BiometricAvailability> {
        tokio::task::spawn_blocking(Self::check_availability_blocking)
            .await
            .map_err(|e| VaultError::Biometric(format!("availability task join failed: {e}")))?
    }

    /// Blocking WinRT consent prompt. Must be called from a background thread.
    /// Returns Ok(true) if verified, Ok(false) if canceled/retried, Err on failure.
    pub fn authenticate_blocking(prompt_message: &str) -> Result<bool> {
        let msg = HSTRING::from(prompt_message);
        let op = UserConsentVerifier::RequestVerificationAsync(&msg)
            .map_err(|e| VaultError::Biometric(format!("RequestVerificationAsync failed: {e}")))?;
        let result = op
            .get()
            .map_err(|e| VaultError::Biometric(format!("Verification task failed: {e}")))?;

        verification_from(result)
    }

    /// Async wrapper: bridges the WinRT consent UI into the Tokio runtime.
    pub async fn authenticate(prompt_message: &str) -> Result<bool> {
        let prompt = prompt_message.to_string();
        tokio::task::spawn_blocking(move || Self::authenticate_blocking(&prompt))
            .await
            .map_err(|e| VaultError::Biometric(format!("auth task join failed: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_maps_every_known_state() {
        assert!(matches!(
            availability_from(UserConsentVerifierAvailability::Available),
            BiometricAvailability::Available
        ));
        assert!(matches!(
            availability_from(UserConsentVerifierAvailability::DeviceNotPresent),
            BiometricAvailability::DeviceNotPresent
        ));
        assert!(matches!(
            availability_from(UserConsentVerifierAvailability::NotConfiguredForUser),
            BiometricAvailability::NotConfiguredForUser
        ));
        assert!(matches!(
            availability_from(UserConsentVerifierAvailability::DisabledByPolicy),
            BiometricAvailability::DisabledByPolicy
        ));
    }

    #[test]
    fn verification_maps_verified_canceled_and_failures() {
        assert!(matches!(
            verification_from(UserConsentVerificationResult::Verified),
            Ok(true)
        ));
        assert!(matches!(
            verification_from(UserConsentVerificationResult::Canceled),
            Ok(false)
        ));
        let busy = verification_from(UserConsentVerificationResult::DeviceBusy);
        assert!(busy.is_err(), "a busy sensor is an error, never a silent pass");
        let policy = verification_from(UserConsentVerificationResult::DisabledByPolicy);
        assert!(policy.is_err());
    }
}