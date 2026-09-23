//! Phase 14 — Post-quantum hybrid key layer (NIST FIPS 203 ML-KEM-768).
//!
//! Design (corrected from the draft prompt):
//! - Verified against ml-kem 0.2.3 signatures: keygen goes through
//!   `KemCore::generate`, `from_bytes` is infallible (length-checked here),
//!   traits are `kem::{Encapsulate, Decapsulate}`.
//! - Canonical HKDF info string: `phantom_vault_hybrid_pq_v1` (single source).
//! - All shared secrets / decapsulation keys are zeroizing types.

use crate::error::{Result, VaultError};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::OsRng;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Single canonical HKDF info — both sides must agree bit-for-bit.
pub const HYBRID_INFO: &[u8] = b"phantom_vault_hybrid_pq_v1";

/// FIPS 203 ML-KEM-768 sizes.
pub const EK_LEN: usize = 1184;
pub const DK_LEN: usize = 2400;
pub const CT_LEN: usize = 1088;

/// Zeroizing ML-KEM shared secret (32 bytes).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PqSharedSecret([u8; 32]);

impl PqSharedSecret {
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Zeroizing hybrid AEAD key for XChaCha20-Poly1305.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridDerivedKey {
    key: [u8; 32],
}

impl HybridDerivedKey {
    pub fn expose(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Zeroizing decapsulation-key bytes for DPAPI custody.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PqDecapsulationBytes(pub Vec<u8>);

impl PqDecapsulationBytes {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

pub struct PqKeypair {
    pub encapsulation: Vec<u8>,
    pub decapsulation: PqDecapsulationBytes,
}

pub struct PqHybridEngine;

impl PqHybridEngine {
    /// Generate a fresh ML-KEM-768 keypair from OS entropy.
    pub fn generate_keypair() -> PqKeypair {
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let encapsulation = ek.as_bytes().to_vec();
        let decapsulation = PqDecapsulationBytes(dk.as_bytes().to_vec());
        PqKeypair {
            encapsulation,
            decapsulation,
        }
    }

    fn ek_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768Params>> {
        if bytes.len() != EK_LEN {
            return Err(VaultError::Crypto("bad PQ encapsulation key length".into()));
        }
        let raw: [u8; EK_LEN] = bytes
            .try_into()
            .map_err(|_| VaultError::Crypto("bad PQ encapsulation key".into()))?;
        let arr: Encoded<EncapsulationKey<MlKem768Params>> = raw.into();
        Ok(EncapsulationKey::from_bytes(&arr))
    }

    fn dk_from_bytes(bytes: &[u8]) -> Result<DecapsulationKey<MlKem768Params>> {
        if bytes.len() != DK_LEN {
            return Err(VaultError::Crypto("bad PQ decapsulation key length".into()));
        }
        let raw: [u8; DK_LEN] = bytes
            .try_into()
            .map_err(|_| VaultError::Crypto("bad PQ decapsulation key".into()))?;
        let arr: Encoded<DecapsulationKey<MlKem768Params>> = raw.into();
        Ok(DecapsulationKey::from_bytes(&arr))
    }

    fn ct_from_bytes(bytes: &[u8]) -> Result<Ciphertext<MlKem768>> {
        if bytes.len() != CT_LEN {
            return Err(VaultError::Crypto("bad PQ ciphertext length".into()));
        }
        let raw: [u8; CT_LEN] = bytes
            .try_into()
            .map_err(|_| VaultError::Crypto("bad PQ ciphertext".into()))?;
        Ok(raw.into())
    }

    fn secret_from_array(arr: ml_kem::SharedKey<MlKem768>) -> Result<PqSharedSecret> {
        let mut ss = [0u8; 32];
        ss.copy_from_slice(arr.as_slice());
        // Belt-and-suspenders: KEM output must never be the all-zero canary.
        if ss == [0u8; 32] {
            ss.zeroize();
            return Err(VaultError::Crypto("degenerate PQ shared secret".into()));
        }
        Ok(PqSharedSecret(ss))
    }

    /// Encapsulate against an encapsulation key → (ciphertext, shared secret).
    pub fn encapsulate(encapsulation_key_bytes: &[u8]) -> Result<(Vec<u8>, PqSharedSecret)> {
        let ek = Self::ek_from_bytes(encapsulation_key_bytes)?;
        let (ct, ss) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| VaultError::Crypto("ML-KEM encapsulation failed".into()))?;
        Ok((ct.to_vec(), Self::secret_from_array(ss)?))
    }

    /// Decapsulate with the decapsulation key + ciphertext → shared secret.
    pub fn decapsulate(
        decapsulation_key_bytes: &[u8],
        ciphertext_bytes: &[u8],
    ) -> Result<PqSharedSecret> {
        let dk = Self::dk_from_bytes(decapsulation_key_bytes)?;
        let ct = Self::ct_from_bytes(ciphertext_bytes)?;
        let ss = dk
            .decapsulate(&ct)
            .map_err(|_| VaultError::Crypto("ML-KEM decapsulation failed".into()))?;
        let out = Self::secret_from_array(ss)?;
        Ok(out)
    }

    /// `Final_Key = HKDF-SHA256(salt: PQ_Shared_Secret, ikm: Argon2_Key)`.
    pub fn combine(argon2_key: &[u8; 32], pq: &PqSharedSecret) -> Result<HybridDerivedKey> {
        let hk = Hkdf::<Sha256>::new(Some(pq.expose()), argon2_key);
        let mut okm = [0u8; 32];
        hk.expand(HYBRID_INFO, &mut okm)
            .map_err(|_| VaultError::Crypto("HKDF expansion failed".into()))?;
        Ok(HybridDerivedKey { key: okm })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let kp = PqHybridEngine::generate_keypair();
        assert_eq!(kp.encapsulation.len(), EK_LEN);
        assert_eq!(kp.decapsulation.expose().len(), DK_LEN);
        let (ct, ss1) = PqHybridEngine::encapsulate(&kp.encapsulation).unwrap();
        assert_eq!(ct.len(), CT_LEN);
        let ss2 = PqHybridEngine::decapsulate(kp.decapsulation.expose(), &ct).unwrap();
        assert_eq!(ss1.expose(), ss2.expose());
    }

    #[test]
    fn hybrid_avalanche() {
        let kp = PqHybridEngine::generate_keypair();
        let (_, ss) = PqHybridEngine::encapsulate(&kp.encapsulation).unwrap();
        let k1 = [7u8; 32];
        let mut k2 = [7u8; 32];
        k2[0] ^= 1; // 1-bit flip in Argon2 key
        let h1 = PqHybridEngine::combine(&k1, &ss).unwrap();
        let h2 = PqHybridEngine::combine(&k2, &ss).unwrap();
        assert_ne!(h1.expose(), h2.expose());
        // differing PQ secret also avalanches
        let kp2 = PqHybridEngine::generate_keypair();
        let (_, ss_b) = PqHybridEngine::encapsulate(&kp2.encapsulation).unwrap();
        let h3 = PqHybridEngine::combine(&k1, &ss_b).unwrap();
        assert_ne!(h1.expose(), h3.expose());
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(PqHybridEngine::encapsulate(&[0u8; 10]).is_err());
        let kp = PqHybridEngine::generate_keypair();
        assert!(PqHybridEngine::decapsulate(kp.decapsulation.expose(), &[0u8; 10]).is_err());
        assert!(PqHybridEngine::decapsulate(&[0u8; 10], &[0u8; CT_LEN]).is_err());
    }
}
