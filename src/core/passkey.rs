//! Resident WebAuthn passkeys (Ed25519).
//!
//! Keypairs are generated from OS entropy, sealed into the vault as RFC 8410
//! DER (hand-rolled fixed-template codec — zero new dependencies), and used
//! in-process for assertion signatures. The seed never leaves the encrypted
//! container; only `sign_count` moves (up) on each use for RP clone detection.

use crate::error::{Result, VaultError};
use crate::models::PasskeyItem;
use ed25519_dalek::ed25519::signature::{Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};

/// Ed25519 OID 1.3.101.112 as it appears inside AlgorithmIdentifier.
const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];

/// Generate a fresh (seed, public) pair from OS entropy.
/// (`SigningKey::generate` needs dalek's `rand_core` feature; raw OsRng +
/// `from_bytes` is byte-identical in behavior with zero feature churn.)
pub fn generate_ed25519() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    (seed, sk.verifying_key().to_bytes())
}

/// RFC 8410 OneAsymmetricKey (85 bytes): SEQ{INT 0, SEQ{OID}, OCT[OCT[seed]], [1]{BITSTR pub}}.
pub fn pkcs8_encode_private(seed: &[u8; 32], pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(85);
    out.extend_from_slice(&[0x30, 0x53, 0x02, 0x01, 0x00, 0x30, 0x05]);
    out.extend_from_slice(&OID_ED25519);
    out.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    out.extend_from_slice(seed);
    out.extend_from_slice(&[0xA1, 0x23, 0x03, 0x21, 0x00]);
    out.extend_from_slice(pubkey);
    out
}

/// Strict inverse of `pkcs8_encode_private`. Any deviation → Err (never panic).
pub fn pkcs8_decode_private(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let bad = |why: &str| VaultError::Crypto(format!("PKCS#8 parse: {why}"));
    if der.len() != 85 {
        return Err(bad("length"));
    }
    let expect = |i: usize, b: &[u8]| {
        der.get(i..i + b.len())
            .is_some_and(|s| s == b)
            .then_some(())
            .ok_or_else(|| bad("tag"))
    };
    expect(0, &[0x30, 0x53, 0x02, 0x01, 0x00, 0x30, 0x05])?;
    expect(7, &OID_ED25519)?;
    expect(12, &[0x04, 0x22, 0x04, 0x20])?;
    expect(48, &[0xA1, 0x23, 0x03, 0x21, 0x00])?;
    let mut seed = [0u8; 32];
    let mut pubkey = [0u8; 32];
    seed.copy_from_slice(der.get(16..48).ok_or_else(|| bad("seed"))?);
    pubkey.copy_from_slice(der.get(53..85).ok_or_else(|| bad("pubkey"))?);
    // Cross-check: the seed MUST regenerate the embedded public key,
    // otherwise this blob was tampered with (or mis-encoded).
    let check = SigningKey::from_bytes(&seed);
    if check.verifying_key().to_bytes() != pubkey {
        return Err(bad("seed/pubkey mismatch"));
    }
    Ok((seed, pubkey))
}

/// RFC 8410 SubjectPublicKeyInfo (44 bytes, `302a...` prefix):
/// SEQ{SEQ{OID}, BITSTR pub}. Inner = 7 + 35 = 42 = 0x2A.
pub fn spki_encode_public(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(44);
    out.extend_from_slice(&[0x30, 0x2A, 0x30, 0x05]);
    out.extend_from_slice(&OID_ED25519);
    out.extend_from_slice(&[0x03, 0x21, 0x00]);
    out.extend_from_slice(pubkey);
    out
}

/// Sign a challenge (e.g. decoded WebAuthn `challenge`) with the seed.
pub fn sign_bytes(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(msg).to_bytes()
}

/// Verify a signature against a raw 32-byte public key. False on any error.
pub fn verify_bytes(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(pubkey)
        .and_then(|vk| {
            vk.verify(
                msg,
                &Signature::from_bytes(sig),
            )
        })
        .is_ok()
}

/// Register a new resident credential. `rp_id` validation lives with the
/// caller (UI/native-host); this constructor never fabricates identity.
pub fn register(rp_id: &str, user_name: &str, now_unix: u64) -> PasskeyItem {
    let (seed, pubkey) = generate_ed25519();
    let mut credential_id = [0u8; 32];
    let mut user_handle = [0u8; 16];
    OsRng.fill_bytes(&mut credential_id);
    OsRng.fill_bytes(&mut user_handle);
    // Millis-grade uniqueness without a counter service.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for (i, b) in nanos.to_le_bytes().iter().enumerate() {
        credential_id[i] ^= b;
    }
    PasskeyItem {
        id: format!("pk-{}-{nanos}", now_unix),
        rp_id: rp_id.to_string(),
        user_name: user_name.to_string(),
        user_handle: user_handle.to_vec(),
        credential_id: credential_id.to_vec(),
        private_key_pkcs8: pkcs8_encode_private(&seed, &pubkey),
        public_key_der: spki_encode_public(&pubkey),
        sign_count: 0,
        created_at: now_unix,
        // Fresh credentials start active in the vault, unpinned.
        favorite: false,
        deleted_at: None,
    }
}

/// Phase 3 — WebAuthn ceremony packaging (assertion + fmt-none attestation).
/// The page's promise is fulfilled with these bytes; the RP verifies them
/// against the registered credential. Pure — unit tested.
use base64::Engine as _;
use sha2::{Digest, Sha256};

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Validate ceremony binding: origin must be https and its host must equal
/// rp_id exactly (no silent cross-origin signing). Returns the canonical
/// origin string for clientDataJSON.
pub fn ceremony_origin(origin: &str, rp_id: &str) -> std::result::Result<String, String> {
    let url = url::Url::parse(origin.trim()).map_err(|_| "bad origin".to_string())?;
    if url.scheme() != "https" {
        return Err("origin must be https".to_string());
    }
    let host = url.host_str().unwrap_or("").to_lowercase();
    if host.is_empty() || host != rp_id.trim().to_lowercase() {
        return Err("origin host must equal rp_id".to_string());
    }
    Ok(url.origin().ascii_serialization())
}

/// CBOR helpers (fixed-shape attestation only — no general encoder).
fn cbor_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(1 + b.len());
    if b.len() < 24 {
        out.push(0x60 + b.len() as u8);
    } else {
        out.push(0x78);
        out.push(b.len() as u8);
    }
    out.extend_from_slice(b);
    out
}

fn cbor_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + b.len());
    if b.len() < 24 {
        out.push(0x40 + b.len() as u8);
    } else if b.len() < 256 {
        out.push(0x58);
        out.push(b.len() as u8);
    } else {
        out.push(0x59);
        out.push((b.len() >> 8) as u8);
        out.push((b.len() & 0xFF) as u8);
    }
    out.extend_from_slice(b);
    out
}

/// Full assertion triple: authenticator data, client-data JSON, signature.
pub type AssertionTriple = (Vec<u8>, Vec<u8>, [u8; 64]);

/// Build a full assertion response for an existing credential.
/// The caller supplies the NEW counter (old+1) and persists it — clone detection.
pub fn assertion_response(
    seed: &[u8; 32],
    rp_id: &str,
    origin: &str,
    challenge: &[u8],
    counter: u32,
    uv: bool,
) -> std::result::Result<AssertionTriple, String> {
    if challenge.is_empty() || challenge.len() > 1024 {
        return Err("bad challenge length".to_string());
    }
    let origin = ceremony_origin(origin, rp_id)?;
    let mut auth = Vec::with_capacity(37);
    auth.extend_from_slice(&Sha256::digest(rp_id.trim().to_lowercase().as_bytes()));
    auth.push(0x01 | if uv { 0x04 } else { 0x00 });
    auth.extend_from_slice(&counter.to_be_bytes());
    let client_data = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\"}}",
        b64url(challenge),
        origin
    );
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
    let sig = sign_bytes(seed, &signed);
    Ok((auth, client_data.into_bytes(), sig))
}

/// COSE_Key for Ed25519: {1: OKP(1), 3: EdDSA(-8), -1: Ed25519(6), -2: x}.
fn cose_ed25519(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    out.extend_from_slice(pubkey);
    out
}

/// Build a fmt-none attestation for a FRESH credential.
/// Returns (attestation_object, client_data_json). The caller persists the
/// returned `PasskeyItem`-equivalent fields (credential id, key, handle).
/// RPs that reject Ed25519/“none” fail LOUD on their side — relayed bytes
/// are standard-shaped, never silently downgraded.
pub fn attestation_object(
    pubkey: &[u8; 32],
    credential_id: &[u8],
    rp_id: &str,
    origin: &str,
    challenge: &[u8],
    user_handle: &[u8],
) -> std::result::Result<(Vec<u8>, Vec<u8>), String> {
    if challenge.is_empty() || challenge.len() > 1024 {
        return Err("bad challenge length".to_string());
    }
    if credential_id.is_empty() || credential_id.len() > 1024 {
        return Err("bad credential id length".to_string());
    }
    if user_handle.is_empty() || user_handle.len() > 64 {
        return Err("bad user handle length".to_string());
    }
    let _ = user_handle; // bound to the vault record, not the wire bytes
    let origin = ceremony_origin(origin, rp_id)?;
    let mut auth = Vec::new();
    auth.extend_from_slice(&Sha256::digest(rp_id.trim().to_lowercase().as_bytes()));
    auth.push(0x01 | 0x04 | 0x40); // UP | UV | AT
    auth.extend_from_slice(&0u32.to_be_bytes());
    auth.extend_from_slice(&[0u8; 16]); // aaguid: none
    auth.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth.extend_from_slice(credential_id);
    auth.extend_from_slice(&cose_ed25519(pubkey));
    let client_data = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"{}\"}}",
        b64url(challenge),
        origin
    );
    // attestationObject = {"fmt":"none","authData":h'..',"attStmt":{}}
    let mut obj = vec![0xA3];
    obj.extend_from_slice(&cbor_text("fmt"));
    obj.extend_from_slice(&cbor_text("none"));
    obj.extend_from_slice(&cbor_text("authData"));
    obj.extend_from_slice(&cbor_bytes(&auth));
    obj.extend_from_slice(&cbor_text("attStmt"));
    obj.push(0xA0);
    Ok((obj, client_data.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_fixed_shapes() {
        let (seed, pubkey) = ([7u8; 32], {
            let sk = SigningKey::from_bytes(&[7u8; 32]);
            sk.verifying_key().to_bytes()
        });
        let pkcs8 = pkcs8_encode_private(&seed, &pubkey);
        assert_eq!(pkcs8.len(), 85);
        assert_eq!(&pkcs8[..7], &[0x30, 0x53, 0x02, 0x01, 0x00, 0x30, 0x05]);
        let spki = spki_encode_public(&pubkey);
        assert_eq!(spki.len(), 44);
        assert_eq!(&spki[..4], &[0x30, 0x2A, 0x30, 0x05]);
    }

    #[test]
    fn der_roundtrip_preserves_seed() {
        let (seed, pubkey) = generate_ed25519();
        let der = pkcs8_encode_private(&seed, &pubkey);
        let (s2, p2) = pkcs8_decode_private(&der).unwrap();
        assert_eq!(s2, seed);
        assert_eq!(p2, pubkey);
    }

    #[test]
    fn der_rejects_garbage_and_tamper() {
        assert!(pkcs8_decode_private(&[]).is_err());
        assert!(pkcs8_decode_private(&[0u8; 85]).is_err());
        assert!(pkcs8_decode_private(&[0x30u8; 40]).is_err());
        // Flip one seed byte: tag structure survives, cross-check must fire.
        let (seed, pubkey) = generate_ed25519();
        let mut der = pkcs8_encode_private(&seed, &pubkey);
        der[20] ^= 0xFF;
        assert!(pkcs8_decode_private(&der).is_err());
        // Flip the version: structural reject.
        der[20] ^= 0xFF;
        der[2] ^= 0xFF;
        assert!(pkcs8_decode_private(&der).is_err());
    }

    #[test]
    fn sign_verify_roundtrip_and_negative() {
        let (seed, pubkey) = generate_ed25519();
        let msg = b"webauthn-challenge-bytes";
        let sig = sign_bytes(&seed, msg);
        assert!(verify_bytes(&pubkey, msg, &sig));
        // Wrong message fails.
        assert!(!verify_bytes(&pubkey, b"other", &sig));
        // Wrong key fails.
        let (_, other_pub) = generate_ed25519();
        assert!(!verify_bytes(&other_pub, msg, &sig));
        // Flipped signature bit fails.
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!verify_bytes(&pubkey, msg, &bad));
    }

    #[test]
    fn generations_are_unique() {
        let (s1, p1) = generate_ed25519();
        let (s2, p2) = generate_ed25519();
        assert_ne!(s1, s2);
        assert_ne!(p1, p2);
    }

    #[test]
    fn register_field_invariants() {
        let now = crate::models::current_timestamp();
        let a = register("github.com", "octo", now);
        let b = register("github.com", "octo", now);
        assert_eq!(a.rp_id, "github.com");
        assert_eq!(a.user_name, "octo");
        assert_eq!(a.credential_id.len(), 32);
        assert_eq!(a.user_handle.len(), 16);
        assert_eq!(a.sign_count, 0);
        assert_eq!(a.created_at, now);
        assert_eq!(a.private_key_pkcs8.len(), 85);
        assert_eq!(a.public_key_der.len(), 44);
        assert_ne!(a.credential_id, b.credential_id, "ids must be random");
        assert_ne!(a.id, b.id);
        // Stored blob must decode back to a working key.
        let (seed, pubkey) = pkcs8_decode_private(&a.private_key_pkcs8).unwrap();
        let sig = sign_bytes(&seed, b"m");
        assert!(verify_bytes(&pubkey, b"m", &sig));
    }

    #[test]
    fn ceremony_origin_binding_strict() {
        assert_eq!(
            ceremony_origin("https://github.com/login", "github.com").unwrap(),
            "https://github.com"
        );
        // Case-insensitive host, exact match only.
        assert!(ceremony_origin("https://GitHub.COM/", "github.com").is_ok());
        assert!(ceremony_origin("http://github.com/", "github.com").is_err());
        assert!(ceremony_origin("https://evil.com/", "github.com").is_err());
        assert!(ceremony_origin("https://sub.github.com/", "github.com").is_err());
        assert!(ceremony_origin("not a url", "github.com").is_err());
    }

    #[test]
    fn assertion_verifies_end_to_end() {
        let (seed, pubkey) = generate_ed25519();
        let chal = b"rp-challenge-xyz";
        let (auth, client_data, sig) =
            assertion_response(&seed, "github.com", "https://github.com/", chal, 41, true).unwrap();
        // authData: rpIdHash(32) | flags(UP|UV=0x05) | counter BE(41).
        assert_eq!(auth.len(), 37);
        assert_eq!(&auth[..32], &Sha256::digest(b"github.com")[..]);
        assert_eq!(auth[32], 0x05);
        assert_eq!(u32::from_be_bytes(auth[33..37].try_into().unwrap()), 41);
        // Signature covers authData || sha256(clientDataJSON).
        let cd: serde_json::Value = serde_json::from_slice(&client_data).unwrap();
        assert_eq!(cd["type"], "webauthn.get");
        assert_eq!(cd["origin"], "https://github.com");
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        assert!(verify_bytes(&pubkey, &signed, &sig));
        // No UV → flag drops, still verifies.
        let (auth2, _, _) =
            assertion_response(&seed, "github.com", "https://github.com/", chal, 42, false).unwrap();
        assert_eq!(auth2[32], 0x01);
        // Bad inputs refuse.
        assert!(assertion_response(&seed, "github.com", "https://github.com/", b"", 1, true).is_err());
        assert!(assertion_response(&seed, "github.com", "https://evil.com/", chal, 1, true).is_err());
    }

    #[test]
    fn attestation_object_structural() {
        let (_seed, pubkey) = generate_ed25519();
        let cred_id = [9u8; 32];
        let handle = [3u8; 16];
        let (obj, cd) = attestation_object(
            &pubkey,
            &cred_id,
            "github.com",
            "https://github.com/register",
            b"reg-challenge",
            &handle,
        )
        .unwrap();
        // {"fmt":"none",...} → 0xA3 0x63 'f' 'm' 't' 0x64 'none'.
        assert_eq!(&obj[..8], &[0xA3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o']);
        // Tail: "attStmt" + empty map.
        assert_eq!(&obj[obj.len() - 9..], &[0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xA0]);
        let cdv: serde_json::Value = serde_json::from_slice(&cd).unwrap();
        assert_eq!(cdv["type"], "webauthn.create");
        assert_eq!(cdv["origin"], "https://github.com");
        // Bad inputs refuse.
        assert!(attestation_object(&pubkey, &[], "github.com", "https://github.com/", b"c", &handle).is_err());
        assert!(attestation_object(&pubkey, &cred_id, "github.com", "http://github.com/", b"c", &handle).is_err());
        assert!(attestation_object(&pubkey, &cred_id, "github.com", "https://github.com/", b"c", &[0u8; 65]).is_err());
    }
}
