//! Detached Ed25519 signer/verifier for release assets.
//!
//! This is the missing half of the updater pipeline: `src/sync/updater.rs`
//! already verifies `<asset>.sig` (raw 64 bytes, or hex) against the pinned
//! `UPDATER_PUBLIC_KEY`, but nothing produced those signatures. This tool does,
//! and it refuses to sign with a key that does not match the pinned public key
//! — a mismatched signature would be rejected by every client anyway.
//!
//! It lives in its own crate on purpose: a key-handling tool must not pull in
//! the desktop app's network/UI dependency graph.
//!
//! Usage:
//!   pv-sign keygen --out PATH [--force]
//!   pv-sign pubkey (--key HEX | --key-file PATH | --key-env VAR)
//!   pv-sign sign FILE   (--key HEX | --key-file PATH | --key-env VAR) [--out SIG]
//!   pv-sign verify FILE [--sig SIG]
//!
//! The seed is never printed. `keygen` requires `--out` so a new key cannot be
//! generated and then lost in scrollback.

#[path = "../../../src/release_pubkey.rs"]
mod release_pubkey;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};

const KEY_ENV_DEFAULT: &str = "PV_SIGNING_KEY";
const SEED_LEN: usize = 32;

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    if !t.len().is_multiple_of(2) || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn parse_seed_text(s: &str) -> Result<[u8; SEED_LEN], String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex_decode(t).ok_or_else(|| "key is not valid hex".to_string())?;
    if bytes.len() != SEED_LEN {
        return Err(format!(
            "key must be {SEED_LEN} bytes ({} hex chars), got {} bytes",
            SEED_LEN * 2,
            bytes.len()
        ));
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Accepts either a raw 32-byte seed file or a hex text file (with optional
/// newline / `0x` prefix). Raw wins when the length is exactly 32.
fn seed_from_file_bytes(raw: &[u8]) -> Result<[u8; SEED_LEN], String> {
    if raw.len() == SEED_LEN {
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(raw);
        return Ok(seed);
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| "key file is neither 32 raw bytes nor hex text".to_string())?;
    parse_seed_text(text)
}

fn load_seed(
    key: Option<String>,
    key_file: Option<String>,
    key_env: Option<String>,
) -> Result<[u8; SEED_LEN], String> {
    if let Some(path) = key_file {
        let raw = std::fs::read(&path).map_err(|e| format!("cannot read key file {path}: {e}"))?;
        return seed_from_file_bytes(&raw);
    }
    if let Some(hex) = key {
        return parse_seed_text(&hex);
    }
    let var = key_env.unwrap_or_else(|| KEY_ENV_DEFAULT.to_string());
    let value = std::env::var(&var).map_err(|_| {
        format!("no signing key: pass --key, --key-file or --key-env (env {var} is not set)")
    })?;
    parse_seed_text(&value)
}

fn signing_key(seed: &[u8; SEED_LEN]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

fn public_key(seed: &[u8; SEED_LEN]) -> [u8; 32] {
    signing_key(seed).verifying_key().to_bytes()
}

fn sign_bytes(seed: &[u8; SEED_LEN], data: &[u8]) -> ([u8; 32], [u8; 64]) {
    let sk = signing_key(seed);
    let pk = sk.verifying_key().to_bytes();
    let sig = sk.sign(data);
    (pk, sig.to_bytes())
}

fn verify_with(pk: &[u8; 32], data: &[u8], sig: &[u8]) -> Result<(), String> {
    if sig.len() != 64 {
        return Err(format!("signature must be 64 bytes, got {}", sig.len()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(sig);
    let vk = VerifyingKey::from_bytes(pk).map_err(|e| format!("pinned key is invalid: {e}"))?;
    vk.verify_strict(data, &Signature::from_bytes(&arr))
        .map_err(|_| "signature does not verify against the pinned key".to_string())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn key_args(args: &[String]) -> (Option<String>, Option<String>, Option<String>) {
    (
        flag(args, "--key"),
        flag(args, "--key-file"),
        flag(args, "--key-env"),
    )
}

fn sig_path_for(file: &str) -> PathBuf {
    PathBuf::from(format!("{file}.sig"))
}

fn usage() -> String {
    "usage:\n  pv-sign keygen --out PATH [--force]\n  \
     pv-sign pubkey (--key HEX | --key-file PATH | --key-env VAR)\n  \
     pv-sign sign FILE   (--key HEX | --key-file PATH | --key-env VAR) [--out SIG]\n  \
     pv-sign verify FILE [--sig SIG]"
        .to_string()
}

fn run_keygen(args: &[String]) -> Result<(), String> {
    use rand::RngCore;
    let Some(out) = flag(args, "--out") else {
        return Err("keygen requires --out PATH; the seed is never printed".into());
    };
    let path = Path::new(&out);
    if path.exists() && !has_flag(args, "--force") {
        return Err(format!("{out} already exists; pass --force to replace it"));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    let mut seed = [0u8; SEED_LEN];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut seed);
    let pk = public_key(&seed);
    std::fs::write(path, format!("{}\n", hex_encode(&seed)))
        .map_err(|e| format!("cannot write {out}: {e}"))?;
    println!("wrote seed: {out}");
    println!("public key: {}", hex_encode(&pk));
    println!("pinned key: {}", release_pubkey::UPDATER_PUBLIC_KEY_HEX);
    println!(
        "matches pinned: {}",
        if pk == release_pubkey::UPDATER_PUBLIC_KEY {
            "yes"
        } else {
            "NO — update src/release_pubkey.rs before signing"
        }
    );
    println!("Rust array: [");
    for chunk in pk.chunks(8) {
        let row: Vec<String> = chunk.iter().map(|b| b.to_string()).collect();
        println!("    {},", row.join(", "));
    }
    println!("]");
    Ok(())
}

fn run_pubkey(args: &[String]) -> Result<(), String> {
    let (key, key_file, key_env) = key_args(args);
    let seed = load_seed(key, key_file, key_env)?;
    let pk = public_key(&seed);
    println!("public key: {}", hex_encode(&pk));
    println!("pinned key: {}", release_pubkey::UPDATER_PUBLIC_KEY_HEX);
    println!(
        "matches pinned: {}",
        if pk == release_pubkey::UPDATER_PUBLIC_KEY {
            "yes"
        } else {
            "NO"
        }
    );
    Ok(())
}

fn run_sign(args: &[String]) -> Result<(), String> {
    let Some(file) = args.get(1).filter(|a| !a.starts_with("--")) else {
        return Err("sign needs a FILE".into());
    };
    let data = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let (key, key_file, key_env) = key_args(args);
    let seed = load_seed(key, key_file, key_env)?;
    let (pk, sig) = sign_bytes(&seed, &data);
    if pk != release_pubkey::UPDATER_PUBLIC_KEY {
        return Err(format!(
            "refusing to sign: key derives {} but the pinned key is {}",
            hex_encode(&pk),
            release_pubkey::UPDATER_PUBLIC_KEY_HEX
        ));
    }
    let out = flag(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| sig_path_for(file));
    std::fs::write(&out, sig).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!(
        "signed {file} -> {} (64-byte Ed25519, key {})",
        out.display(),
        hex_encode(&pk)
    );
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    let Some(file) = args.get(1).filter(|a| !a.starts_with("--")) else {
        return Err("verify needs a FILE".into());
    };
    let data = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let sig_path = flag(args, "--sig")
        .map(PathBuf::from)
        .unwrap_or_else(|| sig_path_for(file));
    let raw = std::fs::read(&sig_path)
        .map_err(|e| format!("cannot read {}: {e}", sig_path.display()))?;
    // Updater accepts raw 64 bytes or hex; accept both here too.
    let sig = if raw.len() == 64 {
        raw
    } else {
        let text = std::str::from_utf8(&raw)
            .map_err(|_| "signature file is neither 64 raw bytes nor hex".to_string())?;
        hex_decode(text).ok_or_else(|| "signature file is not valid hex".to_string())?
    };
    verify_with(&release_pubkey::UPDATER_PUBLIC_KEY, &data, &sig)?;
    println!("OK {file} (sig {})", sig_path.display());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("keygen") => run_keygen(&args),
        Some("pubkey") => run_pubkey(&args),
        Some("sign") => run_sign(&args),
        Some("verify") => run_verify(&args),
        Some("-h") | Some("--help") => {
            println!("{}", usage());
            Ok(())
        }
        _ => {
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("pv-sign: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn sign_verify_roundtrip_and_rejects_tamper() {
        let (pk, sig) = sign_bytes(&SEED, b"installer bytes");
        assert!(verify_with(&pk, b"installer bytes", &sig).is_ok());
        assert!(verify_with(&pk, b"installer bytez", &sig).is_err());
        let other = public_key(&[8u8; 32]);
        assert!(verify_with(&other, b"installer bytes", &sig).is_err());
        assert!(verify_with(&pk, b"installer bytes", &sig[..63]).is_err());
    }

    #[test]
    fn seed_text_accepts_hex_and_0x() {
        let hex = hex_encode(&SEED);
        assert_eq!(parse_seed_text(&hex).unwrap(), SEED);
        assert_eq!(parse_seed_text(&format!(" 0x{hex}\n")).unwrap(), SEED);
        assert!(parse_seed_text("abcd").is_err());
        assert!(parse_seed_text(&"z".repeat(64)).is_err());
    }

    #[test]
    fn seed_file_accepts_raw_and_text() {
        assert_eq!(seed_from_file_bytes(&SEED).unwrap(), SEED);
        assert_eq!(
            seed_from_file_bytes(hex_encode(&SEED).as_bytes()).unwrap(),
            SEED
        );
        assert!(seed_from_file_bytes(b"not-a-key").is_err());
    }

    #[test]
    fn pinned_key_parses_and_hex_matches() {
        let vk = VerifyingKey::from_bytes(&release_pubkey::UPDATER_PUBLIC_KEY).unwrap();
        assert_eq!(
            hex_encode(&vk.to_bytes()),
            release_pubkey::UPDATER_PUBLIC_KEY_HEX
        );
    }
}
