//! Release-signing public key (Ed25519) — the single source of truth.
//!
//! The matching 32-byte private seed is NEVER in this repository. It lives in
//! the maintainer's offline backup and in the GitHub Actions secret
//! `PV_SIGNING_KEY` (hex, 64 characters). `tools/pv-sign` refuses to
//! sign if the supplied key does not derive this public key, and the updater
//! refuses any asset whose `<asset>.sig` does not verify against it.
//!
//! Rotation (2026-10-31): the original key had no private half available, so
//! the first certificate-free release rotates it. Clients built before this
//! change cannot verify the new key and need one manual reinstall; after that
//! every release must keep signing with this key. Update both the array and the
//! hex constant together and run `cargo test pv_sign`.

pub const UPDATER_PUBLIC_KEY: [u8; 32] = [
    223, 135, 133, 241, 202, 20, 180, 246, 145, 239, 168, 62, 114, 205, 244, 171, 216, 114, 127,
    245, 111, 75, 39, 162, 194, 168, 99, 132, 78, 175, 207, 214,
];

// Used by the `pv_sign` binary; the GUI binary only needs the array.
#[allow(dead_code)]
pub const UPDATER_PUBLIC_KEY_HEX: &str =
    "df8785f1ca14b4f691efa83e72cdf4abd8727ff56f4b27a2c2a863844eafcfd6";
