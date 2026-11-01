//! A23: local-only API surface (`127.0.0.1`) for the `pv` CLI.
//!
//! - `token`: DPAPI-sealed bearer token + port file
//! - `local`: loopback HTTP listener with per-request approval
//! - `cli`: the `phantom_vault pv ...` client
//!
//! The API is opt-in, read-only, loopback-only, expires after 24h, and every
//! secret read blocks on an in-app Allow/Deny prompt.

pub mod cli;
pub mod local;
pub mod token;

/// Tests in these modules mutate the process-wide token/port paths.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
