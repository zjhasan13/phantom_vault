pub mod crdt_merge;
pub mod github_sync;
pub mod p2p_pairing;
pub mod p2p_local;

/// Serializes tests that mutate process-global P2P env vars (device/paired/PIN
/// paths). Shared by `p2p_local` and `p2p_pairing` tests.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub mod updater;
