# CryptoAuditor — run 33a85550 participant 0

No P0/P1. 11 P2s; the crypto core is fundamentally sound (fresh OsRng nonces per message, Argon2id 64MiB/t3/p4 as constants, verify-before-decrypt, rev chain inside AEAD, atomic save).

Top 5:
1. A-01 src/storage.rs:487,682-740 — plaintext JSON envelope never zeroized; every save/unlock leaves the full vault (all passwords/SSH keys) in freed heap.
2. A-04 src/crypto.rs:369-370 — `?` on wrong-password return skips argon2_key.zeroize(), so each failed unlock strands a password-derived key.
3. A-02 src/models.rs:593 — `Vault` derives Debug; card CVV, SSH private key, passkey seed, totp_unlock_secret and attachment_root print in clear via {:?}.
4. A-05 src/storage.rs:485 — fs::read(...).unwrap_or_default() hides read errors and resets rev=1/prev_hash="", breaking the A16 anti-rollback chain.
5. A-03 src/crypto.rs:187-195,315-318,432-435 — no AAD on container AEAD; header bound only via key derivation. Verified not exploitable today (swaps fail closed), but fragile.

Full report: some temp path — I'll use the delivered artifact instead.