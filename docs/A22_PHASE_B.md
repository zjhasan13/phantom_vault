# A22 Phase B — PQ-paranoid container profile

> Status: **implemented (Phase B)**. No production/UI path uses it yet; A22 is
> not shipped until Phase C (Settings toggle + mandatory portable `.pvx` backup +
> sync guards) lands. Portable remains the default.
>
> Landed: `PV3\0` + `encrypt/decrypt_vault_paranoid_secret`
> (`src/crypto.rs`), profile dispatch + `save_vault_secret_with_profile`
> (`src/storage.rs`), device keypair load (`src/security/pq_profile.rs`).
> Tests: `cargo test` **509 passed / 1 ignored** (+ 4 `pv_sign`), `npm test`
> **133/133**, clippy clean.

## Goal

A vault sealed with the **PQ-paranoid** profile must not open with the master
password alone. It needs:

```
master password  +  this device's ML-KEM decapsulation key
```

The decapsulation key is the DPAPI-sealed sidecar from Phase A
(`src/security/pq_profile.rs`, `pq_device.dpapi`).

## Non-goals

- Portable (`PV2\0`) bytes stay unchanged. Paranoid uses a **new** `PV3\0`
  magic so a reader never has to guess the key chain from an authenticated
  field it cannot read yet.
- No UI toggle yet (Phase C). A paranoid save is reachable only from tests until
  the mandatory portable-backup gate exists.
- No sync of paranoid vaults (sync merge already refuses `PV3` blobs; Phase C
  refuses it at the button).
- No TPM-backed key yet (later hardening; DPAPI is user+machine bound).

## Facts this design builds on

- Portable v2 layout: `PV2\0` + salt + wrap nonce + wrapped DK + KEM ct +
  payload nonce + AEAD payload (`src/crypto.rs`).
- The portable DK is wrapped under `Argon2id(password)`, so a guessed password
  yields the whole key chain (gap C4).
- A16 stores `{meta, vault}` inside the AEAD payload, with `rev`/`prev_hash`,
  padded to 1 MiB (`src/storage.rs`).
- The legacy `V2Legacy` path already knows how to use a DPAPI-sealed
  decapsulation key; it is read-only migration today.

## Design

### 1. Profile marker

Extend `ContainerMeta` (inside the AEAD payload, authenticated):

```json
{ "format": "phantom-vault", "version": 2,
  "profile": "paranoid", "rev": 12, "prev_hash": "…" }
```

- `#[serde(default = "portable")] profile: String` so pre-A22 vaults parse.
- Only `"portable"` and `"paranoid"` accepted; unknown ⇒ fail closed.
- Keeping `version: 2` avoids a second break: old builds still fail on the
  envelope itself (A16), but the marker tells new builds which KDF to use.

### 2. Key chain

Paranoid save/load:

```
argon = Argon2id(password, salt)                 // 32 B
shared = ML-KEM-768.decapsulate(device_dk, kem_ct)
hybrid = HKDF-SHA256(argon || shared, info="pv-paranoid-v1")
key    = XChaCha20-Poly1305 key (32 B)
```

- The container carries the KEM ciphertext encapsulated to the **device
  encapsulation key**.
- The password alone cannot decapsulate; the sidecar alone cannot derive the
  Argon2 half. Both are required.
- Never store the decapsulation key in the container; never wrap it under the
  password.

### 3. Crypto API (`src/crypto.rs`)

Keep portable functions untouched. Add:

```rust
pub fn encrypt_vault_paranoid_secret(
    password: &SecretString,
    encapsulation_key: &[u8],   // from pq_profile::generate_and_seal
    plaintext: &[u8],
) -> Result<Vec<u8>, String>;

pub fn decrypt_vault_paranoid_secret(
    password: &SecretString,
    decapsulation: &PqDecapsulationBytes,
    payload: &[u8],
) -> Result<Vec<u8>, String>;
```

- Reuse `Argon2id` (64 MiB/t=3/p=4), ML-KEM-768, HKDF-SHA256 and XChaCha20 from
  the existing portable implementation.
- Fresh salt + fresh KEM encapsulation on every save.
- Parse/validate lengths before doing KDF work; fail closed on truncation.
- Zeroize the argon key, shared secret and hybrid key on every path.

### 4. Storage API (`src/storage.rs`)

```rust
pub fn save_vault_secret_with_profile(
    vault: &Vault,
    password: &SecretString,
    file_path: impl AsRef<Path>,
    profile: ContainerProfile, // Portable | Paranoid
) -> Result<(), String>;
```

- `save_vault_secret` becomes `…with_profile(…, Portable)` (no behaviour change).
- Paranoid save requires `pq_profile::exists()`; if the sidecar is missing,
  generate once and use the returned encapsulation key (or refuse — decide in
  Phase C; Phase B tests may generate explicitly).
- `load_vault_versioned_secret` dispatches on `meta.profile` **after** AEAD
  decrypt? No: the profile is inside the AEAD payload, so the key derivation
  must be chosen before decrypt. The profile therefore needs to be readable
  **without** the key.
  - Decision: put a 1-byte profile tag in the container header (after `PV2\0`),
    authenticated by the AEAD payload's meta. Old portable readers ignore it?
    No — the layout would shift. Alternative: use a **new container magic**
    (`PV3\0`) for paranoid only; portable stays byte-identical. This is the
    safer choice: no ambiguity, no shifted offsets.
  - Revised: paranoid container magic `PV3\0` + same field order; `profile` is
    still in meta for defence in depth. `detect_version` gains `V3Paranoid`.
- Load:
  - `V3Paranoid` → `pq_profile::load_decapsulation()`; missing sidecar ⇒
    “this vault requires this device's PQ key” (distinct from wrong password).
  - `PV2` portable → unchanged.
  - Legacy V2Legacy/V1 → unchanged.
- A16 `rev`/`prev_hash` and 1 MiB padding are reused unchanged; rekey preserves
  the sidecar and writes rev N+1.
- Sidecar name `pq_device.dpapi`; add it to `.gitignore` and the factory-reset
  target list.

### 5. Rekey / backup / decoy / sync

| Flow | Paranoid behaviour |
|---|---|
| Rekey | new password, same device key; rev+1; `.bak.1.enc` old password (still needs the sidecar to open) |
| `.bak.1.enc` | paranoid, not portable; document |
| Scheduled backup | copy only; same sidecar required |
| Decoy | stays **portable** so the duress password works under coercion |
| `.pvx` export | portable backup passphrase (recovery path); never paranoid |
| GitHub/P2P sync | refused in Phase C with a clear message |
| Device key lost | vault unreadable; only a pre-enable `.pvx` backup restores |

## Implementation notes (Phase B, landed)

- `V3Paranoid` magic is detected before `PV2\0`; portable bytes are untouched.
- Paranoid layout: `PV3\0 | salt 16 | kem_ct 1088 | nonce 24 | ct+tag`.
  There is no wrapped DK in the container — the device keeps it.
- Key chain: `HKDF-SHA256(salt = ML-KEM shared secret, ikm = Argon2id key,
  info = "phantom_vault_paranoid_v1")`. The info string is distinct from the
  legacy hybrid key chain so the two can never collide.
- The encapsulation key is re-derived from the sealed decapsulation key
  (`PqHybridEngine::encapsulation_from_decapsulation`), so the sidecar custodies
  exactly one secret.
- Saves refuse with `PQ-paranoid save refused: PQ device key is missing …`
  when no sidecar exists. There is no silent portable fallback.
- Loads of `PV3` fail with `This vault requires this device's PQ key: …` before
  the AEAD step, so "missing device key" is distinguishable from a bad password.
- `meta.profile` is validated against the magic; unknown profiles and
  downgrade attempts fail closed.
- Sync merge (`decrypt_blob_to_envelope`) rejects `PV3` blobs, so a paranoid
  container can never be adopted by a peer even before Phase C's UI guard.
- Factory reset already shreds `*.dpapi`, which covers `pq_device.dpapi`
  (locked by a test).
- Honest limits unchanged: DPAPI is user+machine bound (same-user malware can
  unseal it), and losing the sidecar or the Windows profile means data loss.

## Decisions (settled)

1. **Profile marker:** `PV3\0` magic + authenticated `meta.profile` (both must
   agree; either alone is not enough).
2. **Sidecar lifecycle:** explicit device-key creation in Phase C, gated behind
   a portable `.pvx` export. Phase B has no UI.
3. **Locked-vault UX:** missing sidecar surfaces as “requires this device's PQ
   key”, never as a password error.
4. **Rekey with sidecar missing:** refuse (the load proof fails); rekey preserves
   the profile and never downgrades to portable.

## Tests (exit criteria)

1. Paranoid save → decrypt with password only **fails** with a distinct error.
2. Password + correct sidecar → opens the exact vault JSON.
3. Missing/corrupt sidecar → fail closed, not “wrong password”.
4. Portable vault still opens and never consults the sidecar.
5. Rekey: new password + same sidecar opens; old password fails; rev increments.
6. A16 chain/padding invariants still hold for paranoid (rev/prev_hash).
7. Tampered KEM ciphertext / AEAD tag → error, no partial plaintext.
8. Sidecar is DPAPI-bound (unseal fails with a foreign blob).
9. Sync merge refuses a `PV3` blob.
10. Profile mismatch (magic vs meta) fails closed.

Exit criteria 1–8, 10 are covered by
`storage::tests::paranoid_profile_requires_sidecar_and_never_downgrades` and
`crypto::tests::paranoid_roundtrip_needs_password_and_device_key`; 9 by the
sync merge guard.

## Phase C gate (do not skip)

- Settings toggle only after a successful portable `.pvx` export.
- Sync + P2P buttons refuse paranoid vaults with an explanation.
- Warning text: losing `pq_device.dpapi` or this Windows profile means data loss.
- Docs: README/SECURITY/RELEASE + release-note upgrade requirement.
