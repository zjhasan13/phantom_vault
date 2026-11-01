# A22 Phase B — PQ-paranoid container profile (design note)

> Status: design only. No production path uses it yet; A22 is not shipped until
> Phase C (UI + backup gate + sync guards) lands. Portable remains the default.

## Goal

A vault sealed with the **PQ-paranoid** profile must not open with the master
password alone. It needs:

```
master password  +  this device's ML-KEM decapsulation key
```

The decapsulation key is the DPAPI-sealed sidecar from Phase A
(`src/security/pq_profile.rs`, `pq_device.dpapi`).

## Non-goals

- No new container magic in Phase B. The portable envelope layout stays; only
  the key derivation and a `profile` field change.
- No UI toggle yet (Phase C). A paranoid save is reachable only from tests until
  the mandatory portable-backup gate exists.
- No sync of paranoid vaults (Phase C refuses it).
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

## Tests (exit criteria)

1. Paranoid save → decrypt with password only **fails** with a distinct error.
2. Password + correct sidecar → opens the exact vault JSON.
3. Missing/corrupt sidecar → fail closed, not “wrong password”.
4. Portable vault still opens and never consults the sidecar.
5. Rekey: new password + same sidecar opens; old password fails; rev increments.
6. A16 chain/padding invariants still hold for paranoid (rev/prev_hash).
7. Tampered KEM ciphertext / AEAD tag → error, no partial plaintext.
8. Sidecar is DPAPI-bound (unseal fails with a foreign blob).

## Decisions still open (settle before coding)

1. **Profile marker location:** recommend new magic `PV3\0` for paranoid (no
   offset shifts; portable bytes unchanged). Meta `profile` is secondary.
2. **Sidecar lifecycle:** generate on first paranoid enable vs. explicit “create
   device key” step. Recommend explicit + mandatory `.pvx` backup gate (Phase C).
3. **Locked-vault UX:** if the sidecar is missing, show “device key missing —
   restore a portable backup” rather than a password error.
4. **Rekey with sidecar missing:** refuse; never silently fall back to portable.

## Phase C gate (do not skip)

- Settings toggle only after a successful portable `.pvx` export.
- Sync + P2P buttons refuse paranoid vaults with an explanation.
- Warning text: losing `pq_device.dpapi` or this Windows profile means data loss.
- Docs: README/SECURITY/RELEASE + release-note upgrade requirement.
