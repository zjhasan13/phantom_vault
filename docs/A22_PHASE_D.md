# A22 Phase D — TPM-backed device-key custody (design note)

> Status: **D0 design + D1 custody layer + D2 wiring implemented.** Enabling the
> paranoid profile now prefers TPM 2.0, falls back to DPAPI with a visible
> backend label, and offers an explicit proof-first "Move device key to TPM".
> D3 is the remaining QA/release pass. A/B/C are shipped (`c79f535`).
>
> D1/D2 landed: `src/security/pq_tpm.rs` (`PVT1`, CNG RSA-2048 OAEP-SHA256 wrap
> + XChaCha20 DK seal, platform *and* software KSP), backend-aware
> `src/security/pq_profile.rs` (strict load order, `reseal_to`, no hidden
> fallback), Settings backend status + move action (`src/main.rs`,
> `ui/appwindow.slint`), and the `.tpm` factory-reset sweep. Tests:
> `cargo test` **515 passed / 2 ignored** (+ 4 `pv_sign`); the ignored ones are
> the real-TPM manual test (DPAPI→TPM migration verified on this Infineon
> TPM 2.0) and the pre-existing hardware test. `npm test` **133/133**, clippy
> clean.

## 1. Goal

Today the ML-KEM decapsulation key lives in `pq_device.dpapi`, sealed with
DPAPI (`src/security/pq_profile.rs`). DPAPI is user + machine bound, but the
ciphertext can be decrypted by any process running as that user on that machine,
and domain profiles can roam the DPAPI master key.

Phase D binds the device key to this machine's **TPM 2.0**:

```
sidecar (pq_device.tpm)  ──unseal──>  TPM persisted RSA key  ──>  AES key
                                                                     │
                                                  XChaCha20-Poly1305(dk)
```

Copying the sidecar to another PC no longer helps: the TPM key does not exist
there.

## 2. Non-goals

- No container-format change. `PV3\0`, the key chain and A16 rev/padding stay
  exactly as shipped in A22 B/C.
- No protection against same-user malware (see threat model).
- No Windows Hello / user-presence prompt by default.
- No macOS/Linux backend (A10).
- No passkey/FIDO2 work (A21).

## 3. Threat model (honest)

| Threat | DPAPI (today) | TPM (Phase D) |
|---|---|---|
| Offline disk theft (sidecar copied) | weak: DPAPI master key can be extracted from the profile | strong: unseal needs the TPM |
| Sidecar copied to another PC | fails (different DPAPI keys) | fails (TPM key absent) |
| Same-user malware while running | can unseal | **can still unseal** (no user-presence by default) |
| TPM clear / Windows reinstall / profile loss | n/a | **permanent key loss** — same honest warning as today |
| Domain profile roaming | DPAPI key may roam | does not roam |

`NCRYPT_UI_PROTECT_KEY_FLAG` would add a user-presence prompt, but it breaks
unattended saves and auto-unlock flows; it stays an open decision, default OFF.

## 4. Platform facts verified for this design

- Dev machine: **TPM 2.0 present**, `TPM Manufacturer: Infineon SLB9670`,
  `Ready For Storage: True` (`tpmtool getdeviceinformation`).
- `Cargo.toml` already enables `windows 0.58` with `Win32_Security_Cryptography`,
  which exposes the NCrypt surface used below:
  `NCryptOpenStorageProvider`, `NCryptCreatePersistedKey`, `NCryptFinalizeKey`,
  `NCryptOpenKey`, `NCryptEncrypt/Decrypt`, `NCryptDeleteKey`,
  `MS_PLATFORM_CRYPTO_PROVIDER`, `MS_KEY_STORAGE_PROVIDER`,
  `NCRYPT_LENGTH_PROPERTY`, `NCRYPT_PAD_OAEP_FLAG`, `NCRYPT_SILENT_FLAG`,
  `BCRYPT_OAEP_PADDING_INFO`.
- CI has no TPM. Tests therefore need the **software KSP**
  (`MS_KEY_STORAGE_PROVIDER`) — same NCrypt code path, no hardware dependency —
  plus `#[ignore]`/feature-gated TPM tests for a real machine.

## 5. Design

### 5.1 Backend abstraction

Extend `src/security/pq_profile.rs` with a internal backend:

```rust
enum BackendKind { Dpapi, Tpm }

trait KeySealer {
    fn kind(&self) -> BackendKind;
    fn available(&self) -> bool;
    fn seal(&self, dk: &[u8]) -> Result<Vec<u8>, String>;
    fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, String>;
}
```

- `DpapiSealer` wraps the current `DpapiGuard` path (unchanged bytes).
- `TpmSealer` implements §5.2 against a CNG provider name + persisted key name.
- Tests select the backend via `PV_PQ_KEY_BACKEND=dpapi|tpm|software`; the
  existing `PV_PQ_DEVICE_KEY_FILE` override stays for the sidecar path.
- Production default: **TPM if available, else DPAPI** (§5.5).

### 5.2 TPM sealing scheme

A TPM RSA key cannot encrypt 2400 bytes directly, so seal a random symmetric key
and encrypt the decapsulation key with it:

1. `NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER)` — fails cleanly when
   no TPM / provider is unavailable.
2. `NCryptOpenKey("PhantomVault-PQ-Device-v1")`; if absent,
   `NCryptCreatePersistedKey(NCRYPT_RSA_ALGORITHM, keyName, 0, 0)` +
   `NCRYPT_LENGTH_PROPERTY = 2048` + `NCryptFinalizeKey`.
   - user scope (no `NCRYPT_MACHINE_KEY_FLAG`; no admin requirement)
   - `NCRYPT_SILENT_FLAG` on operations; **no** UI-protect by default
3. Seal: random 32-byte `wrap_key`; `NCryptEncrypt` it with RSA-OAEP-SHA256
   (`BCRYPT_OAEP_PADDING_INFO`) + `NCRYPT_SILENT_FLAG`.
4. Encrypt the 2400-byte decapsulation key with
   `XChaCha20-Poly1305(wrap_key)` — reuses the existing Rust AEAD, so NCrypt is
   only used for the RSA wrap.
5. Unseal: RSA-OAEP decrypt `wrap_key`, then AEAD-open the DK; any failure is
   fail-closed (never falls back to DPAPI).

Reserve RSA-2048 (`256 B` ciphertext). If a TPM rejects OAEP-SHA256 in D1, the
fallback is OAEP-SHA1 for the 32-byte wrap only, documented explicitly.

### 5.3 Sidecar format (`pq_device.tpm`)

| Field | Size | Notes |
|---|---|---|
| magic | 4 | `PVT1` |
| version | 1 | `1` |
| backend | 1 | `2` = TPM, `3` = software KSP (test-only, never accepted as hardware custody) |
| key_name_len | 1 | length of the persisted key name |
| key_name | N | `PhantomVault-PQ-Device-v1` |
| rsa_ct_len | 2 | LE, `256` for RSA-2048 |
| rsa_ct | 256 | OAEP-wrapped 32-byte wrap key |
| nonce | 24 | XChaCha20 |
| sealed_dk | 2416 | 2400-byte DK + 16-byte tag |

The DPAPI sidecar keeps its current opaque DPAPI blob format; no migration of
existing files is forced.

### 5.4 Load / save order

Save (paranoid):
1. `pq_sidecar::load_keypair()` — probe `pq_device.tpm` first, then
   `pq_device.dpapi`.
2. Missing/corrupt ⇒ the same distinct error as today (`PQ device key is
   missing` / `cannot be unsealed`); save refuses, no silent portable write.
3. If the TPM sidecar exists but cannot unseal (TPM cleared, provider error),
   **do not** silently try DPAPI — report the TPM failure. A stale DPAPI file
   lying next to it must not become a hidden fallback.

Load: identical, and the `V3Paranoid` arm continues to surface the error before
the AEAD step.

### 5.5 Availability and fallback policy (shipped in D2)

- On enable: try TPM; if `NCryptOpenStorageProvider`/key creation fails, fall
  back to DPAPI and show the backend in the Settings status line:
  `Device key: TPM 2.0 (hardware-bound)` / `Device key: DPAPI (software fallback)`.
- Existing paranoid vaults keep working with their DPAPI sidecar.
- **Move key to TPM** (explicit, after a fresh `.pvx` export): unseal DK with
  DPAPI → seal with TPM → write `pq_device.tpm` → in-memory unseal proof →
  end-to-end vault load → delete `pq_device.dpapi`. Failure removes the TPM file
  and keeps DPAPI.
- Never auto-migrate on unlock: a silent backend switch is indistinguishable
  from tampering/telemetry and adds a failure window to the only key.

### 5.6 Lifecycle

| Flow | Behaviour |
|---|---|
| Enable paranoid | Gate unchanged (`.pvx` export in-session). Prefer TPM, else DPAPI; write one sidecar only |
| Re-enable / rekey | Reuse the existing healthy sidecar of whichever backend is present |
| Disable | Keep the sidecar (older paranoid backups stay openable), as in Phase C |
| Move to TPM (D2) | Explicit, proof-first (in-memory unseal + vault load), old sidecar deleted only after the proof |
| Factory reset | Shred `pq_device.tpm` **and** `pq_device.dpapi` (`.tpm` joins the sweep) |
| TPM cleared / reinstall | Unseal fails; the only recovery is a portable `.pvx` backup + restore into a portable vault |

## 6. Failure modes

| Symptom | Required behaviour |
|---|---|
| No TPM | `BackendKind::Tpm::available() == false`; enable uses DPAPI; status says so |
| TPM present, key creation denied (policy) | Same as no TPM (DPAPI fallback + honest status) |
| Sidecar magic/size corrupt | Fail closed; no DPAPI fallback |
| TPM unseal error with `pq_device.tpm` present | Fail closed with a TPM-specific message |
| Wrong password | Unchanged: AEAD failure, distinct from device-key errors |
| Sidecar missing | Unchanged: "This vault requires this device's PQ key" |

## 7. UX

Settings → PQ-paranoid gains one status line (no new modal):

```
Device key: TPM 2.0 (hardware-bound)   |   Device key: DPAPI (software fallback)
```

When the sidecar is DPAPI-sealed and the vault is paranoid, a **Move device key
to TPM** button appears; it is gated by the same in-session `.pvx` export and
runs the proof-first migration (§5.6). Warnings stay as shipped; D2 adds one
line to the existing copy: *"TPM-backed keys do not survive a TPM clear or
Windows reinstall — your .pvx backup is the only restore path."* The enable gate
itself does not change. Enabling with no sidecar tries TPM first and only falls
back to DPAPI when the TPM provider or key creation refuses.

## 8. Tests

Status: **1–6 are green** (4 via software KSP and the real-TPM manual run); the
TPM-disabled run and the per-save timing measurement are D3.

1. **Software KSP round-trip** (`security::pq_tpm::tests::software_ksp_seals_and_unseals`):
   seal → unseal the same DK; tamper/truncation fail closed.
2. **Backend label**: `active_backend()` reports `software`/`tpm`/`dpapi`; the
   Settings line and the move-button visibility use it.
3. **No hidden fallback** (`pq_profile::tests::tpm_sidecar_roundtrips_and_never_falls_back_to_dpapi`):
   corrupt `pq_device.tpm` + valid `pq_device.dpapi` still fails closed.
4. **Migration proof** (`pq_profile::tests::migration_to_cng_keeps_the_same_decapsulation_key`,
   plus the manual TPM run): DPAPI-sealed DK → TPM-sealed DK → same bytes; the
   old file is removed only after the proof, and rollback restores DPAPI.
5. **Container regression**: the full A22 B/C storage test still passes with the
   TPM backend present (portable + PV3 unchanged).
6. **Manual, `#[ignore]`**: `security::pq_profile::tests::tpm_device_roundtrip_manual`
   passed on this machine's Infineon TPM 2.0 (2026-11-01), including the
   DPAPI→TPM migration; a "TPM provider disabled" run is D3.
7. **Performance budget**: the real-TPM manual run took ~1.4 s for two key
   creations + migration (key creation dominates); per-save unseal timing is
   measured in D3 before adding a zeroizing per-unlock DK cache.

## 9. Migration / rollback

- Rolling back to the current build is safe: a `PVT1` sidecar is simply an
  unknown file to old builds, and old builds cannot open `PV3` anyway.
- Rolling back a *migrated* vault to DPAPI requires the explicit move action
  (D2) or restoring the portable `.pvx`; we do not ship an automatic reverse
  migration.
- No vault bytes, revisions or backups are rewritten by D1/D2; only the
  sidecar changes.

## 10. Decisions (settled in D0)

1. **Fallback policy:** DPAPI fallback + visible backend status (shipped).
2. **User-presence:** `NCRYPT_UI_PROTECT_KEY_FLAG` OFF by default; optional
   future "lock every save" mode.
3. **Migration:** explicit only; no auto-migration on unlock (shipped).
4. **Key scope:** per-user (shipped).
5. **RSA size:** 2048 (shipped).
6. **Backend choice:** at enable time, TPM preferred (shipped).

## 11. Slices and exit criteria

- **D0 — DONE:** this document reviewed; decisions 1–6 settled (recommended
  defaults accepted).
- **D1 — DONE:** CNG provider abstraction (`Tpm`/`Software`), `PVT1` format,
  RSA-2048 OAEP-SHA256 wrap + XChaCha20 DK seal, atomic sidecar writes, strict
  TPM→DPAPI load order with no fallback, software-KSP tests, and a real-TPM
  manual roundtrip on this device. Production still writes DPAPI — D2 wires the
  preference.
- **D2 — DONE:** enable prefers TPM with an honest DPAPI fallback, Settings
  backend line, proof-first "Move device key to TPM" (in-memory unseal + live
  vault load before deleting DPAPI), `.tpm` factory-reset sweep, and the
  migration tests (software KSP + real TPM).
- **D3 (remaining, 1 day):** TPM-disabled QA, per-save unseal timing
  measurement, release-note wording, and a final docs pass.
