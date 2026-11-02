# A24 — chunked, separately encrypted attachments

> Status: **A24a shipped** (format + crypto + tests). A24b–d are planned and
> need sign-off before touching the vault format.

## Why

Today an attachment is a base64 `Vec<u8>` inside the vault JSON
(`src/models.rs:70-80`), capped at 5 MiB (`src/models.rs:82`). Adding or
removing one byte re-serialises and re-encrypts the **whole vault**, and the
GitHub/P2P sync then re-uploads the whole blob. A 50 MiB file is therefore both
slow and memory-hungry, and every attachment byte participates in every vault
save.

Goal (acceptance): **a 50 MiB attachment saves without re-encrypting the vault
or holding the whole vault + attachment in RAM at once**, while keeping
zero-knowledge storage and existing vaults openable.

## Current behaviour (evidence)

- Inline storage: `src/models.rs:70-82` (`EncryptedAttachment.data`, 5 MiB cap).
- Add path reads the whole file, caps at 5 MiB, pushes into the item and calls
  `save_vault_secret` — `src/main.rs:12205`, `src/main.rs:12241-12249`.
- Detail preview/download/delete read `data` directly (`attachments_of`,
  `src/main.rs:14820+`); the UI never streams.
- Native `.pvx` export is lossless and includes attachment bytes; CSV/KDBX
  deliberately do not (`src/main.rs:11173`).
- GitHub sync pushes one encrypted `vault.enc` (`src/sync/github_sync.rs`);
  P2P does the same. There is no multi-file attachment transfer.

## Format (A24a, implemented)

`src/attachment_store.rs` defines `PVAB1`:

```
magic "PVAB1" (5) | flags (1) = 0
| chunk_size u32 LE (1 MiB) | chunk_count u32 LE
| size_bytes u64 LE
| wrapped_key = nonce(24) + sealed file_key(32+16 tag) = 72
| chunk 0: nonce(24) + ciphertext+tag
| chunk 1: ...
```

- Each attachment gets a random 32-byte **file key**.
- The file key is wrapped with XChaCha20-Poly1305 under the vault
  **attachment root** (32 bytes), with AAD `"PVAB1-key" || attachment_id`.
- Each chunk is sealed with the file key, a fresh 24-byte nonce and AAD
  `"PVAB1" || attachment_id || chunk_index_le`. Swapping chunks between files
  or reordering them fails the tag.
- `SidecarMeta { chunk_size, chunk_count, size_bytes, wrapped_key }` is the
  vault-side metadata; the header must match it exactly on read.
- 1 MiB chunks bound peak memory; empty files are supported (`chunk_count=0`);
  50 MiB is the current ceiling.
- Writes go to a temp file, `sync_all`, then rename; a failed write leaves no
  half-file. Reads reject truncation, trailing data, wrong root/id and any
  metadata/header mismatch.
- Tests: roundtrip (2 full chunks + a partial), empty file, wrong root/id,
  tampered chunk, swapped chunks, oversized declaration, over-long stream.

Honest limit: the sidecar header leaks the plaintext size and chunk count;
filenames/MIME stay inside the encrypted vault JSON.

## Key hierarchy (A24b)

- Add `Vault.attachment_root: Vec<u8>` (32 random bytes, base64 via
  `models::serde_b64`, `#[serde(default)]`).
- `Vault` already derives `Zeroize`/`ZeroizeOnDrop`, so the root is scrubbed on
  lock.
- The root lives **inside the encrypted vault container**, so the master
  password and PQ profile protect it; rekeying re-encrypts the container and
  the root automatically (no per-attachment rewrap).
- Legacy vaults: generate the root lazily on the first sidecar write. If a
  vault references sidecars but the root is empty, **fail closed** with
  “attachment key missing — restore the vault backup”; never mint a new root
  silently (it would orphan every existing sidecar).
- `EncryptedAttachment` gains:
  - `storage: AttachmentStorage` (`Inline` default = legacy, `Sidecar`),
  - `sidecar: Option<SidecarMeta>`.
  `data` stays for legacy inline rows; new sidecars leave it empty.
- Per-attachment file keys are never stored in plaintext; only the wrapped
  form is in the vault metadata (and duplicated in the sidecar header for
  consistency checks).

## Local store + migration (A24b)

- Directory: `<vault_dir>/attachments/<id>.pvab`; tests/portable overrides via
  an explicit base-dir argument (no hidden global).
- **Lazy migration:** on save, every `Inline` attachment is streamed to a
  sidecar first, its metadata is switched to `Sidecar`, and only then is the
  vault saved. If the vault save fails, the old vault still carries the inline
  bytes; the new sidecar is an orphan (safe, can be garbage-collected).
- Never delete the old vault/backup before the new save is durable (existing
  `storage.rs` .bak rotation already covers the blob).
- Missing sidecar on read → explicit “attachment file is missing — restore it
  from a backup”; never return empty bytes.
- A sidecar orphan sweep (ids not referenced by the vault) can be a manual
  maintenance command, not an automatic delete.
- `MAX_ATTACHMENT_BYTES` becomes 50 MiB; the per-item count stays 10 unless
  we decide otherwise. The add path streams from disk in 1 MiB chunks.

## Export/import (A24b)

A single `.pvx` file can no longer be a bare encrypted JSON once bytes live
outside it. Introduce a packed `PVX2` container (no new dependency):

```
magic "PVX2" (4) | version(1) | entry_count u32
| for each: name_len u16 | name | size u64 | bytes
```

- Required entry `vault.enc` = the existing encrypted vault blob.
- Optional `attachments/<id>.pvab` entries; names are validated as
  `attachments/[0-9a-f]+.pvab`, sizes capped, count capped.
- All payloads are already AEAD-sealed; the container itself is not another
  encryption layer. A SHA-256 per entry in a `manifest` entry is optional but
  recommended for truncation/corruption diagnostics.
- Legacy `.pvx` (JSON blob) and all other formats keep working; the importer
  sniffs `PVX2` first.
- CSV/KDBX stay lossy for attachments (unchanged, documented).

Alternative considered: a ZIP. Rejected for now to avoid a new dependency and
because no external tool needs to open the container; the custom packer is
~100 lines and testable.

## Sync/P2P (A24c)

Two options:

1. **Bundle-first:** sync the `PVX2` pack as one remote object. Simple and
   correct, but every sync re-uploads all attachments (a 50 MiB file on every
   change).
2. **Manifest + content-addressed sidecars (recommended):** keep `vault.enc`
   and add a manifest of `{id, sha256, size}`; upload only sidecars whose hash
   is absent remotely; delete on revoke; P2P mirrors the same manifest.
   Conflicts are resolved by the existing vault revision head; an attachment
   whose sidecar is missing is reported, never silently dropped.

A24c needs a migration story for a remote that still has the old single blob:
read it, migrate locally, then push the manifest + sidecars on the next sync.

## UI (A24b)

- Raise the picker cap to 50 MiB and show progress while streaming.
- Detail panel marks sidecar-backed rows (and “missing” rows) clearly.
- Preview/download stream to a temp file instead of cloning the bytes into
  every `CredentialView`/`AttachmentView`; delete removes the sidecar after the
  vault save succeeds (best-effort; orphans are harmless).
- No new plaintext-on-disk path: preview temp files are deleted on close, and
  download is the existing explicit user action.

## Tests

- A24a (done): format roundtrip, empty, wrong root/id, tamper, reorder,
  oversized/over-long, temp cleanup.
- A24b: migration keeps bytes byte-for-byte; vault save failure leaves the old
  inline copy usable; missing sidecar fails closed; 50 MiB save leaves the
  vault tiny and peak memory bounded; `PVX2` export/import roundtrip; legacy
  `.pvx` still imports; CSV/KDBX still exclude bytes.
- A24c: manifest upload only sends missing hashes; missing sidecar is a visible
  error; revoke deletes; remote old-blob migration.
- Manual QA: 50 MiB add/cancel, preview/download, lock mid-add, disk-full,
  antivirus-locked file, 100%/125% layout.

## Honest limits / non-goals

- No compression or deduplication; two identical files cost twice.
- Sidecars are only as strong as the vault root; a stolen vault + sidecars is
  still offline-brute-forceable at the master-password cost.
- Deleting or moving the vault without `attachments/` loses the bytes; the UI
  must say so on export/move.
- Attachments remain per-item; A20 shares logins only (no attachment sharing).
- No streaming decryption to a browser or network surface; local files only.

## Slices / effort

| Slice | Scope | Effort |
|---|---|---|
| A24a | `PVAB1` format + crypto + tests | **done (~0.5 day)** |
| A24b | vault root/metadata, local store, migration, UI, 50 MiB cap, `PVX2` export/import, tests | 3–4 days |
| A24c | sync/P2P manifest + delta upload + old-blob migration | 2–3 days |
| A24d | progress UI, missing-file UX, disk-full/antivirus QA, docs | 1 day |

## Decisions needed before A24b

1. 50 MiB cap (recommended) or 100 MiB?
2. Keep 10 attachments/item or raise to 20?
3. `PVX2` custom packer (recommended) or add a ZIP dependency?
4. Sync: manifest + delta (recommended) or bundle-first?
