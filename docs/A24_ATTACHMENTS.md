# A24 — chunked, separately encrypted attachments

> Status: **A24a (format) + A24b-lite (50 MiB sidecars for large files) shipped.**
> Existing/inline attachments are unchanged; new files over 5 MiB are stored as
> `PVAB1` sidecars and no longer force a whole-vault re-encryption. Sidecar
> sync/P2P is **blocked with a clear error until A24c** (no silent data loss);
> `.pvx` export re-inlines sidecars so the legacy single-file backup stays
> readable. No new dependencies were added, so the app size is unchanged.

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

## Key hierarchy (A24a/A24b-lite, implemented)

- `Vault.attachment_root: Vec<u8>` (32 random bytes, base64 via
  `models::serde_b64`, `#[serde(default)]`) — `src/models.rs`.
- `Vault` derives `Zeroize`/`ZeroizeOnDrop`, so the root is scrubbed on lock.
- The root lives **inside the encrypted vault container**, so the master
  password and PQ profile protect it; rekeying re-encrypts the container and
  the root automatically (no per-attachment rewrap).
- Legacy vaults keep an empty root until the first >5 MiB attachment; then
  `ensure_root` generates one. If a vault references a sidecar but the root is
  empty/malformed, reads fail closed with “attachment key missing — restore the
  vault backup”; a new root is never minted silently.
- `EncryptedAttachment` carries:
  - `storage: AttachmentStorage` (`Inline` default = legacy, `Sidecar`),
  - `sidecar: Option<SidecarMeta>`.
  `data` stays for inline rows; sidecar rows leave it empty.
- Per-attachment file keys are never stored in plaintext; only the wrapped
  form is in the vault metadata (and duplicated in the sidecar header for
  consistency checks).

## Local store (A24b-lite, implemented)

- Directory: `<vault_dir>/attachments/<id>.pvab`; tests use an explicit path.
- **Threshold rule:** files ≤5 MiB keep the legacy inline path (so existing
  sync/P2P keeps working); new files **>5 MiB** are written as sidecars with a
  50 MiB ceiling. Existing attachments are not migrated in this slice.
- The add path writes the sidecar first, then saves the vault metadata; if the
  vault save fails, the in-memory snapshot is restored and the new sidecar is
  deleted. A crash between the two leaves an orphan sidecar (safe; no metadata).
- Sidecar reads decrypt into RAM for preview/download; delete removes the sidecar
  only after the vault save succeeds.
- Missing sidecar on read → explicit “attachment file is missing — restore it
  from a backup”; never return empty bytes.
- **A24c (pending):** lazy migration of old inline attachments, streaming
  preview/download, orphan sweep and background gc.
- `MAX_ATTACHMENT_BYTES` stays 5 MiB as the inline threshold;
  `MAX_SIDECAR_ATTACHMENT_BYTES` is 50 MiB; the per-item count stays 10.

## Export/import (A24b-lite, implemented)

- `.pvx` stays the existing single self-contained encrypted blob. Before a
  native export, sidecars are decrypted into a **clone** of the vault
  (`attachment_store::inline_all`), so legacy `.pvx` files keep working on any
  version/device.
- Cost: export reads all sidecars and can hold a large clone + JSON base64 in
  memory (a 50 MiB attachment can need several hundred MiB at peak). Export is
  explicit and infrequent; A24c can add streaming.
- Import is unchanged: inline bytes land in the vault. New >5 MiB adds on the
  importing device will switch to sidecars.
- CSV/KDBX stay lossy for attachments (unchanged, documented).
- A future `PVX2` packer is no longer required for portability; it would only
  help sync/streaming, which A24c covers with a manifest.

## Sync/P2P (A24b-lite guard)

- **Sidecar attachments are local-only for now.** When `<vault_dir>/attachments`
  contains any `.pvab`, `github_sync::push_remote`/`pull_remote` and
  `p2p_local::sync_with_peer` refuse with a clear “large attachments are stored
  separately … export .pvx instead” error. This prevents a silent vault that
  references sidecars the other device does not have.
- Files ≤5 MiB stay inline, so ordinary vaults keep syncing unchanged.
- **A24c (pending):** manifest + content-addressed sidecar transfer, old-blob
  migration, delete-on-revoke and conflict handling. The CRDT merge already
  refuses two different attachment roots instead of dropping one side.

## UI (A24b-lite, implemented)

- File picker title says “max 50MB; >5MB stored separately”.
- >5 MiB files write a sidecar and show the same attachment row; ≤5 MiB keep
  the inline path.
- Preview/download resolve inline bytes or decrypt the sidecar; delete removes
  the sidecar after the vault save. Missing sidecars surface an explicit error.
- No new plaintext-on-disk path: preview stays in RAM, download is the existing
  explicit user action.
- A24c adds streaming progress and avoids holding the whole file in RAM.

## Tests

- A24a (done): format roundtrip, empty, wrong root/id, tamper, reorder,
  oversized/over-long, temp cleanup.
- A24b-lite (done): root generation + fail-closed missing root, sidecar export
  inlining roundtrip, `dir_has_sidecars`; existing vault/storage tests still
  pass with the new defaulted fields.
- A24c (pending): old inline migration, missing sidecar UX, 50 MiB save leaves
  the vault tiny, export/import roundtrip at 50 MiB, sync manifest only uploads
  missing hashes, delete-on-revoke, remote old-blob migration.
- Manual QA: 50 MiB add/cancel, preview/download, lock mid-add, disk-full,
  antivirus-locked file, 100%/125% layout.

## Honest limits / non-goals

- **Large attachments are local-only until A24c**; GitHub/P2P sync refuses
  while a `.pvab` exists. `.pvx` export/import is the supported transfer path.
- Existing inline attachments are not migrated yet; only new >5 MiB files use
  sidecars.
- **Vault `.bak` rotation does not include sidecars.** A `.bak` restore only
  works with the `attachments/` folder from the same point in time; `.pvx`
  export is the self-contained backup. Deleting a sidecar cannot be undone by
  restoring a vault backup that still references it.
- **Pre-A24 builds must not open a sidecar vault:** old code ignores the new
  metadata and can drop attachment bytes on its next save. Upgrade notes must
  say this; the sidecars remain on disk for a restore, but the old vault won't
  reference them. Back up before downgrading.
- Export re-inlines sidecars, so a 50 MiB attachment can need several hundred
  MiB at peak. Add/preview also hold the file in RAM in this slice.
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
| A24b-lite | vault root/metadata, >5 MiB sidecar store, 50 MiB cap, UI add/read/delete, `.pvx` export re-inline, sync guard, tests | **done (~1 day)** |
| A24c | old inline migration, streaming UI, sync/P2P manifest + delta, delete-on-revoke, old-blob migration | 3–4 days |
| A24d | progress UI, missing-file UX, disk-full/antivirus QA, docs | 1 day |

## Decisions (resolved)

1. **50 MiB cap**, 10 attachments/item.
2. **No new dependency** (no ZIP/`PVX2` crate): `.pvx` stays the legacy
   encrypted blob; sync will use a custom manifest in A24c.
3. App size unchanged; the only added binary code is the ~500-line
   `attachment_store` module.
4. Sync/P2P guard is intentional until A24c; no silent attachment loss.
