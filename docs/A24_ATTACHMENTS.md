# A24 — chunked, separately encrypted attachments

> Status: **A24a–d shipped.** Files over 5 MiB are stored as `PVAB1` sidecars
> (vault saves no longer re-encrypt attachment bytes); GitHub and P2P sync both
> transfer sidecars; deletes leave tombstones for remote cleanup; a Settings
> action migrates legacy inline attachments; download streams to disk and
> preview is capped at 8 MiB. No new dependencies; app size impact is code-only.
> A 50 MiB sidecar roundtrip is covered by an ignored manual test; live sync
> calls still need a token/peer.

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
- The add path stats the file and streams >5 MiB through `write_sidecar`
  (1 MiB chunk buffers), so the whole file is not held in RAM.
- The add path writes the sidecar first, then saves the vault metadata; if the
  vault save fails, the in-memory snapshot is restored and the new sidecar is
  deleted. A crash between the two leaves an orphan sidecar (safe; no metadata).
- Sidecar reads decrypt into RAM for preview/download; delete removes the sidecar
  only after the vault save succeeds.
- Missing sidecar on read → explicit “attachment file is missing — restore it
  from a backup”; never return empty bytes.
- **A24d migration (implemented):** Settings → Attachment storage →
  “Move inline to encrypted sidecars” clones the vault, writes every non-empty
  inline attachment to a sidecar, then saves; a failure restores the in-memory
  snapshot and removes the newly written files. Legacy `att<millis>` ids are
  remapped to hex. The action is explicit, not automatic.
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

## Sync/P2P (A24c)

- **GitHub sync (implemented):** encrypted sidecars are uploaded to
  `attachments/<id>.pvab` **before** the `vault.enc` push, so a failure cannot
  publish a vault that references a missing file. Existing remote ids are
  skipped (immutable per-attachment content). Pulls list the remote directory
  and download every sidecar that is missing locally **before** adopting the
  vault. Delete tombstones (`attachments/.deleted`) remove remote ids on the
  next push.
- **P2P (implemented, A24d):** the paired/signed channel gains
  `GET /p2p/attach/list`, `GET|POST|DELETE /p2p/attach/<id>`. `sync_with_peer`
  reconciles sidecars after the vault (pull missing, push new, process local
  tombstones) and reports `attachments ↓n ↑n`. A 50 MiB sidecar travels as
  base64 JSON, so the HTTP body cap is 80 MiB and memory peaks higher. An older
  peer without the endpoints lists zero attachments; vault sync still works
  when there are no local sidecars. If local sidecars exist, the attachment
  push fails loudly and the user must update the peer.
- **Old-inline migration (implemented):** Settings action described above.
- **CRDT merge:** two different attachment roots are refused rather than
  dropping one side.
- Orphans: a remote sidecar may remain after a delete on another device; it is
  ciphertext with a random id and harmless. A manifest/revision is future work.

## UI (A24b-lite + A24c, implemented)

- File picker title says “max 50MB; >5MB stored separately”; >5 MiB files are
  streamed to a sidecar (no whole-file RAM hold).
- ≤5 MiB files keep the inline path; preview/download resolve inline bytes or
  decrypt the sidecar; delete removes the sidecar after the vault save and
  records a remote-delete tombstone.
- **Download streams** the sidecar to a temp file next to the destination and
  renames it; a 50 MiB export no longer holds the whole file in RAM.
- **Preview is capped at 8 MiB**; larger files show “Too large to preview —
  use Export”.
- Settings shows inline/sidecar counts and offers the explicit migration
  action.
- Missing sidecars surface an explicit error.

## Tests

- A24a (done): format roundtrip, empty, wrong root/id, tamper, reorder,
  oversized/over-long, temp cleanup.
- A24b-lite (done): root generation + fail-closed missing root, sidecar export
  inlining roundtrip, `dir_has_sidecars`; existing vault/storage tests still
  pass with the new defaulted fields.
- A24c (done for GitHub/streaming): strict remote attachment paths, sidecar
  file discovery, delete tombstone roundtrip, add-streaming path exercised by
  the `PVAB1` reader/writer tests. Live GitHub calls are not unit-tested (no
  token in CI); they use the same octocrab client and error mapping as sync.
- A24d (done): loopback P2P attachment list/pull/push/delete over the real
  paired/signed channel; inline→sidecar migration keeps bytes; download
  streaming helper; preview cap. A 50 MiB `PVAB1` roundtrip is an ignored test
  (`cargo test fifty_mib -- --ignored`, ~39 s) and passed locally.
- Manual QA still required: 50 MiB `.pvx` export/import, lock mid-migration,
  disk-full, antivirus-locked file, 100%/125% layout.

## Honest limits / non-goals

- **Existing inline attachments require the Settings migration action**; they
  are not moved automatically.
- Pull downloads remote sidecars that are missing locally **before** adoption;
  ids with a local delete tombstone are skipped. A per-vault manifest would
  avoid downloading unrelated orphans.
- Remote delete is best-effort via tombstones; another device can re-upload a
  sidecar it still has. There is no cross-device tombstone reconciliation yet.
- **P2P sidecars travel as base64 JSON** with an 80 MiB body cap; a 50 MiB
  attachment peaks at several hundred MiB of RAM. GitHub uses one file per id.
- Export re-inlines sidecars, so a 50 MiB `.pvx` export can still need several
  hundred MiB; add/download stream, preview is capped at 8 MiB.
- **Vault `.bak` rotation does not include sidecars.** A `.bak` restore only
  works with the `attachments/` folder from the same point in time; `.pvx`
  export is the self-contained backup. Deleting a sidecar cannot be undone by
  restoring a vault backup that still references it.
- **Pre-A24 builds must not open a sidecar vault:** old code ignores the new
  metadata and can drop attachment bytes on its next save. Upgrade notes must
  say this; the sidecars remain on disk for a restore, but the old vault won't
  reference them. Back up before downgrading.
- Export re-inlines sidecars, so a 50 MiB attachment can need several hundred
  MiB at peak.
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
| A24c | GitHub sidecar push/pull + tombstones, streaming add, strict remote paths | **done (~1 day)** |
| A24d | Settings migration, P2P list/pull/push/delete, download streaming, preview cap, 50 MiB roundtrip test | **done (~1.5 days)** |

## Decisions (resolved)

1. **50 MiB cap**, 10 attachments/item.
2. **No new dependency** (no ZIP/`PVX2` crate): `.pvx` stays the legacy
   encrypted blob; GitHub sync uses one remote file per sidecar id.
3. App size impact is code-only (the `attachment_store` module + a few sync
   calls); no new crate, asset or bundled dependency.
4. Both GitHub and P2P transfer sidecars; P2P uses paired/signed endpoints and
   an 80 MiB JSON cap.
