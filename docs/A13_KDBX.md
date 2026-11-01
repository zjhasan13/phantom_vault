# A13 — KeePass KDBX interop

> Status: **import + export shipped.** A `.kdbx` file can be imported
> (previewed/merged) and the vault's logins can be exported to a KDBX4 file.
> The export is logins-only by design; cards/notes/identities stay in `.pvx`/CSV.

## What opens

| Feature | Support |
|---|---|
| KDBX 3.1 and 4.0/4.1 | yes (via the `keepass` crate) |
| KDF: Argon2, Argon2id, AES-KDF | yes |
| Outer cipher: AES-256-CBC, ChaCha20, Twofish | yes |
| Compression: gzip / none | yes |
| Password | yes (per-file password field) |
| Password + key file | API yes (`parse_kdbx(..., keyfile)`), **UI does not expose a key-file picker yet** |
| TOTP (`otp` field) | mapped through the same `apply_totp` path as XML |
| Custom string fields | mapped to `RawItem.custom_text` |
| Group hierarchy | folder path `Root / Child / ...` |
| Attachments / icons / entry history | **not imported** (same as the XML/CSV paths) |
| Recycled/deleted entries | imported as normal rows if the file's group layout contains them (same as XML) |

The decrypted model is mapped to the existing `RawItem` pipeline, so preview,
merge modes, duplicate handling and undo behave exactly like other imports.

## What is exported (slice 2)

"Export KeePass KDBX" in the export card writes a **KDBX 4** file (Argon2id
KDF, AES-256 outer cipher, gzip) with a **separate KDBX password** you enter in
the reprompt modal — never the vault master. Same 12+ character gate as `.pvx`.

| Vault field | KDBX mapping |
|---|---|
| Credential title / username / password | `Title` / `UserName` / `Password` (password protected) |
| First URL | `URL` |
| Notes | `Notes` |
| `totp_secret` | `otp` as `otpauth://totp/<percent-encoded title>?secret=…` |
| Custom text / checkbox fields | unprotected custom strings |
| Hidden custom fields | protected custom strings |
| `folder` (`A / B`) | nested groups under the `PhantomVault` root |
| Trashed credentials | skipped |
| Cards, notes, identities, passkeys, attachments | **not representable** in this export — use `.pvx`/CSV |

The export reuses the `keepass` crate's `save_kdbx4` writer; no KDBX
cryptography is hand-written here.

## Container crypto is not hand-rolled

The `keepass` crate (MIT, `keepass = 0.17`) performs the KDBX container
crypto: KDF, HMAC block stream, outer cipher, inner protected-value stream and
XML parsing. PhantomVault only:

1. checks the plaintext header/KDF parameters **before** the crate runs the
   KDF (`kdbx_kdf_guard`), and
2. maps the decrypted entries to `RawItem`.

This avoids new hand-written cryptographic code in the vault.

### KDF caps (hostile-file defense)

The KDBX header declares its own work factor. Before decrypting, the importer
refuses:

- Argon2 memory > **1 GiB**
- Argon2 iterations > **200 000**
- Argon2 parallelism outside **1–64**
- AES-KDF rounds > **20 000 000**
- unknown KDF UUIDs, missing parameters, truncated headers

A malicious `.kdbx` therefore cannot ask the import worker to allocate
gigabytes or spin forever.

## Dependencies and audit

- `keepass 0.17` (MIT) + `save_kdbx4` feature (the feature is what slice 2 will
  use to write; it is compiled today but unused).
- The crate brings its own `sha2 0.11`, `secrecy 0.10`, `quick-xml 0.42`,
  `aes`, `cbc`, `chacha20`, `twofish`, `rust-argon2`, `flate2`. Some duplicate
  versions coexist with the app's `sha2 0.10` / `secrecy 0.8` / `quick-xml
  0.41`; this is a size cost, not a correctness issue.
- `cargo tree -i rsa` and `cargo tree -i crypto-bigint` are still empty: the
  two RustSec advisories in `audit.toml` remain **not compiled**, unchanged by
  this dependency.

## Tests

Commands:

```powershell
cargo test kdbx
cargo test
```

Coverage:

- `kdbx4_decrypts_and_maps_entries` — synthetic KDBX4 written by the crate:
  protected password, custom field, TOTP, folder path, empty-entry skip.
- `kdbx4_wrong_password_is_a_clear_error` — "wrong password or key file",
  never a vague parse error.
- `kdbx_dispatch_needs_the_file_password` — sniffer → `parse_import_any`
  dispatch; no password is an explicit refusal.
- `real_keepassxc_kdbx4_aes_argon2_imports` and
  `real_keepassxc_kdbx4_chacha20_argon2id_imports` — real KeePassXC-generated
  fixtures (Argon2/AES, Argon2id/ChaCha20).
- `real_keepassxc_kdbx4_keyfile_requires_password_and_keyfile` — both factors
  mandatory.
- `kdbx_kdf_guard_caps_hostile_parameters` — memory/iteration/parallelism/AES
  round caps, unknown KDF, truncated header.
- `kdbx_export_roundtrips_logins_folder_totp_and_custom_fields` — vault →
  KDBX4 → importer returns the same title/user/password/URL/notes, nested
  folder, TOTP and custom fields (including a hidden one); a wrong password
  cannot open the exported file.

Fixtures and attribution: `tests/fixtures/keepass/README.md`.

## Honest limits

- **Export covers logins only.** Cards, secure notes, identities, passkeys and
  attachment bytes are not representable in the KDBX mapping; use `.pvx`/CSV
  for a full-fidelity move.
- Entry history, custom icons and recycle-bin semantics are not modeled;
  imports/exports are row-level.
- No key-file picker in the UI (the parser supports a key file; the export
  always uses a password).
- Fixtures come from the keepass-rs/KeePassXC test suite. A fresh round-trip
  against a locally installed KeePassXC is still manual QA.

## Next (optional hardening)

1. Key-file export / import picker.
2. Attachment mapping (KDBX4 binary pool).
3. Manual KeePassXC round-trip into the release checklist.
