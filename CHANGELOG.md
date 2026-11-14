# Changelog

All notable changes to PhantomVault. The format follows Keep a Changelog; the
project does not yet follow SemVer strictly (pre-1.0).

## Unreleased

### Container format (breaking)

- **A-03**: new containers are `PV4\0` and authenticate their header as AEAD
  associated data. A flipped magic, a swapped profile byte, a re-used salt or a
  wrapped DK / KEM ciphertext lifted from another container now fails the tag
  instead of being silently accepted. `PV2\0`/`PV3\0` vaults still open and are
  rewritten as v4 on the next save.
- **Compatibility:** a build older than this one cannot read a v4 container (it
  sees an unknown magic and reports "wrong password or corrupted file"). Every
  device that syncs the same vault must be updated together.

### Extension

- Firefox native messaging works: the host accepts the add-on id Firefox passes
  as `argv[1]`, allows the registered gecko ids through the origin gate, and the
  registration writes `allowed_extensions`. Not yet verified in a real Firefox.
- `PV_BREACH` no longer returns the vault-derived `reuse` count to a
  content-script sender. That count answers "how many stored items use this
  password", which turned the host into a vault-membership oracle for any
  candidate a page could guess; the in-page save prompt keeps only the public
  HIBP verdict. The popup (no sender tab) still gets it. An empty password is
  rejected before the native host is spawned.

### Desktop

- A failed export now reports in the UI instead of only on stderr (G3).
- The clipboard fallback verifies `set_text` and only clears a copy it still
  owns, so a failed copy no longer shows "Copied" (G4).
- Locking clears the "Undo last import" affordance together with the undo copy,
  so the button can no longer outlive its data (G7).
- A failed access-log append is counted and reported on stderr instead of being
  dropped silently (G8).
- The audit viewer now names the lost appends: its header says how many writes
  failed in this session, so a chain that reads "VALID" over a gap is no longer
  presented as complete (G8).
- Custom-field checkbox rows toggle in the editor instead of staying write-once
  (G2).
- The item detail pane has a logo button that opens the favicon picker, so a
  custom icon can be set without editing the vault file (G1).
- **Sync fork (G6):** a remote that fails the freshness check is no longer a
  dead end. The union merge is still previewed, prefixed with an explicit fork
  warning, and Apply merges **locally only** — the push is skipped so the other
  device's chain is not overwritten. The audit log records
  `merge forced (local only, push skipped)`.
- A staged merge (a full secret copy) is now dropped on lock, as its own comment
  already promised.


## 0.4.2 — 2026-11-12

Security and correctness pass from the 2026-11-10 scan
(`docs/SCAN_2026-11-10.md`).

### Extension

- Fill only on a real user gesture (`isTrusted`): a page can no longer focus its
  own field and dispatch a synthetic `mousedown`/`click` to make the vault fill
  it (B1/B2/B3).
- The OTP picker, the autofill dropdown and the Continue-as chip keep their rows
  in closed shadow roots; page script can no longer read vault titles/usernames
  from the page DOM (B1b).
- Vault reads are bound to the sender frame's registrable domain; `PV_LIST` and
  `PV_FETCH` are popup-only (B4).
- Shared-hosting tenants are separate sites (`evil.github.io` no longer matches
  a login saved on `victim.github.io`) (B10).
- Hotkey and context-menu fills always target the top frame (subframes have no
  engine since B8), instead of failing silently on a probed iframe.
- `clipboardRead` and the offscreen document are gone; content scripts run in
  the top frame only; `hook.js` is web-accessible on http(s) pages only
  (B8/B9). **Behaviour change:** embedded cross-origin login widgets are no
  longer autofilled or captured, and the extension can no longer clear its own
  clipboard copies — the native host still clears the copies it makes.

### Desktop

- A reprompt-armed login's hidden custom fields and linked-password field stay
  masked until the item is revealed.
- Master reprompt now gates reveal, delete, backup-code and custom-field copies,
  not just autofill/export (D-1/D-1b/D-2).
- Auto-lock and the clipboard TTL persist in `ui.prefs.json`; the shipped
  auto-lock default is 15 minutes instead of Never (D-3).
- Native-bridge liveness unseals the Hello token instead of stat-ing the file,
  and the bare `native-host` argv only works in debug builds (B5/B6).
- An open editor counts as activity, so auto-lock no longer fires mid-edit and
  discards an unsaved item. The sync-adoption path refuses to treat an
  unreadable local vault as empty (a PQ-paranoid vault cannot be overwritten).
- The loopback API requires `Host: 127.0.0.1|localhost|[::1]` and no `Origin`,
  and compares the token in constant time (B7).

### Crypto and storage

- The JSON envelope and the decrypted loader buffer are zeroized; the Argon2 key
  is wiped on every early return; `Vault`/`CachedLogin` have redacting `Debug`
  impls (A-01/A-02/A-04/A-11).
- Unreadable, oversized and newer-format containers are refused instead of
  silently resetting the revision chain, aborting on allocation, or being
  rewritten as an older version (A-05/A-06/A-10).
- `secure_write` removes its temp file on every path; PIN KDF parameters read
  from the sealed record are bounded; the access-log chain compare is
  constant-time (A-07/A-08/A-09).

### CI and tests

- `security.yml` runs the JS gates (`npm test`, `test:tokens`) and passes
  `-j 1` to check/clippy/test.
- `share_cli` TTL parsing and the Windows Hello decision table now have tests.

### Known limits

- A-03 (binding the container header as AEAD AAD) is deliberately open: it needs
  a container format bump and a migration path.
- Binaries are still unsigned (Authenticode); see `SECURITY.md`.
