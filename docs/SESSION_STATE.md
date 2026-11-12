# SESSION_STATE — PhantomVault (read me first)

> Short, current snapshot for a fresh agent/session. Deeper history lives in
> `docs/HANDOFF.md`; invariants live in `rules.md`; the agent contract lives in
> `AGENTS.md`. Keep this file under ~150 lines and update it at the end of every
> batch.

## Snapshot

| Field | Value |
|---|---|
| Date | 2026-11-11 |
| Branch / HEAD | `main` @ `b45969c` (closed shadow roots) + docs on top |
| App version | 0.4.1 (`Cargo.toml`) |
| Extension version | 0.4.1 (`browser_extension/manifest.json`) |
| Installer present | `installer-output/PhantomVault-Setup-0.4.1.exe` (20,582,400 bytes) |
| Rust modules | 88 `.rs` files under `src/` |
| UI | one file: `ui/appwindow.slint` (~3.8k lines) |

## Audit 2026-11-10 (docs only, no code change)

Full report: `docs/SCAN_2026-11-10.md`; appendices in `docs/scan/2026-11-10/`
(`A-crypto`, `B-ipc`, `C-gap`, `D-tests`).

- Gates re-run on `116f57a`: `cargo check -j 1` **EXIT=0** (6m29s),
  `npm test` **160/160**, `npm run test:tokens` **21**. `cargo test` /
  `clippy` were **not** re-run; 581 is a static reconciliation
  (585 test fns minus 4 ignored), not a fresh run.
- Highest-severity findings: **B1/B2** extension fills on a synthetic
  `mousedown`/`click` (no `isTrusted`; `content.js:1913`, `:2015`, `:2563`),
  **B3** TOTP picker is an open shadow root (`content.js:515`), **D-1/D-2**
  detail view reveals reprompt-armed secrets and `rp_action = 3` is never
  armed (`main.rs:11477`, `:11563`, `appwindow.slint:3199`), **B5** native-host
  allow-list fails open (`native_host.rs:141`, `:3371`).
- Fix order agreed 2026-11-10:
  1. ~~extension B1/B2/B3~~ — done `ecca87d` (closed roots left as B1b);
  2. ~~desktop reprompt D-1/D-2~~ — done `6d09f35`;
  3. ~~native host B5~~ — done `361b309` (Firefox origin still rejected, see SCAN);
  4. ~~persist auto-lock + clipboard TTL (D-3)~~ — done `d7c3e1f`;
  5. crypto P2 `A-01`/`A-02`/`A-04`;
  6. CI - add `npm test` + `test:tokens`, use `-j 1`.

## Last code batch (2026-11-12f) — `b45969c`

- **B1b**: the autofill dropdown and the Continue-as chip keep only an empty
  host in the page (same ids) and build their rows in a **closed** shadow root.
  Page script can no longer read vault titles/usernames via
  `getElementById("__pv_drop").innerText`. The skin moved too (`:host` root,
  scoped `.pvx-*`); outside-click still works because a closed root retargets
  events to the host.
- Badges stay light-DOM: they carry no vault text, and the click path is already
  isTrusted-gated.
- Gates: `npm test` **171/171**, `npm run test:tokens` **21**. No Rust change.
- Pending: a real-browser visual check (no extension E2E on this machine).

## Last code batch (2026-11-12e) — `ed804cf`

Test coverage for the two files the scan flagged as untested:

- `share_cli.rs` (589 lines, zero tests): `parse_ttl` now has three tests —
  units, trim/case, and the zero/junk/overflow rejects.
- `hello.rs` (88 lines, security boundary, zero tests): the WinRT result
  mappings are now pure functions (`availability_from` / `verification_from`),
  tested without a biometric device (Verified=true, Canceled=false,
  busy/policy/not-configured=error).
- Gates: full suite **607 passed, 0 failed, 4 ignored**; clippy
  `--all-targets -j 1 -- -D warnings` **EXIT=0** (13m43s).

## Last code batch (2026-11-12d) — `652abba`

- **A-07**: `secure_write` deletes its temp file on every path (RAII guard),
  and syncs the parent directory best-effort after the rename. No more `.tmp`
  litter after a failed save.
- **A-08**: the extension PIN record clamps `m/t/p` (8..=1 MiB KiB, 1..=16,
  1..=8) before `Params::new`, so a crafted record cannot ask for ~4 TiB.
- **A-09**: the access-log chain compare is constant-time (`subtle::ct_eq`).
- Gates: full suite **602 passed, 0 failed, 4 ignored**; clippy
  `--all-targets -j 1 -- -D warnings` **EXIT=0** (9m44s).
- **A-03** (no AAD on the container AEAD) stays open on purpose: it needs a
  container format bump + migration, and is not exploitable with today's
  header layout. It is the only open item from the A-series.

## Last code batch (2026-11-12c) — `84143e6`

- **A-05**: a transient container read error (AV/OneDrive) no longer looks like
  a first save — only `NotFound` does. Before, the rewrite used rev=1 + empty
  `prev_hash` and silently reset the anti-rollback chain.
- **A-06**: `metadata().len()` is checked against 64 MiB before `fs::read`; a
  corrupt multi-GB synced file fails cleanly instead of aborting on allocation.
- **A-10**: a container whose `meta.version` is above this build is refused
  (with a clear update message) instead of being parsed as v2 and rewritten.
- Gates: full suite **599 passed, 0 failed, 4 ignored**; clippy
  `--all-targets -j 1 -- -D warnings` **EXIT=0** (10m22s).

## Last code batch (2026-11-12b) — `f60b446`, `5d3f21e`

- **B6** (`f60b446`): `bridge_unlocked()` and the watchdog no longer trust
  `vault_hello.dpapi` existing — the blob must unseal to a non-empty passphrase
  (1 s cache; tests bypass it). An empty file recreated after a lock can no
  longer keep a running host serving.
- **B7** (`5d3f21e`): the local API now requires `Host: 127.0.0.1 | localhost |
  [::1]` and rejects any `Origin` (DNS-rebinding), before the token is read.
  `ct_eq` hashes both sides, removing the length early-return.
- Gates: full suite **595 passed, 0 failed, 4 ignored**; clippy
  `--all-targets -j 1 -- -D warnings` **EXIT=0** (8m27s).

## Last code batch (2026-11-12) — `54c3c74`

Crypto P2 from the scan (A-series):

- **A-01**: the JSON envelope and the decrypted loader buffer are `Zeroizing`,
  so save and every early return wipe the plaintext vault copy.
- **A-04**: every `?` between Argon2 and the payload AEAD (encapsulate,
  combine, wrap, unwrap, decapsulate) is an explicit match that zeroizes the
  derived key before returning.
- **A-02/A-11**: `Vault` and `CachedLogin` no longer derive `Debug`; both have
  redacting impls (counts / [redacted]) with regression tests.
- Gates: full suite **594 passed, 0 failed, 4 ignored**; clippy
  `--all-targets -j 1 -- -D warnings` **EXIT=0** (7m34s).
- Still open from A: A-03, A-05, A-06, A-07, A-08, A-09, A-10.

## Last code batch (2026-11-11e) — `52696c4`

- **B10**: `domain.js` now knows the PSL private-section suffixes users meet
  (github.io, pages.dev, web.app, netlify.app, herokuapp.com, workers.dev, …),
  so two tenants of a shared suffix are different sites. Before, a login saved
  on `victim.github.io` was offered on `evil.github.io`.
- Test: two tenants stay distinct; registry suffixes (co.uk) unchanged.
- Gates: `npm test` **171/171**, no Rust change.

## Last code batch (2026-11-11d) — `19b5ac8`, `019b70b`

- **D-1b** (`19b5ac8`): backup codes, text/hidden/linked custom fields now copy
  through `copy_detail_extra`, which arms the master modal (action 1) for a
  reprompt-armed login. Peep-hole keeps the codes masked until the item is
  revealed. New predicate `detail_copy_needs_reprompt` + unit test.
- **CI** (`019b70b`): `security.yml` runs `npm ci` + `npm test` +
  `npm run test:tokens` and passes `-j 1` to check/clippy/test.
- Gates: full suite **592 passed, 0 failed, 4 ignored**; `cargo clippy
  --all-targets -j 1 -- -D warnings` **EXIT=0** (14m46s); `npm test` 170/170;
  tokens 21.

## Last code batch (2026-11-11c) — `7945ea1`

- **B4**: `PV_QUERY`, `PV_TOTP_LOOKUP`, `PV_CARDS` and `PV_IDENTITIES` now
  require `app` to match the sender frame registrable domain; `PV_LIST` and
  `PV_FETCH` are popup-only. The popup has no `sender.tab` and is unchanged.
- 5 new JS tests: own domain, cross-domain refusal, popup, popup-only, TOTP.
- Gates: `npm test` **170/170**, `npm run test:tokens` **21**. No Rust change,
  so cargo gates were not re-run (last run: 591 passed, clippy 0).
- Edge: a frame with no http(s) origin (file://, about:blank) is now denied —
  there is no domain to bind the read to.

## Last code batch (2026-11-11b) — `d7c3e1f`

- **D-3**: `src/prefs.rs` persists `auto_lock_mins` + `clipboard_secs` to
  `ui.prefs.json` (tmp+rename, clamped, corrupt file -> defaults). Startup
  seeds the atomics and the Slint properties; both Settings handlers save.
  The shipped default is now **15 minutes** instead of Never, so a
  hidden-to-tray vault actually locks.
- Close-to-tray behaviour is unchanged; the idle timer now runs while hidden.
- Gates: `cargo test -j 1 prefs` 4/4; full suite `--test-threads=1` **591 passed,
  0 failed, 4 ignored**; `cargo clippy --all-targets -j 1 -- -D warnings`
  **EXIT=0** (11m17s). Two flakes seen and re-run clean:
  `api::local::…loopback…` (os 10053) and `crypto::…test_legacy_v2_still_opens`
  under memory pressure — both pass alone.

## Last code batch (2026-11-11) — `6d09f35`, `361b309`

Two scan batches landed:

- **D-1/D-2** (`6d09f35`): the detail eye no longer flips a Slint property.
  Hiding is free; revealing a reprompt-armed login arms `rp_action 6` and only
  the verified master password sets `d_secret_visible`. The detail password
  copy now goes through `quick_copy(kind, id)` (same gate). Delete of an armed
  login arms `rp_action 3` and re-enters the existing delete arm.
  New pure predicate `reveal_needs_reprompt` + unit test.
- **B5** (`361b309`): `origin_allowed` fails closed when `native-host.json` is
  missing/empty (it returned `true`), and the bare `native-host` argv only
  bypasses the check in debug builds. Pure `origin_allowed_in` + 3 tests.
- Gates: `cargo check -j 1` EXIT=0, `cargo test -j 1` **586 passed / 1 failed**
  (`api::local::tests::loopback_get_waits_…`, os error 10053 — passes alone,
  flaky like the documented `share_serve` case), 4 ignored. `npm test` 165/165
  and tokens 21 unchanged (JS untouched). `cargo clippy --all-targets -j 1 -- -D`
  `warnings` EXIT=0 (13m12s).
- Residual: `valid_origin_format` rejects `moz-extension://…`; Firefox bridge
  support is therefore unproven. Remove or solve that before claiming it.

## Last code batch (2026-11-10) — `ecca87d`

Extension fill is now gesture-gated (scan B1/B2/B3): a page can no longer focus
its own password field and dispatch a synthetic `mousedown`/`click` at the
dropdown row, the shield/dice badge, the Continue-as chip or the OTP picker row
to make the vault fill that field.

- `content.js`: `isTrusted` on every fill handler; the dropdown Enter path calls
  `onPick` directly (no synthetic `mousedown`); the OTP picker shadow root is
  `mode: "closed"`, so the live code is no longer page-readable.
- `tests/js`: 3 security tests that dispatch real (untrusted) events and assert
  no fill, plus a harness listener spy (`fireTrusted`) so user-path tests still
  run the same handlers.
- Gates: `npm test` **165/165**, `npm run test:tokens` **21**, `cargo check -j 1`
  **EXIT=0** (3m55s). `cargo test`/`clippy` not re-run — no Rust file changed.
- Follow-up **B1b**: the dropdown and badges are still light-DOM, so a page can
  read their row titles/usernames. Moving the hosts into closed shadow roots is
  the remaining hardening step and needs a real browser check.

## Where the Bengali (A26) work stands

**Every desktop surface we own is Bengali.** Coverage landed in nine batches:

| Batch | Commit | What it covered |
|---|---|---|
| B1 | `a486f85` | main dialogs (import/dup/factory/new-PC/attachment/changelog/access-log/shred/health) |
| B2 | `119934f` | Rust status toasts + `VaultError::localized()` (Auto-Type payloads) |
| B3 | `17c6dc9` | main screen (sidebar, chips, counters, empty pane, nudge, travel) + proof-strip fit |
| B4 | `58104f5` | Settings page, 6 tabs / 196 strings + `tog()` ON-OFF chips |
| B5 | `766f5b5` | item detail pane + `ago()` / password-strength helpers |
| B6 | `be741cf` | 138 plain Rust statuses + 69 `{e}` templates + 26 inline templates |
| B7 | `c7e71ac` | 15 arg-based `format!` templates + Rust-set defaults |
| B8 | `d649bb8` | Settings fits the 960 logical px minimum + 9 missed labels |
| B9 | `4eec7e9` | add/edit form (placeholders, helper lines, URL rule, checkboxes, Save/Cancel) |

How the switch works:

- Slint: `root.ui_lang == "bn" ? "বাংলা" : "English"` inline ternaries.
- Rust: `i18n::tr("EN", "BN")` backed by a process-wide flag; `i18n::is_bn()`.
- `lang.pref` (in the vault dir) persists the choice; `lang.pref` = `bn` is how
  the dev harness starts in Bengali.
- Deliberately English: mono/brand chips (`ZERO-KNOWLEDGE`, `RAM-SAFE`,
  `LOCAL VAULT`, `DPAPI BOUND`, `ARGON2ID 64 MiB`, `READY`, `ENCLAVE MODE`,
  `PORTABLE`, `LOCAL-FIRST`), vendor/protocol names (`Windows Hello`, `TPM`,
  `OIDC`, `PAT`, `PowerShell`, `Bash`, `Nushell`, `Addy.io`, `SimpleLogin`,
  `base64`, `hex`, `RP:`), data values (folder names), and the EN/BN toggle.
- Never translated: technical payloads interpolated into errors (COM/serde/OS).

**Remaining A26 work: none known.** If you find an English string the user can
see (outside the "deliberately English" list above), that is a bug — add it the
same way (`(root.ui_lang == "bn" ? "…" : "…")` for Slint, `tr("…", "…")` for
Rust) and extend `docs/A26_BN.md`.

## Last code batch (2026-11-09) - `4eec7e9`

B9 = the add/edit form: item-name/tags/otpauth/website placeholders, the
"typed text stays" warning, the generator hint, `+ Add website`,
`SECRET KEYS / API TOKENS`, `+ Add Custom Field`, the re-prompt / favourite /
travel-safe checkboxes, the Save / Cancel row, the URL-rule cycle button
(Auto/Base/Host/Exact/Prefix/Never) and the inline "Sure?" deletes — plus the
form's Close button.

Evidence: `%TEMP%\pv-bn-form.png` (form open, all Bengali). Earlier batches'
screenshots: `pv-bn-100-main.png`, `pv-bn-100-narrow.png`, `pv-bn-detail8.png`,
`pv-bn-set-*.png`, `pv-bn-set-960.png`, `pv-bn-dev-defaults3.png`,
`pv-bn-status-ssh.png`.

## Gates (last green run, 2026-11-09)

| Gate | Result |
|---|---|
| `cargo check -j 1` | `CHECK=0` |
| `cargo build -j 1` | `BUILD_EXIT=0` (~5 min) |
| `cargo test -j 1` | **583 passed, 0 failed, 4 ignored** |
| `cargo clippy --all-targets -j 1 -- -D warnings` | **EXIT=0** |
| `npm test` | **162/162 pass** |
| `npm run test:tokens` | **21 palette values OK** |

Run Rust gates with `-j 1`; see "Known traps".

## Next move (pick up here)

1. **Live end-to-end check** (needs the user): install
   `installer-output/PhantomVault-Setup-0.4.1.exe`, reload the unpacked
   extension, then walk: Continue-as fill, HUD hero, save prompt (reload /
   folder / notes / BN), offline cache + Windows Hello. The installed 0.4.0
   build cannot talk to the 0.4.1 extension (bridge refuses), so this is
   blocked on install.
2. **HUD 3.0 (640px dual-column) — DECLINED (user, 2026-11-07).** Keep HUD
   2.0's list → separate detail page. Do not build the dual-column layout.
3. **Extension item view + edit — complete** (`0b7e0c6`, `1cf5c6d`).
4. **A26 Bengali pass — complete** (B1–B9 above). New strings must follow the
   same rule; see `docs/A26_BN.md`.
5. **Layout QA still manual**: at 125% DPI the main screen and Settings were
   verified at the default width and at the 960 px minimum; the **item detail
   at 960 px** and the **add/edit form at 960 px** were not captured. Note
   `SLINT_SCALE_FACTOR` does not scale text in Slint 1.18, so it cannot
   simulate another DPI.
6. **Desktop auto-type fixes — complete.** A1–A34 + T1–T10 are fixed or
   documented in `docs/AUDIT.md` §8/§9; the `Status` column is authoritative.
   A1/A2/A5/A9/A10/A23/A24 still need a live target app.
