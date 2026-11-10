# SESSION_STATE — PhantomVault (read me first)

> Short, current snapshot for a fresh agent/session. Deeper history lives in
> `docs/HANDOFF.md`; invariants live in `rules.md`; the agent contract lives in
> `AGENTS.md`. Keep this file under ~150 lines and update it at the end of every
> batch.

## Snapshot

| Field | Value |
|---|---|
| Date | 2026-11-10 |
| Branch / HEAD | `main` @ `a031f29` (A26 Bengali pass B1-B9) + scan docs (`a579032`) |
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
  1. extension B1/B2/B3 - `isTrusted` + closed shadow roots + no fixed ids;
  2. desktop reprompt D-1/D-2 - gate reveal, wire delete;
  3. native host B5 - fail closed, drop the argv bypass;
  4. persist auto-lock + clipboard TTL (D-3);
  5. crypto P2 `A-01`/`A-02`/`A-04`;
  6. CI - add `npm test` + `test:tokens`, use `-j 1`.

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
