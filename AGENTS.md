# AGENTS.md — PhantomVault

> Auto-loaded by OpenCode. Read this file, then **`docs/SESSION_STATE.md`**, before
> touching code. `docs/SESSION_STATE.md` is the short, current snapshot; this file
> is the contract you must not break.

## 1. What this project is

**PHANTOM VAULT** — a Windows-native, local-first, zero-knowledge password
manager written in Rust with a Slint desktop UI and a Chrome/Firefox WebExtension.
No Chromium, no Electron, no WebView inside the app.

- Repo: `zjhasan13/phantom_vault` (branch `main`). **Never delete, rename, or
  force-push `origin`.** Normal `git push origin main` only.
- App version: `Cargo.toml` / `browser_extension/manifest.json` (currently 0.4.1).
- Brand name is always **PHANTOM VAULT** (two words, all caps in UI).

## 2. Read order in a fresh session

1. `docs/SESSION_STATE.md` — current commit, gates, last batch, next move, traps.
2. `rules.md` — architecture/security invariants (non-negotiable).
3. Only then, the doc that matches the task:
   - UI/screens → `docs/UI_PARITY_MAP.md`
   - feature status → `docs/FEATURE_LEDGER.md`
   - long history / older batches → `docs/HANDOFF.md` (read only the relevant
     section; it is ~98 KB)
   - design tokens → `design/tokens.json`, `docs/UI_TOKENS.md`
   - specific subsystems → `docs/A13_KDBX.md`, `docs/A20_SEND.md`,
     `docs/A23_LOCAL_API.md`, `docs/A24_ATTACHMENTS.md`, `docs/A26_BN.md`

`docs/HANDOFF.md` still has legacy mojibake in places; do not mass-rewrite it.

## 3. Hard rules

- **Honesty over marketing.** Never add security claims you cannot point to code
  for. Banned: "AES-256-GCM" (we use XChaCha20-Poly1305), TPM/secure-enclave,
  quantum-immune, "0 ms", "0M leak", "enclave/cloud" chips, or any claim the
  threat model does not support.
- **Keep the user's visual identity**: Aegis palette (`design/tokens.json`),
  existing component names (`AuraButton`, `MonoChip`, `NavItem`, `FieldLabel`),
  existing logic. Refactor only the requested section.
- **Windows only.** No cross-platform abstractions, no new dependencies unless
  the user approves. Ask before adding a crate/npm package.
- **Secrets**: `zeroize` on drop, never log/print secrets, no `.unwrap()` in
  production paths (use `thiserror`).
- **Tests are part of the task.** A UI change is not done until it is seen on
  screen; a logic change is not done until tests cover it.

## 4. Commands (Windows, PowerShell)

```powershell
# build / check (use -j 1 to avoid Allocation failed on RAM-tight machines)
$env:CARGO_TARGET_DIR='C:\Users\<you>\pv-target'; $env:CARGO_INCREMENTAL='0'
cargo check -j 1
cargo build -j 1

# gates — all must be green before commit
cargo test -j 1
cargo clippy --all-targets -j 1 -- -D warnings
npm test
npm run test:tokens

# extension packaging (bumps nothing; see scripts/package_release.ps1)
powershell -File scripts/package_release.ps1
```

Expected green baseline is recorded in `docs/SESSION_STATE.md`. A "green" claim
must include the command output (counts/EXIT code), not just a sentence.

## 5. Definition of done

1. Code compiles and all four gates above pass.
2. For anything visual: unlock the dev build and capture a screenshot before and
   after. Use `scripts/dev/pv-ui-auto.ps1` (see its header). Attach/screenshot
   evidence in the final message.
3. Commit with a Conventional Commit subject (`style(ui):`, `feat(ext):`,
   `fix(ui):`, `docs:` …) and push.
4. **Update `docs/SESSION_STATE.md`** in the same commit or the next one:
   - new commit hash, gate results,
   - what shipped (feature ledger row if user-visible),
   - what is still pending/blocked,
   - any new trap/gotcha.
   Update `docs/FEATURE_LEDGER.md` when a user-visible capability is added,
   changed, or deliberately removed.

## 6. Slint layout gotchas (learned the hard way)

- **A `Rectangle` with no `height` takes its parent's height, not its content's.**
  For dialogs/sheets, give the content layout an id and bind
  `height: <layout>.preferred-height;`.
- **`ScrollView`/`TextEdit` report `preferred-height: 100%`.**
  (see `i-slint-compiler-<ver>/widgets/fluent/scrollview.slint`.) Inside a
  content-sized dialog, pin them with `min-height`/`max-height`/`preferred-height`.
- **A `HorizontalLayout` has no cross-axis alignment.** Children stretch to the
  full row height. Wrap the row in `VerticalLayout { alignment: center; }` and
  give the row a fixed height; wrap small buttons in their own centered
  `VerticalLayout`.
- `alignment` on a layout only affects its **main** axis.
- Never set `x`/`y` on children of a layout (compile error).
- `CheckBox` labels do not wrap; place them inside a layout with enough width.
- Nested layouts are stretchable: if a dialog grows, look for a nested layout or
  a `100%`-preferred child that is absorbing the extra space.

## 7. File map (start here, not exhaustive)

| Path | Purpose |
|---|---|
| `src/main.rs` | Slint callbacks, window wiring, most UI ↔ Rust glue |
| `src/windows_native/native_host.rs` | Native-messaging bridge for the extension |
| `src/security/offline_cache.rs` | Offline snapshot, DPAPI key, Hello/PIN gate |
| `src/storage/`, `src/storage.rs` | Encrypted vault format, backups |
| `src/importer/` | Import/export (`.pvx`, Bitwarden, CSV/KDBX) |
| `src/sync/` | GitHub/P2P/QR sync |
| `ui/appwindow.slint` | Entire desktop UI (large; grep for section comments) |
| `browser_extension/content.js` | Dropdown, save prompts, badges, fill logic |
| `browser_extension/popup.js` | Popup list, editor, HUD, hero card |
| `browser_extension/background.js` | Message routing, per-tab pending saves |
| `tests/js/*.test.mjs` | Extension gates (`npm test`) |
| `design/tokens.json` | Single source of colour/spacing tokens |

## 8. Known traps

- `share_serve::tests::served_share_is_one_view_and_revocable` is flaky under
  `-j 4`; run tests with `-j 1` (it passes alone).
- Linker may fail with `Allocation failed` when Chrome/RAM is tight. Close
  Chrome, retry; it is not a code error.
- Chrome steals focus during UI automation. `scripts/dev/pv-ui-auto.ps1` already
  uses `AttachThreadInput` + explicit `SetForegroundWindow`; do not replace it
  with a plain `SetForegroundWindow`.
- Do **not** call `ShowWindow(SW_RESTORE)` between coordinate reads and clicks —
  it can move/restore the window and invalidate every UIA rect. Read rects and
  click in the same process.
- The dev `phantom_vault.exe` writes to `%PHANTOM_VAULT_DIR%`; point it at a
  throwaway demo vault before UI automation.

## 9. Communication

- The user writes in Bangla. Reply in Bangla; keep identifiers, paths, commands,
  and commit subjects in English.
- State uncertainty explicitly. If something is not verified on screen or by a
  command, say so and say what is blocking it.
