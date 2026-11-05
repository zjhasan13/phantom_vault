# SESSION_STATE — PhantomVault (read me first)

> Short, current snapshot for a fresh agent/session. Deeper history lives in
> `docs/HANDOFF.md`; invariants live in `rules.md`; the agent contract lives in
> `AGENTS.md`. Keep this file under ~150 lines and update it at the end of every
> batch.

## Snapshot

| Field | Value |
|---|---|
| Date | 2026-11-05 |
| Branch / HEAD | `main` @ `171eb92` (pushed; `git ls-remote origin refs/heads/main` matches) |
| App version | 0.4.1 (`Cargo.toml`) |
| Extension version | 0.4.1 (`browser_extension/manifest.json`) |
| Installer present | `installer-output/PhantomVault-Setup-0.4.1.exe` (20,582,400 bytes) |
| Rust modules | 88 `.rs` files under `src/` |
| UI | one file: `ui/appwindow.slint` (~3.7k lines) |

## Last batch (2026-11-05) — shipped in `171eb92`

Four dialogs were content-sized and their headers fixed:

- 2FA import sheet (`ui/appwindow.slint:1983`, `:1989`)
- 2FA export sheet (`ui/appwindow.slint:1911`, `:1917`)
- master reprompt (`ui/appwindow.slint:3403`, `:3410`)
- vault health report (`ui/appwindow.slint:3661`, `:3668`, ScrollView `:3690`)

What was wrong (same for all four):

1. A `Rectangle` with no `height` takes its **parent's** height in Slint, so
   removing the old fixed heights made every dialog full-window.
2. `ScrollView`/`TextEdit` default to `preferred-height: 100%`, inflating the
   health list and the import paste box.
3. `HorizontalLayout` stretches children on the cross axis, so the 40px header
   icon filled the 76px header and crossed the rounded top border.

Fix pattern that should be reused for any new dialog:

```slint
Rectangle {
    width: 520px;
    height: body.preferred-height;      // content-sized, never full-window
    body := VerticalLayout {
        padding: 20px;
        padding-bottom: 24px;           // keeps the footer off the edge
        // pinned scroll areas:
        ScrollView { preferred-height: 240px; min-height: 64px; max-height: 240px; }
        // headers:
        VerticalLayout { alignment: center; padding-top: 6px;
            HorizontalLayout { vertical-stretch: 0; height: 40px; alignment: center; /* … */ }
        }
    }
}
```

Also in this area: the filter strip is centered and gained `Identity` +
`License` chips (`1aa3a70`), and the vault top bar / collapse controls were
centered (`a1f53f8`, `0c7ce6c`).

## Gates (last green run, 2026-11-05)

| Gate | Result |
|---|---|
| `cargo check -j 1` | `CHECK=0` |
| `cargo build -j 1` | `BUILD_EXIT=0` (~5 min) |
| `cargo test -j 1` | **569 passed, 0 failed, 4 ignored** |
| `cargo clippy --all-targets -j 1 -- -D warnings` | **EXIT=0** |
| `npm test` | **158/158 pass** |
| `npm run test:tokens` | **21 palette values OK** |

Run Rust gates with `-j 1`; see "Known traps".

## Next move (pick up here)

1. **Live end-to-end check** (needs the user):
   install `installer-output/PhantomVault-Setup-0.4.1.exe`, reload the unpacked
   extension, then walk: Continue-as fill, HUD hero, save prompt (reload / folder
   / notes / BN), offline cache + Windows Hello. The installed 0.4.0 build cannot
   talk to the 0.4.1 extension (bridge refuses), so this is blocked on install.
2. **HUD 3.0 full 640px dual-column** — only the hero card slice is shipped
   (`25008cc`, `09059bb`).
3. **SSH / License editor** in the popup (currently list + copy only, `b399b06`).
4. **Reuse hint in card/identity save prompts** (login prompt already has it,
   `b8ff022`).
5. **Responsive filter strip**: nine chips overflow when the window is narrow;
   consider wrapping or horizontal scroll.
6. **A26 Bengali pass**: remaining dialogs and Rust-generated status strings are
   still English (`docs/A26_BN.md`).
7. **Manual 100% / 125% layout pass** across all screens (no automated DPI test).
8. **Desktop auto-type fixes** — 34 findings (A1-A34) and 12 UX items are queued in
   `docs/AUDIT.md` §8 (code path) and §9 (popups, notifications, theme conformance,
   T1-T10). Start with A1-A4 (fail-open guard, password-focused field, card 3-vs-4
   Tab stops, multi-line SSH/note typing); all four are small and unit-testable.
   Static analysis only so far: nothing was reproduced on screen, and no gate has
   run on this tree.

## Recently shipped (newest first, ~15 commits)

```
171eb92 style(ui): content-size the four dialogs and center their headers
1aa3a70 style(ui): center the filter strip and add Identity/License chips
a1f53f8 style(ui): vertically center the top bar, collapse controls and list header
0c7ce6c style(ui): space the vault top bar and center the collapse controls
a1ac396 fix(ui): keep the recovery-shards checkbox inside the onboarding card
2d7a6f4 feat(ext): follow the EN/BN language setting in the save prompts
b8ff022 feat(ext): save prompt notes, reuse hint, card/identity parity + a11y
1d85034 fix(ui): drop explicit x/y from a CheckBox inside a HorizontalLayout
396b0ac feat(ext): at-risk flags on the save prompt (HIBP k-anonymity)
c4be27c feat(ext): build the save prompts inside closed shadow roots
7462714 feat(ext): editable title and URL on the save prompt
43a876d feat(ext): choose which existing login a save should update
41329b8 feat(ext): folder picker + close button on the save prompt
b69f8b6 feat(cache): phase 3 hardening (zeroize + sealed-timestamp freshness)
55fe343 feat(cache): keep the offline snapshot fresh and refuse stale reads
```

For the full history: `git log --oneline`. User-visible status per area lives in
`docs/FEATURE_LEDGER.md`.

## Environment bootstrap on a new PC

```powershell
git clone https://github.com/zjhasan13/phantom_vault.git
cd phantom_vault
npm install
$env:CARGO_TARGET_DIR='C:\Users\<you>\pv-target'
$env:CARGO_INCREMENTAL='0'
cargo build -j 1
npm test
```

- Toolchain: stable Rust (MSVC) on Windows 10/11 x64, Node 18+.
- The dev exe lands at `$env:CARGO_TARGET_DIR\debug\phantom_vault.exe`.
- `PHANTOM_VAULT_DIR` selects the vault directory (defaults to the repo/cwd).
- **Device-bound data does not migrate.** DPAPI keys (`*.dpapi`) and the offline
  cache/wrapped keys are machine-bound, so a copied demo vault will not unlock on
  another PC. Create a fresh vault by launching the app once and setting the demo
  password yourself.

## UI verification harness

`scripts/dev/pv-ui-auto.ps1` (dev-only, Windows) drives the built exe through
UI Automation + `mouse_event`:

```powershell
# 1. Start the app against a throwaway vault dir, unlock, screenshot
powershell -File scripts/dev/pv-ui-auto.ps1 -Action verify `
  -Exe "C:\Users\<you>\pv-target\debug\phantom_vault.exe" `
  -VaultDir "$env:TEMP\pv-ui" -Password "Demo-Pass-123!"

# 2. Other actions: dump | click -Arg "Label" | shot -Arg name.png |
#    wheel -Arg "x,y,notches" | navshot -Arg "Label,out.png" | twosheets
```

It prints `SHOT=<path>` lines and `STEP=... ALIVE=True` markers. Screenshots are
saved to `%TEMP%`.

Rules that make automation reliable:

- Set DPI awareness (`SetProcessDpiAwarenessContext(-4)`) before any
  `SetCursorPos`/`mouse_event`, in the same process.
- Query UIA rects and click in the same process; do not call
  `ShowWindow(SW_RESTORE)` in between (it moves the window).
- Slint exposes only `Text` nodes for buttons; click the text's bounding rect.
- Always screenshot immediately before claiming a visual fix.

## Known traps

- `share_serve::tests::served_share_is_one_view_and_revocable` flakes under
  `-j 4`; `-j 1` is stable.
- `Allocation failed` linker errors happen when RAM is tight (Chrome ~4 GB).
  Retry; it is not a code defect.
- `docs/HANDOFF.md` contains legacy mojibake. Read it, don't mass-rewrite it.
- `ui/appwindow.slint` has no per-screen files: grep for the section comments
  (`P0: filter strip`, `==== Master-reprompt`, `Vault Health Report`, …).
