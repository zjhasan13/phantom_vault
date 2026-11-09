# SESSION_STATE — PhantomVault (read me first)

> Short, current snapshot for a fresh agent/session. Deeper history lives in
> `docs/HANDOFF.md`; invariants live in `rules.md`; the agent contract lives in
> `AGENTS.md`. Keep this file under ~150 lines and update it at the end of every
> batch.

## Snapshot

| Field | Value |
|---|---|
| Date | 2026-11-09 |
| Branch / HEAD | `main` @ `c7e71ac` (BN arg-templates B7) |
| App version | 0.4.1 (`Cargo.toml`) |
| Extension version | 0.4.1 (`browser_extension/manifest.json`) |
| Installer present | `installer-output/PhantomVault-Setup-0.4.1.exe` (20,582,400 bytes) |
| Rust modules | 88 `.rs` files under `src/` |
| UI | one file: `ui/appwindow.slint` (~3.7k lines) |

## Last code batch (2026-11-09) - `c7e71ac`

B7 = the Rust leftovers from B6. 15 `format!` templates with explicit arguments
(17 sites) branch on `i18n::is_bn()` (Auto-Type, save/delete/restore failures,
QR scan/parse, import numbers, download progress, page counterâ€¦). The two
Rust-set Slint defaults are localized at startup and on language switch while
they still hold an untouched default: `ssh_status` (`à¦¯à¦¾à¦šà¦¾à¦‡ à¦¹à¦¯à¦¼à¦¨à¦¿`) and
`health_status`/`health_headline` (`à¦à¦–à¦¨à§‹ à¦…à¦¡à¦¿à¦Ÿ à¦¹à¦¯à¦¼à¦¨à¦¿à¥¤`).

Verified on screen: Dev & API shows `à¦à¦–à¦¨à§‹ à¦…à¦¡à¦¿à¦Ÿ à¦¹à¦¯à¦¼à¦¨à¦¿à¥¤` and `à¦¯à¦¾à¦šà¦¾à¦‡ à¦¹à¦¯à¦¼à¦¨à¦¿`
(`pv-bn-dev-defaults3.png`).

A26 is now complete except: the Settings rows that overflow ~20 logical px at
the 960 px minimum window (responsive pass), and a handful of add/edit-form
labels. No Rust status string is knowingly left in English.
## Previous batch (2026-11-09) - `be741cf`

B6 = Bengali Rust statuses. 138 plain statuses (156 sites) go through `tr()`,
69 `format!("â€¦{e}")` error templates localize only their text (technical
payloads stay), and 26 inline-capture templates switch on `i18n::is_bn()`
(canary trip, breach warning, emptied trash, auto-lock countdown, honeytoken,
import counts, leak scanâ€¦).

Verified on screen: Dev & API secret scan shows
`ðŸš¨ à¦¸à§à¦•à§à¦¯à¦¾à¦¨ à¦¸à¦®à§à¦ªà¦¨à§à¦¨: 918à¦Ÿà¦¿ à¦¸à¦®à§à¦­à¦¾à¦¬à§à¦¯ à¦¸à¦¿à¦•à§à¦°à§‡à¦Ÿà¥¤ à¦Ÿà¦¾à¦°à§à¦®à¦¿à¦¨à¦¾à¦² à¦²à¦— à¦¦à§‡à¦–à§à¦¨à¥¤`
(`pv-bn-status-ssh.png`).

Still English: ~35 `format!` templates with explicit args, a few Rust-set Slint
defaults (`ssh_status`, `health_headline`), the Settings rows that overflow at
960 logical px, and some add/edit-form labels.
## Previous batch (2026-11-09) - `766f5b5`

B5 = Bengali item detail pane. The right pane (labels, diagnostic tiles,
storage/history/tags, trash + stale warnings, Open URL/Share/Close/Check/Copy)
follows `ui_lang`, and two shared Rust helpers now localize:

- `models::ago()` -> `à¦à¦‡à¦®à¦¾à¦¤à§à¦°` / `à§© à¦¦à¦¿à¦¨ à¦†à¦—à§‡` / `à§¨ à¦®à¦¾à¦¸ à¦†à¦—à§‡` (feeds every list row,
  the detail meta line and the credential age).
- `core::password_strength::{label,detail}` -> `à¦®à¦¾à¦à¦¾à¦°à¦¿ â€¢ 20 à¦…à¦•à§à¦·à¦° â€¢ à¦‡à¦‰à¦¨à¦¿à¦•`,
  `à¦¦à§à¦°à§à¦¬à¦²/à¦¶à¦•à§à¦¤à¦¿à¦¶à¦¾à¦²à§€/à¦šà¦®à§Žà¦•à¦¾à¦°`, `Nà¦Ÿà¦¿ à¦†à¦‡à¦Ÿà§‡à¦®à§‡ à¦ªà§à¦¨à¦°à¦¾à¦¬à§ƒà¦¤à§à¦¤`, `à¦°à§‹à¦Ÿà§‡à¦Ÿ à¦•à¦°à§à¦¨`.

Still English: the Rust status tail (`set_sync_status`, `set_notification_text`,
`format!` variants - ~250 literals), a few Rust-set Slint defaults
(`ssh_status`, `health_headline`), and the Settings rows that overflow ~20
logical px at the 960 px minimum.

Evidence: `pv-bn-detail8.png` in `%TEMP%` (list row "3 à¦¦à¦¿à¦¨ à¦†à¦—à§‡", tiles, copy chip).
## Previous batch (2026-11-09) - `58104f5`

B4 = Bengali Settings page. All six tabs follow `ui_lang` (196 literals), the
15 ON/OFF chips render as `à¦šà¦¾à¦²à§`/`à¦¬à¦¨à§à¦§` via a new `tog(on)` helper, and the
Rust "missing credentials" + "Windows Hello unavailable" lines go through
`tr()`. Tab widths were re-tuned for the 960 logical px minimum.

Known limit: at 960 logical px a few Settings status rows still overflow ~20
logical px (`pv-bn-set-960.png`); the tab row itself fits. Next layout task is
stacking those rows. The long tail of Rust statuses (~250 literals) and the
item-detail diagnostic tiles are still English.

Evidence: `pv-bn-set-{sec,sync,priv,rec,bak,dev}.png` and `pv-bn-set-960.png` in
`%TEMP%`.
## Previous batch (2026-11-09) - `17c6dc9`

B3 = Bengali layout pass. Main screen is now fully Bengali; the pass found one
real layout bug: the item detail "proof strip" is a single non-wrapping row
whose minimum width (~600 logical px) pushed the pane past the window edge at
the default 1185 logical px, cutting the last chip. The two middle chips are
hidden below 1300 logical px. Harness gained a verified `Unlock` (retry), a
narrow capture at 960 logical px, and `bnmeasure` (UIA rect dump).

Evidence: `pv-bn-100-main.png`, `pv-bn-100-narrow.png` (960 logical),
`pv-bn-detail5.png` (1185 logical, detail open), `pv-bn-100-settings.png`,
`pv-bn-100-health.png` in `%TEMP%`. Below `min-width: 960px` the 3-column
shell overflows on purpose; do not "fix" screenshots taken below it.

## Older batch (2026-11-07) - `4a38695`

The auto-type/popup audit is complete: A1-A34 + T1-T10 fixed/documented, with
A33 landing last (secrets removed from `CredentialView`). `cargo test` 581,
tokens 21. Details: `docs/AUDIT.md` "Fix batch 1-12". Next work is the
non-audit queue (live 0.4.1 E2E, HUD 3.0, SSH/License editor, reuse hint,
responsive filter strip, A26 BN, DPI pass). Details: `docs/AUDIT.md` §9 "Fix batch 1".

## Previous batch (2026-11-05) — shipped in `171eb92`

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
| `cargo test -j 1` | **583 passed, 0 failed, 4 ignored** |
| `cargo clippy --all-targets -j 1 -- -D warnings` | **EXIT=0** |
| `npm test` | **162/162 pass** |
| `npm run test:tokens` | **21 palette values OK** |

Run Rust gates with `-j 1`; see "Known traps".

## Next move (pick up here)

1. **Live end-to-end check** (needs the user):
   install `installer-output/PhantomVault-Setup-0.4.1.exe`, reload the unpacked
   extension, then walk: Continue-as fill, HUD hero, save prompt (reload / folder
   / notes / BN), offline cache + Windows Hello. The installed 0.4.0 build cannot
   talk to the 0.4.1 extension (bridge refuses), so this is blocked on install.
2. **HUD 3.0 (640px dual-column) — DECLINED (user, 2026-11-07).** Keep HUD 2.0's
   list → separate detail page: a 420px popup gives the item full width, and the
   list→detail pattern matches Bitwarden's own extension. Do not build the
   dual-column layout.
3. **Extension item view + edit — complete (`0b7e0c6`, `1cf5c6d`).** Every row
   opens a read-only view (masked secrets, folder, 2FA) with **Edit / Fill /
   Close**; the editor now covers login/note/card/identity **and SSH/License**
   (bridge kinds 6/7, Add chooser included). Nothing left in this gap.
4. **Reuse hint in card/identity save prompts — done (`da1de56`)**: an "also in
   N other item(s)" chip when the PAN / email is already stored elsewhere.
5. **Responsive filter strip — done (`a4c2bfc`)**: chips are 68px; below 1100
   logical px the strip becomes a two-row 5-column grid so all nine stay visible.
6. **A26 Bengali pass - B4 Settings done (`58104f5`).** Main screen (B3) and all
   six Settings tabs are Bengali. Remaining: the item-detail diagnostic tiles,
   ~250 Rust status literals (`set_sync_status` / `set_notification_text` /
   `format!` variants), and a few Rust-set Slint defaults.
7. **Layout pass at 125% DPI - done for the main screen (`17c6dc9`).**
   Still to look at manually: Settings, add/edit form, and the item detail at the
   960 px minimum width. Note `SLINT_SCALE_FACTOR` does not scale text in Slint
   1.18, so it cannot simulate another DPI.
8. **Desktop auto-type fixes — complete.** A1-A34 + T1-T10 are fixed or
   documented in `docs/AUDIT.md` §8/§9 (batches 1-12: `3b1fc92`, `6b095fc`,
   `b4ec6d0`, `1cf999a`, `34048fb`, `d76c34c`, `1a82614`, `2b2f81b`,
   `be545f0`, `b63455c`, `1c03520`, `6d3aac5`, `4a38695`; +12 tests,
   `cargo test` 581). The `Status` column is authoritative. Still needs a live
   target app / person: A1/A2/A5/A9/A10/A23/A24 were verified by code inspection
   (A21 capture focus, A29, A23 and A24 were also checked on screen).

## Recently shipped (newest first, ~15 commits)

```
1c03520 style(ui): put the popups on the Aegis token scale and name them for a11y
b63455c fix(autotype): stop the watcher on lock, keep decoy fills out of real stats, and stop stealing focus
be545f0 fix(ui): make popup drag 1:1 and raise popups reliably before focus-watching
2b2f81b fix(ui): auto-hide popups on focus loss and let them be dragged
1a82614 fix(autotype): make UIA work on the UI thread, stop inventing usernames, log aborts
d76c34c fix(autotype): stop guessing the form, guard the focused control and verify the Tab stop
34048fb fix(ui): give auto-type notifications a tone and keep critical alerts visible
1cf999a fix(autotype): verify UIA writes and make the 2FA watcher cancellable
b4ec6d0 fix(autotype): reject card CVV as OTP, focus the quick windows and reset their state
6b095fc fix(autotype): freeze the target after the minimize settles and keep the typed username
3b1fc92 fix(autotype): fail closed on missing context, password focus, multi-line and card stops
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
