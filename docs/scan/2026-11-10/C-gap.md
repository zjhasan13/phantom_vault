# PhantomVault — UI ↔ backend gap report (`C-gap`)

**Repo:** `C:\Users\Admin\Desktop\New folder\dekstop app\phantom_vault`
**HEAD at scan time:** `116f57a` (2026-11-07) — working tree clean except untracked `.zwork/`
**Scan date:** 2026-11-10
**Mode:** read-only. No repo file was modified; scratch scripts live in `%TEMP%\pv-scan\`.

## Method (and its limits)

| Question | How I answered it |
|---|---|
| Callback → handler map | Parsed all `callback <name>(` declarations in `ui/appwindow.slint`, normalised `foo-bar` → `foo_bar`, matched against every `.on_<name>(` in `src/main.rs`. Bodies extracted by brace matching, then classified (empty / toast-only / real). |
| Dead capabilities | (1) Call-site count for all 594 `pub fn` in `src/`; (2) name-based call graph rooted at `fn main` to find `pub fn` not reachable from `main`; (3) count of callback *invocations* inside the `.slint` file (declaration ≠ call site). |
| Swallowed failures | Filtered the 689 `let _ =` / 30 `.ok();` / 111 `if let Ok(..)` sites down to ones whose expression touches save/delete/lock/clipboard/key/sync/log, then read each in context. |
| Ledger vs reality | Took `docs/FEATURE_LEDGER.md` rows, walked each to its callback and backend entry point, and checked that the backend does what the row says. |
| Logic gaps | Read the full lock path, unlock path, trash path, sync push/pull, auto-lock ticker, save-prompt classifier. |

**Limit that matters:** I did **not** build or run the app. Every "reachable" judgement is static (call site exists and the UI element that fires it exists). Nothing here is a runtime observation, and no gate (`cargo test`) was re-run.

---

## TL;DR — five gaps that matter

1. **The reprompt gate is half-wired.** Autofill and export are gated; the **delete-with-reprompt arm exists but is never armed** (`rp_action = 3` has no writer), and **reveal** is a pure Slint property flip with no Rust path and no audit entry.
2. **Auto-lock and clipboard-clear settings are memory-only.** Restart the app and "1m auto-lock" is back to **Never**; the clipboard timer silently returns to 15 s.
3. **The auto-lock idle clock is fed by a handful of events only** (`main.rs:5012`, `:5565`, `:8508`, `:8549`, `:15461`, `:15725`, `:4724`). Typing in the item editor or clicking around the vault does not refresh it, so a 1-minute setting can lock the vault mid-edit.
4. **Honeytoken trip evidence and the PIN-disable path swallow their write errors.** `canary.rs` ignores the alert write; `app_pin::disable()` ignores a failed PIN-file removal.
5. **Export failures are invisible.** The export worker returns after `eprintln!` (`main.rs:12222`): no dialog opens, no toast, no status change — the user is left staring at "⚠️ pick a destination…". The top dead-end (custom per-domain logo, `appwindow.slint:1321`) is a wiring bug of the same family, detailed in (a)/(b).

---

## (a) Callbacks with no handler or empty handler

**Headline: there are none.** 230 `callback` declarations, 222 of them inside the three windows
(`MainWindow` 580–3878, `QuickBarWindow` 3879–4076, `QuickCaptureWindow` 4077–4200); the other 8
are component APIs (`AuraButton.clicked`, `GeneratorPanel.*`). Those 222 declarations are **219
distinct names** (`drag_start` / `drag_update` / `drag_end` are declared in both secondary windows),
and all 219 resolve to a handler in `src/main.rs` — 220 handler names once `close_requested` (a
`Window` builtin, not a declared callback) is counted. Three handlers are registered twice, once per
window. No handler body is `{}`, and none is a pure *"coming soon"* toast.

What is **declared + handled + never fired** by any Slint code:

| Callback (declared) | Handler | Should trigger | Reality |
|---|---|---|---|
| `override_favicon(string)` — `appwindow.slint:1321` | `main.rs:14248` (full `rfd::FileDialog` → `favicon::save_custom_icon`) | Settings → "Custom logos (per-domain override)" | **Dead end.** Only `↻ Refresh` and `🧹 Clear` are rendered (`:2197`). No element emits `override_favicon`, so a custom logo can never be *set*; Clear can only clean up logos planted by an older build. |
| `toggle_pending_field(int)` — `:1185` | `main.rs:11359` | Editor: tick a checkbox custom field | **Dead end.** Checkbox fields (`ftype == 2`) render as a static glyph `☑/☐` (`:3084`); nothing calls the toggle. A checkbox custom field is write-once — it cannot be flipped after creation. |
| `type_credential_requested(string,string,string)` — `:1237` | `main.rs:8384` (canary-gated autotype of user/pass/totp) | Type a credential | **Dead duplicate.** No call site; the pill/item type paths (`:8474`, `:5090`, `:15762`) cover the capability. |
| `exit_app()` — `:1307` | `main.rs:14032` (clipboard flush → access log → `process::exit`) | Quit button | **Dead duplicate.** `close_requested` (`main.rs:4556`) performs the same flush + exit, so no security regression — only an unreachable copy of the safest quit path. |
| `generate_shards()` — `:961` | `main.rs:12398` | Recovery sheet: generate shards | **Dead duplicate.** `shard_nudge_generate` (`main.rs:12425`) and the drill path do the work. |
| `toggle_travel(int,string)` — `:1324` | `main.rs:13892` | Per-item travel flag | **Dead duplicate.** `set_travel_mode` (`:1313`, handler `main.rs:13267`, fired at `appwindow.slint:1786` / `:2199`) is the live path. |

Two dead **properties** (not callbacks) in the same class:

| Property | Set from Rust | Read in Slint | Consequence |
|---|---|---|---|
| `d_reprompt` (`:695`) | 6 sites | **0** | The "this item is reprompt-armed" indicator does not exist in the detail view. |
| `exp_confirm` (`:763`) | 0 | 0 | Vestigial export-confirmation flag; there is no export confirm sheet at all. |

---

## (b) Unreachable backend capabilities

Verified by call-site counting (comments excluded). The genuine list is short because this codebase
has very little orphan code — that itself is a finding.

| Capability | Module | Why unreachable |
|---|---|---|
| `save_custom_icon(domain, bytes)` | `src/core/favicon.rs:144` | Only caller is `main.rs:14305`, inside `on_override_favicon` — a callback with no Slint call site (see (a)). The favicon *cache* and *clear* paths work; the *set* path is unreachable from the UI. |
| `import_any_file(path)` | `src/importer/mod.rs:352` | **Zero call sites in `src/`.** The import UI dispatches by extension to the per-format parsers instead; the unified entry point is dead API surface (and therefore untested by the UI path). |
| `url_strings(&credential)` | `src/models.rs:241` | **Zero call sites.** Helper left behind after the multi-URL migration. |
| `on_type_credential_requested` | `src/main.rs:8384` | Full handler, no emitter (see (a)). |
| `on_exit_app` | `src/main.rs:14032` | Full handler, no emitter; `close_requested` duplicates it. |
| `on_generate_shards`, `on_toggle_travel`, `on_toggle_pending_field` | `src/main.rs:12398`, `:13892`, `:11359` | Handlers exist; no emitter. `toggle_pending_field` is the only one with **no working alternative** — see (a). |
| **Delete-with-reprompt** (`rp_action == 3`) | `src/main.rs:12106-12160` | The arm is complete (snapshot → trash → re-seal → rollback), and `:11992` documents "1 copy secret, 2 fill, 3 delete" — but no code ever sets `rp_action = 3`. Only 1, 2, 4 and 5 are written (`:4999`, `:5093`, `:8477`, `:8560`, `:10619`, `:13277`, `:15765`). A security control that exists and can never fire. |

Not dead, though they look it: `plant_canary` (`:10206`), `export_recovery_sheet_pdf` (`:11096`),
`export_csv_full_gated` (`:12268`), `push_remote` (`:1416`), `send_*`/`share_serve::serve` (`:15119`),
`set_show_favicons` (`:14222`), `type_card` / `type_identity` (`:523`/`:529`). All have live call sites.

---

## (c) Swallowed failures (file:line, risk)

Raw counts: **689** `let _ =` (251 of them in `main.rs`), **30** `.ok();`. Most are legitimately
best-effort (temp-file cleanup, test fixtures). The ones below touch state the user is told exists.

| # | Site | Code | Risk |
|---|---|---|---|
| 1 | `src/main.rs:777` | `let _ = clipboard.set_text(text.as_str());` (fallback when `copy_sensitive` fails) | **False success.** The toast "📋 Copied (fallback path…)" is shown unconditionally. If `set_text` fails the password is not on the clipboard but the user believes it is. The fallback also bypasses the hash-matched guarded flush and uses a bare `sleep` + `cb.clear()`, so it can wipe an unrelated clipboard entry the user copied in the meantime. |
| 2 | `src/main.rs:1163` | `let _ = std::fs::remove_file(HELLO_TOKEN_FILE);` in `lock_vault_now` | **Lock does not prove the Hello credential is gone.** The comment says this must happen *first* (C4). If the file is held/locked, the DPAPI-sealed passphrase survives the lock; the function proceeds to wipe RAM and report "Vault locked" regardless. |
| 3 | `src/security/canary.rs:52, 92, 97, 162, 164` | `let _ = writeln!(f, …)` / `let _ = std::fs::write(ALERT_FILE, …)` | **Honeytoken trip evidence can vanish.** A canary hit is the strongest duress signal the app has; the local record and the pending-relay queue are both written on a best-effort basis with no user-visible degradation. `main.rs:10206` plants the token and the UI promises "logged!". |
| 4 | `src/security/app_pin.rs:207-208` | `let _ = std::fs::remove_file(pin_path(base)); let _ = std::fs::remove_file(attempts_path(base));` in `disable()` | **"PIN disabled" can be a lie.** If removal fails, the sealed PIN blob stays; the next launch still demands a PIN the user thinks they turned off (or a stale PIN remains a valid unlock factor). |
| 5 | `src/security/access_log.rs:216-221` | `let _ = f.sync_all(); let _ = std::fs::write(head_path_for(path), &hash); … let _ = std::fs::remove_file(lock_path_for(path));` | **Hash-chain integrity degrades silently.** A head file that lags the log (crash between append and head write) weakens truncation detection; a stale lock file can block later appends. Nothing surfaces to the Audit tab. |
| 6 | `src/main.rs:12222-12226`, `:12237-12241` (also `12248`, `12260`) | `Err(e) => { eprintln!("export refused: {e}"); return; }` inside the export worker | **Silent export failure.** The status was pre-set to "⚠️ pick a destination…" (`:12189`), then the worker returns without a dialog, a toast, or a status change. In a release build there is no console, so the user sees a stale prompt and no file. Fails closed (good) but invisibly (bad). |
| 7 | `src/main.rs:91, 98` | `let _ = std::fs::write(HEARTBEAT_FILE, …)` | **Bridge liveness is unobservable.** Every 20 s the heartbeat is rewritten and failures ignored; a read-only/locked `%PHANTOM_VAULT_DIR%` makes the native host refuse to serve while the desktop shows nothing. |
| 8 | `src/main.rs:1964` | `let _ = save_vault_secret(v, &pass, VAULT_FILE);` after `purge_expired_trash` | Trash retention "ran" but was not persisted; the same items are re-purged (and re-reported) on every unlock. No data loss, but the 30-day promise is soft. |
| 9 | `src/main.rs:5667-5668` | `let _ = sync::github_sync::save_repo(...); let _ = sync::github_sync::store_token(...);` | Connect can appear to succeed while the repo/token were not persisted; the next launch asks again (or silently has no credentials). |
| 10 | `src/main.rs:9482` | `let _ = security::admin::save_members(&{…});` | Team/roster edit lost on I/O failure with no message. |
| 11 | `src/main.rs:15038, 15044-15045` | `let _ = share_relay::delete_sync(&published.gist_id); let _ = share_store::revoke(&created.id);` | Only on the rollback path, but a failed gist delete leaves a published encrypted bundle alive while the app reports the share as failed/not created. |

Not swallowed, for the record: the main save path is disciplined — delete/restore/empty-trash all keep a
snapshot and roll the in-memory vault back when `save_vault_secret` fails (`main.rs:6636` delete, `:6736` restore,
`:7049` empty-trash — one of 32 such rollback sites), and the lock path wipes every model (see (e)).

---

## (d) Ledger claims vs code (15 rows, most user-visible first)

`docs/FEATURE_LEDGER.md` rows are quoted by line number. Verdict scale: **match** / **partial** / **mismatch**.

| # | Ledger claim | Verdict | Evidence |
|---|---|---|---|
| 1 | **Master reprompt — "guard for reveal / autofill / delete / export"** (`:25`) | **Mismatch (2 of 4)** | **Autofill ✓** — `rp_action 2` from `main.rs:5093`, `:8477`, `:15765`; `reprompt_gate` (`:2814`) is login-only and tested. **Export ✓** — `on_export_vault` always opens the modal (`:10619`), and the export arm re-checks decoy + master. **Delete ✗** — a complete delete-with-reprompt arm exists (`rp_action 3`, `:12106-12160`) but **nothing ever writes `rp_action = 3`**; the live delete path (`:6598`) checks only decoy mode. **Reveal ✗** — `root.d_secret_visible = !root.d_secret_visible` in Slint (`appwindow.slint:3198`): no Rust, no gate, no access-log line. Detail-view copy is ungated too (`:8503`). |
| 2 | **Item detail — "history, attachments, TOTP" for all kinds** (`:18`) | **Partial** | Attachments fully wired: `pick/download/preview/delete/migrate` (`main.rs:13303/13541/13639/13723/13817`). History and TOTP models exist. But checkbox custom fields cannot be edited after creation (`toggle_pending_field` never fired; `appwindow.slint:3084` renders a glyph). |
| 3 | **2FA hub — "HOTP next"** (`:21`) | **Match** | `main.rs:13954`: decoy-guarded, snapshots the vault, advances the counter, re-seals with the master password, rolls back on save error. |
| 4 | **2FA import — "screen/webcam/file QR + manual paste"** (`:22`) | **Match (build-dependent)** | `camera` is a **default** feature (`Cargo.toml: default = ["camera"]`), so the non-stub `camera_scanner` path is what ships; the `--no-default-features` stub (`camera_scanner.rs:176`) returns an error rather than pretending. |
| 5 | **Vault health — "breached / reused / weak / stale"** (`:24`) | **Match** | `scan_vault_health_offline` / `scan_vault_health` (`main.rs:15900/15910`), per-item HIBP k-anonymity (`breach_check.rs:13`, called `main.rs:6546`, `:11860`), plus grouping helpers `health_rows_for` (`:2663`). |
| 6 | **Recovery kit + shards — "print sheet, shard drill"** (`:26`) | **Match** | PDF export `main.rs:11096` → `pdf_sheet.rs:153`; shard generation `main.rs:12425`; drill verify callback `verify_shard_drill` (`:616`) is fired from the lock screen. The `generate_shards` callback is a dead duplicate only. |
| 7 | **Audit & duress — "duress password, honeytokens, factory reset (3-pass)"** (`:27`) | **Partial** | Duress: `decoy::try_open_decoy` on failed unlock (`main.rs:1942`). Honeytokens: plant path live (`:10206`) but trip recording is best-effort (see (c)#3). Factory reset: 3-pass wipe implemented (`factory_gen`, `:6973-6985`). |
| 8 | **Secure Send — "expiring one-view notes, TTL, read + burn"** (`:28`) | **Match, with the caveat the UI already prints** | `share_store` carries `max_views` / `views` / `expires_at`; serving enforces them in-process (`share_serve.rs`); `main.rs:15119` starts the LAN server. The UI itself says LAN TTL/one-view are app-enforced and gist expiry is best-effort (`appwindow.slint:2256`) — honest. |
| 9 | **Local sync — "GitHub private-repo sync, Wi-Fi P2P, QR fallback"** (`:29`) | **Match** | Push with a real CAS guard: `push_remote(..., head.clone(), head)` (`main.rs:1416`), which refuses when the remote head moved (`github_sync.rs:200-233`); sidecars pushed before the blob (`:1405`); startup pull `:1455`. |
| 10 | **Extension bridge — "native-messaging host install, allowed origins"** (`:30`) | **Unverifiable / currently broken per project docs** | Code exists (`native_host.rs`), but `docs/SESSION_STATE.md:85-88` states the installed 0.4.0 build **refuses** the 0.4.1 extension, so end-to-end is blocked on an install. Static code cannot settle this. |
| 11 | **Import — "row preview, Skip/Update/Import all, undo, dedupe"** (`:31`) | **Match, with one state gap** | Preview/commit + single-slot undo: `undo_import_store` (`:3356`), `on_undo_import` (`:13017`). The undo copy is **cleared on lock** (`:1168`), so an auto-lock between import and undo silently removes the undo affordance. |
| 12 | **Offline cache — "snapshot + DPAPI key + Hello/PIN gate; freshness + sealed timestamp"** (`:33`) | **Match** | `MAX_AGE_SECS = 7 days` enforced on read (`offline_cache.rs:286`, `:333`) and reported (`:254`); refresh on unlock (`main.rs:84`, `:1623`); key rotated on every refresh (`:156-172`); cleared on decoy/disable/nuke (`:2083`, `:14063`). |
| 13 | **Travel mode — "local-only switch"** (`:34`) | **Match** | `set_travel_mode` fired from the sidebar and Settings (`appwindow.slint:1786`, `:2199`), handler `main.rs:13267`; per-item `f_travel` flag; quick-bar filter honours `travel_only` (`main.rs:3173`). |
| 14 | **Access log — "hash-chained, metadata only"** (`:67`) | **Partial** | Chain + head file implemented (`access_log.rs`), secrets never logged (test `secrets_never_touch_the_log`), but the head write and `fsync` are ignored (see (c)#5), so tamper-evidence can degrade without notice. |
| 15 | **Zeroize / secrecy — "required by rules.md"** (`:69`) | **Partial** | `lock_vault_now` is exemplary (wipes active vault, master, models, drafts, history, selection, share stage, import stage, favicon bytes — `main.rs:1151-1290`). But `group 1`: the plaintext secret lives in the Slint `d_secret` property for the whole detail session and is passed back through `copy_password_requested(root.d_secret)` (`appwindow.slint:3199`), i.e. the secret crosses the UI boundary on every reveal/copy by design. Not a bug, but it caps what "secrets never leave Rust" can mean. |

Rows that check out cleanly and needed no correction: password generator (Complex + Diceware,
`main.rs:8671-8681`), `.pvx`/KDBX/CSV/Bitwarden export dispatch (`:12210-12300`), attachments,
local API (`main.rs:14750`).

---

## (e) State-machine / logic gaps

### e1. Lock / unlock

Working: `lock_vault_now` (`main.rs:1151`) is a genuine choke point — Hello token removal, bridge
heartbeat stop, `panic_wipe`, undo-store drop, SSH agent stop, working-set trim, draft/edit/health
clear, guarded clipboard flush, access-log entry, and a UI purge of every secret-bearing model.
Unlock (`main.rs:1878-2100`) handles duress decoy, backoff accounting, Hello re-seal, AND-mode
(scrub the verification copy, re-prompt Hello), TOTP gate.

Gaps:
1. **Hello credential removal is best-effort** (`:1163`) — the one thing the code says must be
   certain is the one thing whose failure is discarded.
2. **Close-to-tray keeps the vault unlocked** (`:4521-4545`). With auto-lock at its default
   **Never**, closing the window leaves a fully unlocked vault in a hidden window with no timer.
3. **Auto-lock idle clock has 7 write sites**: unlock (`:5565`), any copy (`:8508`), TOTP (`:5012`),
   Quick Capture (`:8549`), pill show (`:15725`), the settings change itself (`:15461`), and the
   ticker's own re-arm after firing (`:4724`).
   Typing a note, browsing the list, or editing an item does **not** refresh it — with a 1-minute
   setting the vault locks mid-edit.
4. **Auto-lock / clipboard-timeout are not persisted**: `AtomicU64::new(0)` / `new(15)` at
   `main.rs:4591-4592`, stored only in those atomics at `:15445-15466`. No prefs file, no load on
   boot. Every restart silently reverts the user's security choice (UI shows "Never" again because
   the Slint default is also `0`, `appwindow.slint:1057`).
5. **Proximity lock** is configured and persisted (`proximity.json`, `:4598-4612`), but its
   settings are BLE-RSSI based and depend on `proximity_lock`; I did not verify the monitor thread's
   trigger conditions at runtime.

### e2. Trash / restore

Implemented with rollback (`restore_item` `:6703`, `empty_trash` `:7014`, purge-on-unlock `:1959`).
Gaps: purge persistence is swallowed (`:1964`); there is no UI surface for the 30-day retention
(`TRASH_RETENTION_SECS`) or for what purge removed; `empty_trash` has a confirm sheet
(`show_empty_confirm`) but no undo, unlike the import flow.

### e3. Save-prompt merge (extension)

`classifySubmitted` (`content.js:2946-2955`) is the whole merge policy: match on
**lowercased username only, within the current base domain**, then `known` (silent) / `update` (same
user, new password) / `new`. Gaps: changing the username on the same site produces a **new** item
instead of updating; the same account on a second domain (`accounts.google.com` vs `google.com`)
duplicates; no field-level merge (notes/folder/TOTP of the existing item are not carried into the
update preview). The pending-save buffer is per base domain in `chrome.storage.session` with a 60 s
TTL — reasonable, but a slow 2FA flow can outlive it.

### e4. Sync conflict

Push is correctly CAS-guarded (`expected_remote_sha`, `github_sync.rs:200-233`), so no blind
overwrite. But the conflict *resolution* is a dead end: on refusal the UI only sets
`⚠️ Sync: {e}` (`main.rs:1436`) — no merge, no "pull and retry", no queued push. Startup pull
on divergence keeps local and warns (`:1444-1446`: "never silent-overwrite"). Net effect: two
devices editing the same vault can wedge sync into a permanent warning state that only a manual pull
clears, with no UI path that says so.

### e5. Offline cache freshness

Good: 7-day `MAX_AGE`, age-gated reads, key rotation per refresh, clear on decoy/disable/nuke.
Gap: the desktop never shows the cache's age or staleness (only the extension gate does), and the
`refresh_if_enabled` error is surfaced as a toast/status only.

### e6. Import undo

Undo holds one full pre-import vault copy in memory and is dropped on lock (`main.rs:1168`) and on
`panic_wipe`. Correct hygiene, but it means the "undo" button silently does nothing after any lock
event — the UI does not hide/disable it.

---

## (f) What I could not verify

- **Any runtime behaviour** — no build, no launch, no screenshot. "Reachable" = a call site and a
  firing UI element exist; "works" beyond that is inference.
- **The extension bridge end-to-end** — `docs/SESSION_STATE.md:85-88` says the installed build
  refuses the 0.4.1 extension; that is a packaging state, not something static reading can settle.
- **BLE proximity lock** — I read the config plumbing and the lock call, not the monitor's trigger
  logic (`proximity_lock.rs`), so I cannot say how reliable the RSSI debounce is.
- **Whether `cargo test` / `clippy` are still green at `116f57a`** — not re-run (would need a
  ~5 min build on a RAM-tight machine). The ledger's last recorded green run is `171eb92`.

---

## Maturity, by area (defensible, not vibes)

| Area | Estimate | Basis |
|---|---|---|
| UI ↔ Rust wiring | **~99%** | 222/222 window callbacks handled, 0 empty bodies; 6 dead declarations and 2 dead props are leftovers, not missing glue. |
| Security-critical state paths (lock/wipe) | **~90%** | Lock wipe is exhaustive and rollback-safe; loses points for the swallowed Hello-token delete and tray-unlocked default. |
| Settings persistence | **~50%** | Auto-lock and clipboard timeout are session-only; most other prefs (tray, proxy, proximity, offline cache) do persist. |
| Auth/reprompt coverage | **~55%** | Gate is real and tested for autofill + export; delete has a dead arm and reveal has no gate at all. |
| Error surfacing | **~70%** | Most handlers translate errors into toasts; export failures and several security writes are eprintln/`let _`. |
| Sync | **~75%** | CAS-safe push, sidecar ordering, startup pull; no conflict resolution UI. |
| Extension parity | **~65%** (per its own ledger) | No read-only item view; SSH/License have no editor; merge keyed on username only. |

Overall: **the wiring is finished; the edges are not.** This is not a project full of stubs — it is a
project where a handful of security-adjacent edges (reprompt scope, settings persistence, silent
writes) are weaker than the ledger's ✅ column implies.

---

## Appendix — reproduction

Scratch scripts (not part of the repo):

- `%TEMP%\pv-scan\scan.py` — callback/handler map, empty-body and invocation counts (`callbacks.csv`, `map.json`).
- `%TEMP%\pv-scan\dead2.py` — `pub fn` call-site counts (`pubfns2.json`).
- `%TEMP%\pv-scan\reach.py` — call graph from `main()` (`unreach.json`).
- `%TEMP%\pv-scan\swallow.py` + `list.py` — swallowed-error inventory (`swallow.json`).
- `%TEMP%\pv-scan\panels.py` — never-true property heuristic (noisy; used only to seed manual checks).
- `%TEMP%\pv-scan\handlers.py` — handler body classifier.

Useful one-liners:

```powershell
# callbacks never fired from the .slint
python "$env:TEMP\pv-scan\scan.py"
# every handler body size + emptiness
python "$env:TEMP\pv-scan\handlers.py"
```
