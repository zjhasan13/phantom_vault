# PhantomVault — Deep Audit (browser extension + desktop)

> Produced from a read-only plan-mode sweep (5 parallel explore agents + inline
> verification). Every row cites `file:line`. Claims that could not be
> reproduced are explicitly marked **FALSE POSITIVE** rather than deleted, so a
> future session does not re-chase them.
>
> Baseline at audit time: `cargo test` 446 passed / 1 ignored, `node --test
> tests/js/background.test.mjs` 16/16, branch `main` clean, version `0.2.1`.

## 0. Verification log (claim → verdict)

| Claim | Verdict | Evidence |
|---|---|---|
| Sidebar "Lock" terminates the app instead of locking | **CONFIRMED** | `ui/appwindow.slint:1349` `NavItem { … label: "Lock"; tapped => { root.lock_now(); } }` → `src/main.rs:11665-11670` `on_lock_now` → `std::process::exit(0)`. No separate Exit item. |
| Passkey `uv` is a caller-supplied boolean (2FA bypass) | **CONFIRMED, low reach** | `src/windows_native/native_host.rs:507` `if req.get("uv").and_then(as_bool) != Some(true)` — the legacy `assert` path trusts a boolean. The extension relay uses `assert_full`/`attest` with a Hello-minted `uv_token` (`background.js:327`), and `HANDOFF.md` records the legacy path as unreachable from the extension (fail-closed test pinned). |
| `crypto.rs` skips `zeroize()` on decrypt error | **CONFIRMED (minor)** | `src/crypto.rs:131-136` — `cipher.decrypt(..).map_err(..)?` returns before `key_bytes.zeroize()` on the error branch. |
| `st["fill_counts"][id]` serde_json IndexMut panic | **FALSE POSITIVE** | Same pattern already ships at `native_host.rs:1313` and is exercised by `native_host.rs:2467` (`fill_counts_and_verified_propagate`). No panic. |
| `backup_scheduler` backs up the wrong file | **FALSE POSITIVE (project-wide note)** | `storage/backup_scheduler.rs:100` reads `developer::vault_run::VAULT_FILE`; the entire app uses the same relative `my_secure_vault.enc` (`main.rs:44`). CWD-relative is a project-wide convention, not a scheduler bug. |

Unverified agent reports — all closed since: `security/access_log.rs:96-99`
(HMAC→SHA256) = D3 fixed; `security/emergency.rs:259-264` (shards in heap) =
D4 fixed; `content.js:843` session-cache invalidation = E5 fixed; the
`main.rs:2011` "toast scope" claim is **unreproducible** (baseline line 2011 is
`AuthView { … group_code(&next) … }`, no toast) and is closed as a false
attribution.

### Verified in the Phase 1 pass (previously "unverified")

| Claim | Verdict | Evidence |
|---|---|---|
| >1 MB GitHub object adopts an empty vault | **CONFIRMED — FIXED** | The Contents API returns `encoding:"none"`, `content:""` for files above ~1 MB (`octocrab` 0.41.2 `models/repos.rs`). `pull_remote` decoded `""` → `raw = []`; a fresh device then hit the adopt branch and wrote 0 bytes (`main.rs` `local.is_empty()`). Now `decode_remote_blob()` rejects empty/whitespace bodies, and the adopt path independently refuses zero-byte remotes. |
| `octocrab.decoded_content()` panics on the merge path | **FALSE POSITIVE (merge) / CONFIRMED (API internal)** | `decoded_content()` does `base64::decode(...).unwrap()` internally, but merge/crypto consumers treat the bytes as ciphertext and fail safely. The real loss was the empty-body adopt path above. |
| `importer/mod.rs` byte-slices Unicode (`split_at`) | **CONFIRMED — FIXED** | `parse_bw_datetime` used `t.split_at(t.len() - 6)`; a multi-byte stamp can put that index mid-char → panic. Now `str::get` returns `None`. |
| `secret_scanner` byte offsets drift on Unicode | **CONFIRMED — FIXED** | `to_lowercase()` can change byte length, so `line[abs + prefix.len()..]` could slice off-boundary. Now `to_ascii_lowercase()` (1:1 bytes) + `get`. |
| `backup_scheduler` non-atomic write | **CONFIRMED (minor) — FIXED** | A crash/full disk during `fs::write(&dest, ..)` could leave a truncated `.enc` that looks valid. Now temp file + rename. |

## 1. Browser extension — capture engine (Tier 0 scope)

The core defect: **registration / multi-page credential capture "gives up"**.
Root causes (all in `browser_extension/content.js` unless noted):

| ID | Defect | Location |
|---|---|---|
| G1 | Submit handler requires `input[type=password]:not([autocomplete="new-password"])` — a signup field is invisible to the watcher | `content.js:1977` |
| G2 | SPA saver reads `f.pass[0]` only; `findFields` already computes `f.newPass` but nothing consumes it | `content.js:2192-2193` (producer `:704`) |
| G3 | Signup vs login is never classified; confirm-password forms are treated identically | `content.js:1841-1849` |
| C1 | Submit handler `await queryHost(...)` runs **before** the prompt → a full-page POST navigation unloads the doc first | `content.js:1981-1985` |
| C2 | SPA ping waits a fixed 2500 ms then reads the DOM | `content.js:2222` |
| K1 | Only `pvPending.totpId` crosses navigation; no non-secret username carry for multi-page signup | `content.js:44-77` |
| K2 | `chrome.storage.session` is read from the content script but never granted content-script access (`setAccessLevel` absent) | `content.js:48,56,67,76`; `background.js` (none) |

Supporting facts reused by the fix: `findFields` returns `{ pass, newPass, users,
otp, cards, addr }` (`content.js:694-716`); the save UI is `saverToast` /
`updateToast` (`content.js:1850-1953`) and posts `PV_SAVE_LOGIN`; the background
already guards `PV_SAVE_LOGIN` with a sender-tab domain match
(`background.js:288-304`).

## 2. Other extension findings (outside Tier 0)

| ID | Finding | Location |
|---|---|---|
| E1 | `registrable()` / `pvRegistrable` mishandle multi-label ccTLDs (`foo.co.uk` → `co.uk`) | `content.js:87-91`, `background.js:419-423`, `popup.js:381-384` — **FIXED (Phase 3)**: `domain.js` PSL-subset `registrable()` |
| E2 | `EQUIV_CLUSTERS` duplicated in three files (drift risk) | `content.js:94`, `background.js:424`, `popup.js:386` — **FIXED (Phase 3)**: single `domain.js` table |
| E3 | Popup fill path bypasses desktop blocked-domains / punycode guards | `popup.js:466-517` — **FIXED (Phase 2)** via shared `domain.js` |
| E4 | Login iframes are never scanned (`all_frames:false`, no `match_about_blank`) | `manifest.json:36-42` - **FIXED (Phase 4)**: `all_frames:true`; **P6** removes the inert cross-origin guard - every frame matches/fills with its OWN origin, save sender is validated by `sender.url`, and popup/hotkey/menu route to the frame that owns the form. No `match_about_blank` (hostless origin still refused) |
| E5 | `extDeskOkPage` session cache never invalidated | `content.js:824-873` — **FIXED (Phase 5)**: 30 s TTL + cache drop on `focus` / `visibilitychange`(visible) / bfcache `pageshow`; a `PV_SESSION_STATE` locked reply clears it, and the background broadcasts `PV_GATE_LOCKED` to every tab the moment any caller detects a lock/idle timeout (Phase 6). Staleness is bounded to 30 s and every secret still rides the native bridge gate |
| E6 | Broad `MutationObserver` on `documentElement` (perf) | `content.js:2468-2480` — **FIXED (Phase 6)**: the two synchronous subtree observers became ONE 120 ms-debounced observer (`pvScheduleScan`) that coalesces re-render storms into a single `scan()`+`scanForms()` pass; cold pages still scan immediately |

## 3. Desktop findings (separate line — not Tier 0)

| ID | Finding | Location | Sev |
|---|---|---|---|
| D1 | "Lock" = process exit (see §0) | `main.rs:11677`, `slint:1350` | High (UX) — **FIXED (Phase 4)**: manual Lock + tray Lock ride `lock_vault_now` (RAM wipe + lock screen, process alive); separate Exit nav item + tray Exit are the only `process::exit` paths |
| D2 | Passkey legacy `uv` boolean trust | `native_host.rs:507` | Low — **confirmed unreachable** (extension sends `assert_full`/`attest` + `uv_token` only); legacy parity retained by design |
| D3 | Access log HMAC→SHA256 fallback | `security/access_log.rs:96-99` | High — **FIXED (Phase 2)** fail-closed |
| D4 | Emergency shards left in heap (reported) | `security/emergency.rs:259-264` | Med — **FIXED (Phase 2)** |
| D5 | >1 MB vault sync loss (reported) | `sync/github_sync.rs:171-180` | High — **FIXED (Phase 1)** |
| D6 | `zeroize()` skipped on decrypt error | `crypto.rs:131-136` | Low — **FIXED (Phase 1)** |

## 4. Tier roadmap (accepted)

- **Tier 0 (this work):** extension capture engine — G1/G2/G3, C1/C2, K1/K2.
  Extension-only; no Rust/exe rebuild; OTP engine (`pvPending`,
  `chainPendingStep`, `sweepOtpOnce`, `otpObserver`) untouched.
- **Tier 1 (security):** D2/D3/D4, E3, plus `setAccessLevel` hardening.
- **Tier 2 (correctness/data):** D5/D6, E1/E2, importer/scanner panics.
- **Tier 3 (UX):** D1 real lock screen (process stays), app-shell toasts, E4 iframe.
  D1 + E4 **DONE (Phase 4)**; app-shell toasts remain out of scope.
- **Tier 4 (tests):** content-script harness coverage.

## 5. Accepted decisions

- **Lock semantics:** real lock screen with the process alive, plus a separate
  Exit. (Implemented in Phase 4: sidebar + tray Lock vs sidebar + tray Exit.)
- **Tier 0 scope:** extension capture engine only.
- **Multi-page carry:** username only (non-secret). Password is **never**
  persisted to `storage.session`/`local` (P1-b policy intact).
- **iframe capture:** every frame, by its own origin (P6). `all_frames:true` injects everywhere; a cross-origin frame matches/fills only credentials saved for that frame's own URL, and `PV_SAVE_LOGIN` is validated against `sender.url` (never the top tab), so an embedded login is stored under the iframe origin. Popup, hotkey and context menu pick the frame with the visible form (`PVDomain.pickActionFrame`, `info.frameId` for menus). `match_about_blank` stays off (blank frames inherit a hostless origin and are refused).

## 6. Phase log

- **Phase 1 — data integrity (DONE `96b9330`):** D5 empty-body guards
  (`decode_remote_blob` + adopt gate), D6 zeroize-on-error, Unicode-safe
  `parse_bw_datetime` and `scan_line`, atomic backup write. Baselines moved
  `cargo test` 446 → **451 passed / 1 ignored**, `npm test` **25/25**.
- **Phase 2 — security (DONE `b850ce7`):** D3 access-log append is now
  fail-closed (unreadable chain key ⇒ refuse + loud stderr, never unkeyed
  SHA-256); D4 emergency shard plaintext Vecs zeroized (seal + open); E3 popup
  fill + suggestions honor blocked domains and punycode via the new shared
  `browser_extension/domain.js` (loaded by `popup.html`, packaged by
  `build.ps1`). D2 confirmed dead from the extension — no code change. `npm test`
  **28/28** (added `tests/js/domain.test.mjs`).
- **Phase 3 — shared domain logic (DONE `05c0a36`):** E1 `registrable()`
  now keeps multi-label public suffixes (`foo.co.uk` → `foo.co.uk`, not
  `co.uk`) via a pragmatic PSL subset; E2 `EQUIV_CLUSTERS` / `memberHit` /
  `domainsEquiv` live only in `domain.js`. Wiring: manifest `js` order
  (`domain.js` before `content.js`) in both manifests, `importScripts()`
  (classic MV3 SW) in `background.js`, `popup.html` already loads it.
  Harnesses updated (background `importScripts` stub, content jsdom loads
  `domain.js` first). `npm test` **32/32**; `cargo test` 452 unchanged.
- **Phase 4 — UX/lock + iframes (DONE `e06d841`):** D1 sidebar Lock (`slint:1350` →
  `main.rs:11677`) and tray Lock now call the shared `lock_vault_now` pipeline
  (RAM scrub, clipboard flush, access log, lock screen) instead of
  `process::exit(0)`; a new sidebar **Exit** + tray **Exit** are the only quit
  paths (clipboard flushed first, access log `exit`). E4 `all_frames:true` in
  both manifests with a same-origin-only boot guard (`content.js:9-22`):
  cross-origin/blank subframes return before any observer/capture setup.
  Tests: +1 jsdom/manifest regression (`npm test` **33/33**), `cargo test`
  **452 passed / 1 ignored**. E6 explicitly deferred (perf only).
- **Phase 5 — E5 gate cache (DONE `fc36e65`):** the desktop-presence verdict is no longer
  page-lifetime. `content.js` caches it for at most `EXT_DESK_OK_TTL_MS`
  (30 s) and drops it on window `focus`, tab visibility return, and bfcache
  `pageshow`; a locked `PV_SESSION_STATE` reply clears it immediately. Secrets
  were already bridge-gated, so this closes the stale-UX window rather than a
  security hole. Regression test stubs `Date.now` and asserts one probe for
  warm actions, re-probe after 31 s, and re-probe after `focus` →
  `npm test` **34/34**. Extension-only (no Rust rebuild).
- **Phase 6 — E6 observer + lock broadcast (DONE `e6eadf5`):** `content.js` replaces the
  two synchronous `documentElement` subtree observers with ONE 120 ms-debounced
  observer (`pvScheduleScan`) that runs `scan()` + `scanForms()` once per
  mutation storm; boot scans stay immediate. `background.js` now pushes
  `PV_GATE_LOCKED` to every tab whenever a `PV_SESSION_STATE` reply is locked or
  a `PV_PING` fails/reports `unlocked:false`, so E5's cache drops on lock/idle
  timeout across all tabs, not just the probing one. Tests: +3 (background
  broadcast, content broadcast invalidation, E6 static guard) →
  `npm test` **37/37**. Extension-only (no Rust rebuild).

## 7. Fill/capture strength pass (P0–P3)

- **P0 — URL-less web fill hole (DONE `6a4b0c6`):** desktop Smart-Grab items store
  `urls: Vec::new()`, while both gates treated an empty URL list as "allow"
  (`content.js:197`, `popup.js:422`) and native `query` matches on
  title/username substrings. A lookalike host (`discord-login.com`) could
  therefore pull a desktop-captured "Discord" item and autofill it. Both gates
  now **refuse** entries without a stored URL; `filterEntries` skips them
  silently (phishing toast reserved for real stored-URL mismatches) and the
  popup explains "No site URL saved — edit this item and add one." Desktop
  items remain reachable via the app-aware QuickBar/Auto-Type. Tests: +4
  (url-less hotkey refusal, bound control, popup gate/source assertions) →
  `npm test` **41/41**; `cargo test` 452 unchanged (extension-only).
- **P1 — capture URL/title quality (DONE `620bf68`):** save/update previously stored
  `location.href` verbatim (query tokens + fragment) and a naive
  `document.title.split("-")[0]`. `content.js` now stores
  `captureUrl()` = origin + path (query/hash stripped, trailing slashes
  normalized, path kept for prefix/exact rules) and `captureTitle()` =
  `og:site_name` / `application-name` / `apple-mobile-web-app-title`, else a
  suffix-stripped title with generic segments ("Sign in", "Login", …) skipped,
  else the registrable host. Native `canonical_login_url()` applies the same
  normalization in `save_login` (defense in depth for older clients). Tests:
  +2 jsdom save-payload regressions and +1 Rust canonicalization test →
  `npm test` **43/43**, `cargo test` **453 passed / 1 ignored**.
- **P2 — desktop app binding (DONE `ce43147`):** `Credential` gained an additive
  `#[serde(default)] apps: Vec<String>` (old vaults load unchanged; disk/export
  round-trips preserve it). Smart-Grab stores the lowercased exe stem + pretty
  app name (`cap_app`, hidden Slint property); `Ctrl+Alt+A` QuickBar shows
  items bound to the focused app regardless of title (text fallback when no
  binding exists). Auto-Type now refuses app-bound items in any other
  foreground app (`autotype-blocked-app` access-log event) while unbound web
  items stay unrestricted. Tests: +1 serde-default, +1 binding helper →
  `cargo test` **455 passed / 1 ignored**; no extension change.
- **P3 — popup fill parity (DONE `dbd721a`):** popup quick-fill/fill-submit used a naive
  `executeScript` injector (first text/email + first password), bypassing the
  content engine's React setters, multi-step chaining and URL gate. Both now
  send `PV_FILL_ENTRY {id}`; content re-queries by domain, re-applies
  `entryAllowed`, fills with `fillLogin()` and reports the field count. Direct
  inject remains only as a fallback for tabs without content.js; a content
  refusal surfaces its real reason. Tests: +2 jsdom (engine fill, unbound id
  refusal) +1 popup source assertion → `npm test` **46/46**.
- **P4 — UIA `SetValue` desktop fill (DONE `6e31196`):** Auto-Type now tries
  `ValuePattern.SetValue` on the focused control before sending keystrokes
  (`desktop_autofill::set_focused_value`, used by both `type_sequence` and
  `type_fields`). Only an enabled, writable Edit qualifies
  (`uia_value_allowed`); password boxes that report read-only fall back to the
  existing focus-guarded Unicode SendInput path, so coverage never regresses.
  Value is still `sanitize_field()`ed, and the foreground token is re-checked
  before every fill/Tab/Enter. Test: +1 policy gate →
  `cargo test` **456 passed / 1 ignored**.
- **P5 — UIA login field-pairing (DONE `9f7c298`):** app-bound desktop logins try
  `fill_login_pair()` first: visible Edit controls in the foreground window are
  enumerated (bounded depth/nodes, offscreen skipped); the focused password wins
  else the first password, and the username is the nearest non-password Edit
  above it (fallback: any Edit). Both must be enabled + writable **before** any
  write; a partial write is reverted, and pairing is refused when focus sits in
  an Edit outside the pair (chat/search box). Success fills both without Tab,
  logs `autotype/uia-pair`, then sends Enter. Read-only password boxes / missing
  pairs fall back to the P4 per-field SetValue → SendInput path. Test: +1 pick
  heuristic matrix → `cargo test` **457 passed / 1 ignored**.

- **P6 — cross-origin iframe fill (DONE `7e6da61`):** `content.js` no longer disables
  itself in cross-origin frames: embedded SSO/checkout logins now get badges,
  autofill and save prompts, and every domain decision uses the frame's own
  origin (the top document is never read). Background `PV_SAVE_LOGIN` validates
  `sender.url`, so an iframe credential is saved under the iframe's domain, not
  the embedding page. `PVDomain.pickActionFrame()` (shared) probes all frames
  via `chrome.scripting.executeScript({allFrames:true})` and routes hotkey/menu
  to the frame with the focused/visible password form (menu uses `info.frameId`;
  fallback = explicit top frame, never a broadcast). Popup collects frame hosts,
  merges iframe-domain suggestions (capped at 5 extra origins), extends the
  blocked/punycode/mismatch gates to them, and sends `PV_FILL_ENTRY` + direct
  inject + submit to the same picked frame. Top-only ceremony/OTP popup calls
  now pass `{frameId:0}` so they can never be answered by an iframe. Tests:
  +4 background (frame save accept/refuse, hotkey routing/fallback), +1 domain
  pick matrix, +2 popup source → `npm test` **53/53**.
- **Repo follow-ups (DONE `621892c`):** `write_adopted_head` was already wired on both
  adopt paths (`p2p_local::serve_conn`, `sync_with_peer`); the inline rollback
  condition is now the pure `adopt_rollback_blocked()` with a unit test
  (older/equal+different sha refused, same-sha idempotent, fresh head allowed).
  `ssh_agent::AgentKey` is explicitly `ZeroizeOnDrop`: `Zeroize` wipes comment
  and pubkey and replaces the dalek `SigningKey` (whose Drop wipes `secret_key`),
  so session teardown does not rely on implicit field-drop order. Tests: +2 →
  `cargo test` **459 passed / 1 ignored**; clippy unchanged (2 pre-existing
  `manual_clamp`).
- **Badge noise + card capture (DONE `e8a282f`):** the in-field control is
  now reconciled to exactly ONE action-aware icon per credential context:
  login = shield on the password (username folds into it), signup/new-password
  = dice only, password-change = the same shield opens a fill-or-generate menu
  (so no second dice), card = its own shield. Icon kinds are derived each scan
  and stale/mismatched buttons are removed, which also fixes SPA transitions
  (revealed password, form swap, removed field) and hidden groups. Checkout
  billing emails are never treated as logins. The form-less fallback was the real bug - it treated
  *any* password on the page as proof that every text input was a username, so
  nickname/sidebar/comment boxes were badged; it now requires the same `<form>`,
  a tight login ancestor, or 320px proximity. Standalone email/username badges
  require a credential-step signal (autocomplete, form action, path/title), and
  checkout pages never badge billing emails. Card save is implemented end to
  end: `readFormCard()` (Luhn + MM/YY + CVV shape), a masked Save/Update
  banner, SPA `PV_SPA_CARD` hook, background `PV_SAVE_CARD` with the P6
  sender-frame check, and native `save_card` (validates PAN/expiry, dedupes by
  PAN, updates holder/expiry/CVV in place). Card *fill* was also dead:
  `filterEntries()` dropped card rows (no `urls`), so `queryCards()` now asks
  the host with `all:true` (a domain hint is not a card binding) and
  `fillCard()` handles split month/year selects. `resolveRows()` now returns
  only the anchor's own kind (a disabled card/identity toggle no longer falls
  through to login rows), and the generator fills only new/confirm sibling
  fields - never the current password on a change form. Tests: +12 content,
  +3 background, +1 Rust -> `npm test` **71/71**, `cargo test` **460 passed /
  1 ignored**; clippy unchanged (2 pre-existing `manual_clamp`).
- **Multi-page carry v2 + identity suggestions (DONE, 0.3.2):** the carried
  username is now the FIRST sort key in the login dropdown (`rankLogins`:
  carried -> verified -> `last_filled` -> A->Z), and the same helper drives the
  hotkey and context-menu fill/copy paths, so `logins[0]` vault order no longer
  leaks into a fill (TOTP copy now picks the highest-ranked account that
  actually carries a secret). Ordering only - the carry can never hide a row or
  gate a fill (K1). Carry is scoped per tab through an opaque background
  `PV_TAB_ID` (`pvCaptureCarry:<tabId>`), so two same-site tabs cannot clobber
  each other; it is cleared only on a full username+password fill (a
  password-only step keeps it for save pairing). Pure-XHR step 1 (a
  `fetch`/XHR posting an identifier and no password) now pings a data-free
  `PV_SPA_IDENT` tripwire, and `maybeCarryFromDom()` re-reads the username from
  the DOM, so Google/FxA/Okta flows no longer depend on a native `submit`.
  Identity suggestions were still dead because `suggestIdentities()` asked for
  `PV_IDENTITIES` through `filterEntries`, which drops every URL-less row; it
  now uses the raw `getIdentities()` path (like cards). The checkout-path
  heuristic also hijacked explicit address fields (`isCard` won over
  `isAddr`) so identities never appeared on billing steps - `isAddr` now takes
  precedence. The popup suggestion list mirrors the same trust rank. Tests: +4
  JS (identity row, SPA identifier carry, hotkey ranking, popup static) ->
  `npm test` **79/79**; `cargo test` unchanged **461 passed / 1 ignored**
  (Rust untouched). The jsdom harness now honours `storage.session` reads and
  stubs `PV_IDENTITIES`.

## 8. Desktop auto-type / autofill audit (2026-11-05)

Read-only static sweep of the non-browser fill path: `src/windows_native/autotype.rs`
(433 lines), `src/windows_native/desktop_autofill.rs` (671 lines), and the
`TypeRequest` / `trigger_autotype` / `chain_2fa_watch` glue in `src/main.rs`.
**No finding was reproduced on screen** — the build was blocked at audit time by
the Windows commit limit (pagefile fixed at 4096 MB, peak 4095/4096), so nothing
was compiled or run. Treat this as a ranked hypothesis list backed by code
citations, not as verified behaviour. Baseline at audit time: `main` @
`de7e189`, 0.4.1.

### P0 — correctness and safety

| ID | Defect | Location | Fix direction | Status |
|---|---|---|---|---|
| A1 | Both guards are fail-open: `if let Ok(ctx) = inspect_active_context()` skips the spoof **and** app-binding checks when COM/UIA fails, then typing proceeds | `main.rs:326`, `:346` | For app-bound items, inspection failure must abort and log (`autotype-blocked-nocontext`). | fixed @3b1fc92 |
| A2 | The focused password box is never handled. Username is written to the focused control first (`SetValue`, else keystrokes), so clicking the password field sends the username into it; Tab then puts the password in the next control | `autotype.rs:313`, `:329`; `is_password_focused` is computed at `desktop_autofill.rs:568` but never read by the type path; pair-fill is app-bound only (`main.rs:402`) | Detect a password-focused control and require pair-fill or hunt the username field first. | fixed @3b1fc92 |
| A3 | Card fill contradicts its own contract: `main.rs:209` says separate MM / YY boxes (4 Tab stops), but `type_card` collapses them into one `MM/YY` field (3 stops) | `main.rs:381`, `autotype.rs:175-182` | Type `number{TAB}month{TAB}year{TAB}cvv`, or keep both modes and pick from the focused control. | fixed @3b1fc92 |
| A4 | Multi-line items are typed as one line: SSH keys (kind 6) and notes (kind 3) pass through `sanitize_field`, which strips `\n` and `\t` | `main.rs:235-244`, `:199-208`; `autotype.rs:65` | Refuse auto-type for kinds 3/6 and offer copy instead. | fixed @3b1fc92 |
| A5 | UIA fill reports success on `SetValue Ok` alone. React/Electron controlled inputs ignore the write, no keystroke fallback runs, and the user is told the fill worked | `desktop_autofill.rs:264-273`; `autotype.rs:304-309` | Re-read the value pattern and compare; fall back to keystrokes when unchanged. | fixed @1cf999a |

### P1 — reliability and false positives

| ID | Defect | Location | Fix direction | Status |
|---|---|---|---|---|
| A6 | Focus-token race: `set_minimized(true)` is requested, the worker starts immediately, and `foreground_token()` can still capture the vault's own HWND; 1.4 s later `ensure_focus` aborts | `main.rs:366`, `:374`; `autotype.rs:295` | Capture the token after the minimize settle, or resolve the target HWND before minimizing. | fixed @6b095fc |
| A7 | A failed password `SetValue` reverts the username field to `""`, destroying an email the user had already typed | `desktop_autofill.rs:269` | Save the previous value and restore it on failure. | fixed @6b095fc |
| A8 | `pick_login_pair` falls back to the first password in tree order when focus is not inside an Edit, and the focus guard only applies in the focused-Edit case; login+signup pages can fill the wrong form | `desktop_autofill.rs:166-179`, `:254-258` | Require an in-pair focus, or an explicit form-container match. | fixed @d76c34c |
| A9 | TOTP false positive: `"securitycode"` / `"security-code"` are OTP keys and password fields are accepted, so a card "Security code" (CVV) box can receive the live TOTP | `desktop_autofill.rs:459`, `:528` | Drop card-style keys, require an auth neighbour word, and only type when the OTP field is focused. | fixed @1cf999a (matcher b4ec6d0) |
| A10 | The 30 s 2FA watcher has no cancel and no countdown, and `type_text_raw` captures the foreground at typing time, so a focus change sends the code (with Enter) elsewhere | `main.rs:483-505`; `autotype.rs:260-272` | Visible countdown pill with cancel; abort unless the OTP field is focused. | fixed @1cf999a |
| A11 | The focus guard compares HWND only. Focus can move to another control inside the same window (autocomplete, "show password", confirm-password) without aborting | `autotype.rs:248-255` | Also compare the focused element's UIA runtime id. | fixed @d76c34c |
| A12 | The keystroke fallback assumes exactly one Tab between username and password | `autotype.rs:322-335` | Verify the post-Tab control is a password Edit before typing; abort otherwise. | fixed @d76c34c |

### P2 — polish, privacy, diagnostics

| ID | Defect | Location | Note | Status |
|---|---|---|---|---|
| A13 | `chain_2fa.pref` is read from the current working directory and defaults to ON | `main.rs:295` | Relative path is a project-wide convention, but TOTP auto-type is opt-out, not per-fill consent. | documented @1a82614 |
| A14 | "focus the target field…" is set on a window that is being minimized, so the user never sees it | `main.rs:365-366` | Use a tray balloon / toast. | fixed @1a82614 |
| A15 | `hunt_username` returns the control's *name* when its value is empty, so a placeholder like "Email address" can be saved as the username | `desktop_autofill.rs:352-359` | Prefer empty over a placeholder; filter known placeholder strings. | fixed @1a82614 |
| A16 | `ComGuard::enter()` runs per call; on an STA thread `RPC_E_CHANGED_MODE` makes UIA fill silently no-op | `desktop_autofill.rs:296` | Initialize COM once per worker. | fixed @1a82614 |
| A17 | Quick Bar in an unbound app lists the whole vault, with no app-relevant narrowing | `main.rs:3706-3718` | Show bound items first, then recent, then the rest. | fixed @1a82614 |
| A18 | Partial expiry produces `"/2030"` (empty month) or `"01/"` (empty year) | `autotype.rs:176-180` | Skip the field instead of emitting a malformed date. | fixed @3b1fc92 (via A3) |
| A19 | Standalone TOTP (kind 8) types without Enter while the login chain always submits | `main.rs:254` | Pick one behaviour, or expose a toggle. | documented @1a82614 |
| A20 | Aborted/failed types leave no access-log entry; only spoof and app-block events are logged | `main.rs:335`, `:355`, `:424` | Log `autotype-abort` with the reason, never the secret. | fixed @1a82614 |

### UX improvements (ranked by impact)

1. Countdown toast ("Typing into Discord in 3…") with Esc cancel, replacing the
   invisible minimize notification (A14).
2. Show the target in the Quick Bar: `target: Discord (discord.exe)`.
3. Granular fill: username only / password only / both, plus "fill without submit"
   (today every login types Enter, `main.rs:182`).
4. Post-fill verification: re-read the password field length (never the value) and
   warn when the fill did not land.
5. Warn before typing an item that contains characters auto-type cannot send
   (tab/newline) and offer copy instead (A4).
6. 2FA pill with a 30 s countdown and cancel; type only when the OTP field is
   focused (A9, A10).
7. Turn a block into an action: "bound to Discord, active app is Notepad" with
   "Bind to Notepad" / "Always allow".
8. Quick Bar empty state: "No items bound to Notepad — Alt+S to capture".
9. Remember the last successful target app per item ("Type into Discord again").
10. Tray quick-fill menu with the focused app's top three items.
11. Announce block/abort messages through a UIA live region, not just a
    notification text.
12. Force-keystroke toggle when UIA fill had no effect (A5).

### Test gaps

Unit tests cover the pure helpers only: `pick_login_pair`, `uia_value_allowed`,
`otp_like`, `sanitize_field`, `build_sequence` / `build_tabbed_sequence`,
`field_units_cover_ascii_and_surrogates`, `c_encodes_byte_exact`, and
`app_binding_matches_exe_pretty_name_and_unbound` (`main.rs:16051`). Nothing
pins: the fail-open guard (A1), the password-focused case (A2), the card 3-vs-4
field contract (A3), multi-line stripping (A4), or a `SetValue` that reports
success without changing the value (A5).

### Suggested fix order

1. A1, A2, A3, A4 — small, unit-testable, no UI work.
2. A6, A7 — reliability, one function each.
3. A5, A9, A10 — needs a live target app to verify.
4. UX items 1-4 in one UI batch.

## 9. Auto-type UI surfaces + theme conformance (2026-11-05)

Second read-only pass, same day. Scope: the three UI surfaces the desktop fill
path touches — `QuickBarWindow` (`ui/appwindow.slint:3846`), `QuickCaptureWindow`
(`:3994`), and the notification toast (`:3077`) — checked against
`design/tokens.json`, `docs/UI_TOKENS.md` and the `PhantomTheme` block
(`ui/appwindow.slint:140`). Static only: no build, no screenshot, nothing
reproduced.

### Code / behaviour findings (continues the A-series)

| ID | Defect | Location | Status |
|---|---|---|---|
| A21 | Neither popup focuses anything on open, so typing, ↑↓, Enter and **Esc** are dead until the user clicks a field. The lock screen does this correctly (`init => { self.focus(); }`), the popups do not, and no Rust call focuses them | `ui/appwindow.slint:3921`, `:4062` vs `:1452`; `main.rs:4922-4931` | fixed @b4ec6d0 |
| A22 | `qb_index` is never reset when the Quick Bar opens, so the highlight can be absent (index > list length) while Enter still copies the clamped last row | `ui/appwindow.slint:3859`; `main.rs:4926-4928`; only `edited` resets it (`:3926`) | fixed @b4ec6d0 |
| A23 | Always-on-top popups never auto-hide: no `focus-out` handler exists anywhere in the UI file (0 matches), so clicking another app leaves a 640×380 panel floating over it | `ui/appwindow.slint:3846-3851` | fixed @be545f0 |
| A24 | Frameless popups have no drag region and Rust never sets a position: `start-drag` = 0 matches, no `set_position`; the window lands wherever Windows puts it and cannot be moved | `ui/appwindow.slint:3847`, `:3995` | fixed @be545f0 |
| A25 | Every `notification_text` change forces `notification_kind = "info"` (`:618`), and the auto-type paths never set a kind — so "App mismatch", "SendInput was blocked" and "focus moved mid-type" all render in the neutral cyan/info tone. Only the copy path sets a kind | `ui/appwindow.slint:618`, `:3077`; `main.rs:534`, `:544`, `:552` | fixed @34048fb |
| A26 | The toast self-dismisses after 4 s regardless of severity, so an actionable auto-type error disappears while the user is still reading it | `ui/appwindow.slint:3078` | fixed @34048fb |
| A27 | The canary alert is clobbered in the auto-type path: the banner is set, then the minimize message (`:365`) and the success message (`:469-471`) overwrite it while the window is minimized, so the tripwire is never seen. The copy path deliberately avoids this (`:8081-8082`) | `main.rs:4686-4694`, `:365`, `:466-472` | fixed @34048fb |
| A28 | A blocked auto-type (spoof or app mismatch) only sets a notification on the hidden main window and leaves the Quick Bar open with no message, so the user sees nothing happen | `main.rs:335-341`, `:355-361` | fixed @34048fb |
| A29 | `cap_show_pass` is never reset when the capture window opens, so a previous "show password" state can expose the next captured secret while it is typed | `ui/appwindow.slint:4008`; `main.rs:4853-4871` | fixed @b4ec6d0 |
| A30 | The 2FA watcher outlives a lock: locking the vault during the 30 s window still types the code afterwards | `main.rs:483-505` | open |
| A31 | `record_ext_fill` also runs in decoy mode, writing decoy item ids and counters into the shared extension stats sidecar | `main.rs:423`; `native_host.rs:2758-2768` | open |
| A32 | The Quick Bar opens with the focused app name pre-typed into the search box, so the field starts with text the user did not type and must be cleared to search | `main.rs:4926` | open |
| A33 | Secrets ride the row model: `CredentialView.password` is populated for every listed item, so the Quick Bar and main list materialize all passwords in Slint memory with no zeroize. The copy path's own comment says the model "never carries secrets" | `ui/appwindow.slint:21`; `main.rs:2999` vs `:8103-8105` | open |
| A34 | After typing, the app restores and shows the main window, stealing focus back from the login form immediately after Enter | `main.rs:459-460` | open |

### Theme conformance (Aegis palette, `design/tokens.json`)

Verdict: **no colour is off-palette.** Every popup colour resolves to an Aegis
token value. The drift is in scale, token discipline, semantic tone, brand
casing and one contrast pair.

| ID | Drift | Evidence | Token value | Status |
|---|---|---|---|---|
| T1 | Off-scale spacing: 18px padding, 10px and 6px gaps | `ui/appwindow.slint:3899`, `:4041`, `:3903`, `:3968` | `spacing` = 4 / 8 / 12 / 20 / 32 | open |
| T2 | Off-scale radius: 18px window, 10px tiles | `:3874`, `:4020`, `:3907`, `:3956` | `radius` = 2 / 4 / 6 / 8 / 12 / pill | open |
| T3 | Off-scale type: 14px/800 headers, 11px captions, 9px chips | `:3914`, `:3915`, `:4056`, `:235` | `typography` = 15 / 13 / 12 / 10 | open |
| T4 | Alpha tints are raw hex, not tokens: `#060e20f2`, `#4edea366`, `#4edea333`, `#ffb4ab1a`, `#ffb4ab55` | `:3873`, `:3878`, `:4019`, `:4024`, `:199`, `:195`, `:197` | no alpha scale exists; `UI_TOKENS.md:24,89` already lists this as remaining debt | open |
| T5 | Active `GatewayTab` uses white on `primary-container` = **2.55:1**, below AA 4.5 (and below AA-large 3.0). `on-primary` gives 5.2:1 | `:245` | `on_primary` = `#003824` | open |
| T6 | Popup background is 95% opaque (`#060e20f2`) over an arbitrary wallpaper, so `text-dim` contrast is backdrop-dependent (6.35:1 on the token surface, lower on a bright desktop) | `:3873`, `:4019` | `surface_lowest` = `#060e20` | open |
| T7 | Magic `y: 2px` / `y: 0px` inside layout rows instead of a centred `VerticalLayout` | `:3971-3975`, `:3077` | AGENTS.md §6 layout pattern | open |
| T8 | Brand casing: "Phantom Quick Bar" / "PhantomVault Quick Bar" vs the two-word all-caps rule; the main window follows it | `:3914`, `:3852`, `:4000` | AGENTS.md §1 | open |
| T9 | i18n gaps inside otherwise localized windows: "hits", the search placeholder, the footer hint and "Type" stay English | `:3918`, `:3922`, `:3985`, `:3971` | A26 | open |
| T10 | Zero accessibility properties in the whole UI file (`accessible-role` / `accessible-label` = 0 matches), so both popups are unnamed to screen readers | whole file | — | open |

Not defects: emoji icons in the popups are explicitly allowed by the icon
policy (`docs/UI_TOKENS.md:62-71`), and the popups reuse `AuraButton`,
`FieldLabel`, `MonoChip` as required.

### Recommended UI batch (theme-first, smallest set)

1. Focus on open + reset `qb_index` + reset `cap_show_pass` (A21, A22, A29) —
   three lines, fixes the "keyboard does nothing" first impression.
2. `focus-out` auto-hide with a short grace, plus a drag region on both popups
   (A23, A24).
3. Notification semantics: set `notification_kind` for every auto-type outcome
   and make warn/error sticky instead of 4 s (A25, A26).
4. Surface the block reason where the user is looking (A28) and stop clobbering
   the canary banner (A27).
5. Token work: add `primary-glow`, `danger-tint`, `surface-scrim` to
   `design/tokens.json`, mirror them in `PhantomTheme`, then replace the popup
   literals; switch `GatewayTab` to `on-primary` (T4, T5).
6. Then the visual-scale sweep (T1, T2, T3), brand casing and the four English
   strings (T8, T9).

### Verification pass (2026-11-07)

Read-only re-check of every citation in §8/§9 against HEAD `0bf187a`. Only docs
changed since the audit (`git diff --stat de7e189..HEAD` → `docs/AUDIT.md`,
`docs/HANDOFF.md`, `docs/SESSION_STATE.md`), so `src/` and `ui/` are the same
tree the audit read. **No runtime reproduction yet; no gates were needed for
this pass.**

**Result: 33 of 34 A-items confirmed, 1 partial, 0 wrong, 0 stale line numbers;
T1–T10 confirmed.**

Confirmed exactly as written (spot-check evidence):

| Item | Evidence that settles it |
|---|---|
| A1 | `main.rs:326` `if let Ok(ctx) = inspect_active_context()` wraps both the spoof and binding checks; `Err` falls through to typing |
| A2 | `autotype.rs:313` writes the username to the focused control; pair-fill is only reached for non-empty `apps` (`main.rs:402-406`); `is_password_focused` has no reader in the type path (`main.rs:4427`, `:4863` only) |
| A3 | `autotype.rs:175-182` builds `number{TAB}MM/YY{TAB}CVV` (3 stops) while `main.rs:209` calls for 4 |
| A4 | `autotype.rs:65` drops every control char (`\n`, `\t`); notes/SSH are single-field requests (`main.rs:199-208`, `:235-244`) |
| A5 | `desktop_autofill.rs:264-273` returns `true` on `SetValue().is_ok()`; the value is never re-read |
| A7 | `desktop_autofill.rs:269` `up.SetValue("")` on password failure |
| A8 | `desktop_autofill.rs:166-179` falls back to first password; focus guard only when focus is inside an Edit (`:254-258`) |
| A9 | `desktop_autofill.rs:459-460` treat `securitycode`/`security-code` as OTP keys; `:528` accepts password edits |
| A10 | `main.rs:483-505` has no cancel/lock check; `autotype.rs:261` captures the foreground at typing time |
| A11 | `autotype.rs:248-255` compares HWND only |
| A12 | `autotype.rs:322-335` sends one Tab and types the password with no post-Tab check |
| A13 | `main.rs:295` reads `chain_2fa.pref` relative to cwd; missing file = ON |
| A15 | `desktop_autofill.rs:352-359` returns the control name when the value is empty |
| A16 | four `ComGuard::enter()` call sites; `Err` makes `set_focused_value` return false (`:234`, `:297`) |
| A17 | `main.rs:3739` keeps all rows when `bound.is_empty()` |
| A18 | `autotype.rs:176-180` `format!("{}/{}")` even when one half is empty |
| A19 | `main.rs:254` standalone TOTP `press_enter: false`; login chain always submits (`autotype.rs:337`) |
| A20 | access log writes on success (`main.rs:424`), spoof (`:335`), block (`:355`) — not on aborts |
| A25 | Slint `:618` `changed notification_text => notification_kind = "info"` |
| A26 | Slint `:3078` `Timer { interval: 4s; … }` |
| A27 | canary text set at `main.rs:4690`, then overwritten by `:365` and `:469` |
| A29 | no `set_cap_show_pass` anywhere in `src/`; `cap_show_pass` survives reopen |
| A31 | no decoy guard before `trigger_autotype` (`main.rs:8000`, `:8059`), unlike capture-save (`:4955`) |
| A33 | `main.rs:3538` passes `&c.password` into `CredentialView.password`; the "never carries secrets" comment is at `:8103-8105` |
| A34 | `main.rs:459-460` restores and shows the main window right after typing |

Partial:

- **A32** — true for **Ctrl+Alt+A** only. `main.rs:4886` pre-fills `app_prefilter`
  for the auto-type entry; the Alt+Space branch passes `String::new()` (`:4890`).

Confirmed but runtime-dependent (static order proves the window, not the timing):

- **A6** — `set_minimized(true)` (`main.rs:366`) is followed immediately by
  `thread::spawn` (`:374`), and the worker captures `foreground_token()` at
  `autotype.rs:295`. Whether the minimize has settled before that line runs
  cannot be decided statically.
- **A5 / A9 / A10 / A21–A30 / A34** — the code paths are proven, but the user
  impact (React inputs ignoring `SetValue`, a CVV box receiving a TOTP, the
  popups being keyboard-dead) needs a live target app and a screen recording.

Theme verdict correction:

- The §9 verdict "no colour is off-palette" holds for the two popups: their only
  hex literals are `#060e20f2` and `#4edea366` (both tokens + alpha).
- **But the toast info background `#101834` (`ui/appwindow.slint:3077`) is not in
  `design/tokens.json`** (palette has `canvas #0b1326`). It is a raw literal that
  T4 misses; add it to the token set or map it to an existing surface.

Test-gap claim re-checked: the listed tests exist
(`sanitize_strips_control_chars`, `sequence_layout_is_user_tab_pass_enter`,
`tabbed_sequence_chains_fields_with_tabs`, `uia_setvalue_policy_requires_enabled_writable_edit`,
`uia_login_pair_uses_focus_and_edit_order`, `otp_matcher_hits`,
`spoof_guard_catches_typosquats`, …) and none of them pins A1/A2/A3/A4/A5.

### Fix batch 1 — A1–A4 (`3b1fc92`)

- **A1** — `autotype_gate()` returns `BlockNoContext` for bound items when
  `inspect_active_context` fails; unbound items are unchanged.
- **A2** — `focused_is_password()` + pair-first policy: a focused password box
  never receives the username; the fill aborts if the UIA pair is unavailable.
- **A3 / A18** — card fill is four stops (`number{TAB}month{TAB}year{TAB}CVV`);
  a partial expiry stays empty instead of becoming `/2030`. Trade-off:
  combined `MM/YY` checkout fields need a future mode.
- **A4** — kinds 3 (note) and 6 (SSH) are refused with a Copy suggestion and an
  `autotype-blocked-multiline` log entry.
- Tests +7 (`autotype_gate_*`, `autotype_refuses_multiline_item_kinds`,
  `card_fields_*`, `password_focus_forces_pair_attempt`):
  `cargo test` **576 passed / 0 failed / 4 ignored**, clippy clean.
- Still not reproduced against a live target app: A6/A5/A9/A10 and the UI
  items (A21–A34) remain open.

### Fix batch 2 — A6–A7 (`6b095fc`)

- **A6** — the foreground HWND is captured after `SETTLE_MS` in both
  `type_sequence` and `type_fields`, so the async minimize can no longer leave
  the vault's own window as the target. Zero HWND aborts immediately; an
  Alt+Tab during the following 600 ms focus delay still aborts via
  `ensure_focus`.
- **A7** — the username box's previous value is read before the write and
  restored when the password `SetValue` fails, instead of being blanked.
- Not unit-covered (timing / UIA); the raw-vs-trimmed helper is pinned by
  `bstr_restore_keeps_the_typed_username_exact`.
  `cargo test` **577 passed / 0 failed / 4 ignored**, clippy clean.
- Next in this series: A5 (verify the write landed), A9 (CVV/TOTP), A10
  (watcher cancel + focus), then the A21–A34 UI batch.

### Fix batch 3 — A9, A21, A22, A29 (`b4ec6d0`)

- **A9 (matcher)** — `otp_like` rejects card labels (CVV/CVC, card number,
  expiry, "security code") before the generic `code` heuristic; only a
  six-digit prompt passes the digit fallback. Explicit OTP/2FA/authenticator
  wording still wins. The "type only when the OTP field is focused" half is
  **A10**, still open.
- **A21** — new `public function focus_search()` / `focus_first_field()` called
  from Rust right after `show()`, for the Quick Bar and Quick Capture.
- **A22** — `qb_index` is reset to 0 in both Quick Bar open paths.
- **A29** — `cap_show_pass` is reset to false on every capture open.
- Screen evidence: the capture title is focused on open (typing `zz` with no
  click landed in it) and the eye toggles 1F441 -> 1F648 -> 1F441 across
  reopen. The Quick Bar hotkeys did not register on the test machine, so A21's
  Quick Bar half and A22 are compile/check verified only.
- `cargo test` **578 passed / 0 failed / 4 ignored**, clippy clean.

### Fix batch 4 — A5, A10 (`1cf999a`)

- **A5** — `set_focused_value` re-reads the value after `SetValue`; an ignored
  write returns false so the caller falls back to keystrokes. Password boxes are
  exempt (masked/withheld value). `fill_login_pair` verifies both writes and
  restores the previous pair on a mismatch; an unreadable pattern keeps
  trust-on-write so a secret is never typed twice.
- **A10** — the watcher publishes a 30 s countdown
  (`chain_2fa_active`/`chain_2fa_secs`) and obeys a shared cancel flag; a pill
  in the main window shows "2FA auto-fill in Ns" with Cancel. `otp_screen_visible`
  now requires the OTP control (or an ancestor within four levels) to be
  focused, and the watcher re-checks focus after the 300 ms settle before typing.
- **A9** is now fully fixed (matcher here, focus gate in this batch).
- Not reproduced end-to-end: the countdown/cancel pill and the focus guard need
  a live OTP flow (login submit -> OTP screen).
- **A30** (watcher outlives a lock) is still open.
- `cargo test` **579 passed / 0 failed / 4 ignored**, clippy clean.

### Fix batch 5 — A25-A28 (`34048fb`)

- **A25** — auto-type outcomes set `notification_kind`: block/mismatch/
  multi-line = warn, spoof/abort = error, success = success. The banner is no
  longer forced to the neutral info tint.
- **A26** — the toast timer keeps warnings for 10 s and leaves errors until the
  user dismisses them; info/success still clear after 4 s.
- **A27** — the three auto-type entry points pass `quiet` when the honeytoken
  tripped, so the canary banner is not overwritten by the "minimized" or result
  toasts. Typing still proceeds (the tripwire is logged).
- **A28** — block/abort reasons are mirrored to a Quick Bar `qb_status` line
  (cleared on open and on query edits), so a refused type explains itself where
  the user is looking.
- Not screen-verified: these states need a honeytoken item and a bound-app
  mismatch; the demo vault has neither. `cargo test` **579 / 0 / 4 ignored**,
  clippy clean.

### Fix batch 6 — A8, A11, A12 (`d76c34c`)

- **A8** — `pick_login_pair` requires focus inside one of the form's Edit
  controls and picks the nearest password at/after it (or the nearest before).
  No Edit focus = no pair, so a login/signup page is not filled from page order.
  Unit tests cover the no-focus and second-signup-block cases.
- **A11** — `FocusGuard` captures the focused UIA element and checks it on every
  keystroke (control-level, not just HWND); the lock is re-captured after the
  intentional Tab. UIA failure keeps the old window-only behaviour.
- **A12** — after Tab, the password is only written when the control reports
  IsPassword or its label/id says password/secret (PIN matched on word
  boundaries). Otherwise the fill aborts.
- FocusGuard is runtime-only/compile-verified; A8 and the label heuristic have
  unit tests. `cargo test` **580 / 0 / 4 ignored**, clippy clean.

### Fix batch 7 — A13-A17, A19, A20 (`1a82614`)

- **A16** — `ComGuard` tolerates `RPC_E_CHANGED_MODE` (Slint's STA UI thread)
  and only calls `CoUninitialize` when it initialized the apartment. Without
  this, the A1 gate could fail-closed on every bound item.
- **A15** — `hunt_username` no longer returns an empty edit's label/placeholder
  as the username.
- **A14** — the "vault minimized" toast is gone: it was set on a window that
  was already minimizing and was never visible.
- **A20** — failed/aborted fills write an `autotype-abort` access-log entry with
  the reason only.
- **A17** — an unbound Quick Bar orders recent fills first, then the existing
  title/username score, instead of vault page order.
- **A13** (documented) — the Settings toggle is the consent control and
  `chain_2fa.pref` is relative to the cwd pinned by `PHANTOM_VAULT_DIR`;
  missing file still means ON.
- **A19** (documented) — standalone TOTP types without Enter on purpose; the
  login chain submits because it just filled a login form.
- `cargo test` **581 / 0 / 4 ignored**, clippy clean.

### Fix batch 8 — A23, A24 (`be545f0`)

- **A23** — both always-on-top popups spawn a bounded foreground watcher that
  hides them 250 ms after another window takes focus. A 2 s grace (and a
  "seen foreground" flag) prevents a slow `SetForegroundWindow` from hiding the
  popup instantly; `bring_to_foreground` now attaches to the foreground thread.
- **A24** — the frameless popups drag 1:1 from a topmost 56 px header strip.
  Slint reports down/move/up; Rust anchors on `GetCursorPos` + the window origin
  and applies `SetWindowPos(... SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE)`.
- Screen evidence: the capture moved from `160,160` to `280,220` for a
  `+120,+60` drag, then disappeared within a second of focusing the main window.
- `cargo test` **581 / 0 / 4 ignored**, clippy clean, build clean.

## Import/export upgrade: native lossless backup, row previews, merge modes, undo

- New native document `phantomvault-backup` v1: the full `Vault` (logins,
  cards, identities, notes, licenses, SSH keys, passkeys, 2FA hub accounts,
  attachment bytes, URL match rules). Trash, sharing grants and verification
  ids are machine-local and stay behind. Exported only as `.pvx` - the same
  portable hybrid envelope as the vault file (Argon2id + ML-KEM +
  XChaCha20Poly1305), sealed with the master password, so there is no second
  secret to lose. Decoy refused; the plaintext JSON serializer is internal.
- Sniffer learns two formats: the `PV2\0` magic is checked BEFORE text
  decoding (binary container) and the `"format":"phantomvault-backup"`
  marker before every vendor heuristic. Encrypted backups are decrypted with
  the live master; a foreign/wrong master fails loudly instead of partially
  importing.
- Dry-run preview is row-level now: kind + title + username/full name +
  folder, secrets never rendered, capped at 200 rows. Three merge modes:
  Skip dupes (default), Update existing (in place; id preserved so
  `verified_ids` still point at the item; retired password pushed to
  history), Import all. Switching modes recomputes counts on a clone.
- Login dedupe includes the normalized URL set: the same title/user/password
  on two different sites imports twice (rotation + decoy safety intact).
- Session-only "Undo last import": pre-import snapshot + post-import vault
  fingerprint; refuses when anything changed since the import. RAM only,
  wiped on lock and replaced by the next import.
- "Full CSV" export (all kinds, `data_json` per row) for spreadsheets;
  plaintext and gated/decoy-refused like the other file exporters.
- Tests: +7 Rust (native encrypted round-trip incl. passkey seed + attachment
  bytes, trash/local-state exclusion, real-sniffer parse + native merge,
  full-CSV coverage, URL-aware dedupe, update-in-place with history, ImportAll)
  -> `cargo test` **468 passed / 1 ignored**. JS untouched (`npm test` 79/79).
  Release bump: 0.4.0 (Cargo.toml, Cargo.lock, installer.iss, both extension manifests).
