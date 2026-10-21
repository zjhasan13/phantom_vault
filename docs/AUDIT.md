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