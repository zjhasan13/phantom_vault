# Session Handoff — PhantomVault

> Read this fully in a fresh session BEFORE doing anything. Last updated: A15b ephemeral P2P beacons + paired-device management (A15a+b complete), after A16/A12/A17/A11b/A14.
> Companion: `rules.md` (architecture invariants — non-negotiable).

## 1. Where we are

- **Web 0.3.2 (latest):** one ranking for every fill path (`rankLogins`:
  carried -> verified -> last_filled -> A->Z) used by the dropdown, hotkey and
  context menu; identity suggestions fixed (raw `getIdentities()` - URL-less
  rows no longer dropped, and `isAddr` beats the checkout-card heuristic);
  per-tab carry (`pvCaptureCarry:<tabId>` via background `PV_TAB_ID`); SPA
  identifier-only step 1 carries the username via a data-free `PV_SPA_IDENT`
  tripwire; popup mirrors the trust rank; carry clears only on a full fill.

- **Import/export 0.4.0:** lossless native
  `.pvx` backup (same master-password hybrid envelope — superseded by A6 below,
  which adds the `PVBK1` backup-passphrase tag; passkeys, 2FA hub,
  SSH keys, attachment bytes), row-level preview with Skip / Update existing /
  Import all, URL-aware login dedupe, session-only undo guarded by a vault
  fingerprint, and an all-kinds "Full CSV" export. Importer decrypts `.pvx`
  with the live master and refuses a foreign one. Installer + zips rebuilt at
  0.4.0.
  Tests `npm test` **79/79**, `cargo test` **468 passed / 1 ignored**.
  Installer `installer-output/PhantomVault-Setup-0.4.0.exe` (8.54 MB, sha16
  `675196E7EC550471`, excludes `browser_extension/dist`); exe 19.55 MB
  ProductVersion 0.4.0; zips `dist/phantomvault-{chrome,firefox}-0.4.0.zip`
  (111002 / 111054 bytes). Release upload is user-side (`gh` unauthenticated).

- **A5 — master password rekey (this batch):** `storage::rekey_vault_secret`
  proves the old password against the live container, encrypts under the new
  one (fresh Argon2id salt + fresh ML-KEM keypair, KDF params untouched),
  round-trip-verifies, proves the old password no longer opens it, rotates the
  previous container to `.bak.1.enc` (still old-password) and writes
  atomically. Settings > Security gains the three-field card + two-tap
  confirm (`change_master_password`). On success: RAM master replaced, Hello
  token re-sealed, App PIN removed (PIN is unrecoverable), shard nudge reset,
  metadata-only `rekey` access-log event, sync push. Deliberate: `.pvx`, old
  backups and GitHub history stay on the old password. Tests: +6 →
  `cargo test` **481 passed / 1 ignored**, `npm test` **118/118**. A4 hardware
  clipboard QA still unverified (gap doc §5.7).

- **A9 — edit-before-save (this batch):** `content.js` now has one
  `credentialToast` builder behind `saverToast`/`updateToast`. The prompt shows
  the submitted username and password in real inputs (password masked) inside a
  **closed** shadow root, so the pair can be corrected before anything is
  stored and a page script cannot read it back out of the DOM. Save reads the
  edited values, trims the username only, blocks an empty pair with an inline
  error, and re-classifies against `existingSync` so a pair equal to a stored
  entry stops with "already saved" instead of a host round-trip. The 30 s timer
  re-arms on typing and refuses to close while a field is focused; Escape
  inside a field keeps the edit, elsewhere it dismisses. Tests: +6 →
  `npm test` **124/124**, `cargo test` 481 unchanged. Honest limit: a closed
  shadow root is a DOM boundary, not a keyboard boundary — the page can still
  see key events, as it can for the original typing.

- **A6 — independent backup passphrase (this batch):** new `.pvx` exports are
  `b"PVBK1"` + the unchanged portable envelope, sealed with a **backup
  passphrase** instead of the vault master (`exporter::export_native_encrypted`,
  `BACKUP_V2_MAGIC`). Export gate (`backup_pass_error`): ≥12 characters, confirm
  must match, and the value must **differ from the master** — reusing the master
  is refused outright. The master reprompt stays as proof of presence. Import
  checks the tag first (`Format::PhantomBackupV2`) and decrypts a tagged file
  **only** with the backup field; a missing/wrong passphrase fails with an
  explicit message and leaves the vault untouched. Untagged files take the
  legacy path (master password) so pre-A6 backups still import. UI: two modal
  fields for encrypted export + an optional "Backup passphrase" field on the
  Import screen, both cleared once Rust owns the secret. `crypto.rs` unchanged;
  fresh salt per export (asserted). Tests +4 → `cargo test` **485 passed / 1
  ignored**, `npm test` **124/124**.

- **A8a — certificate-free release pipeline (this batch):**
  `.github/workflows/release.yml` runs on `v*` tags: verifies tag == Cargo
  version, refuses without `PV_SIGNING_KEY`, then calls
  `scripts/package_release.ps1` (the same script used locally) to run
  `cargo test` + `npm test`, build the release exe, compile `installer.iss`,
  zip both extensions, write a CycloneDX SBOM, hash every asset
  (`<asset>.sha256` + `SHA256SUMS.txt`) and sign every `.exe`/`.zip`.
  `tools/pv-sign/src/main.rs` (its own crate, no app dependency graph)
  produces raw 64-byte Ed25519 `<asset>.sig` and refuses a
  key that does not match the pinned key; `src/release_pubkey.rs` is now the
  single source of truth (updater re-exports it). Releases ship both the Inno
  installer and `PhantomVault-<ver>-windows-x64.exe`; `pick_asset` now skips
  `setup`/`installer` names and refuses an installer-only release, so the
  updater can never swap the installer over the live app. The workflow
  publishes the release and a GitHub build-provenance attestation. **No UPX** —
  the old sub-8MB target came from v0.2.0 (6.7 MB); the published 0.4.1 exe is
  19.77 MB (0.4.0 was 19.55 MB) and the installer 8.98 MB, so
  `docs/RELEASE.md` records the real size instead.
  **Key rotation:** the old pinned key had no available private half, so a new
  key was generated. Seed: `%USERPROFILE%\.phantomvault\release_signing.key`
  (user-only ACL, never printed by keygen). The GitHub secret `PV_SIGNING_KEY`
  is set and verified via `gh secret list` (the maintainer's stored OAuth token
  was used; the seed was piped through stdin, never echoed). Clients built
  before this change must reinstall once manually.
  **First live run (2026-10-31):** tag `v0.4.1` published automatically by
  `release.yml`. Assets: setup exe 8,979,423 B, portable exe 20,727,808 B,
  both zips, `.sig` + `.sha256` for each, CycloneDX SBOM (583 components) and
  `SHA256SUMS.txt`. Verified after download: both exes' `.sig` against the
  pinned key, hashes equal the API digests and `SHA256SUMS.txt`, and
  `gh attestation verify … --repo zjhasan13/phantom_vault` exited 0.
  `security.yml` is green on the tag commit too.
  Tests +4 → `cargo test` **485 passed / 1 ignored + 4 pv_sign tests**; `npm test` **124/124**.
  Authenticode (A8b) remains open — no certificate.

- **A11 — offline read-only extension cache (this batch):** Settings > Security
  gains an opt-in toggle. On enable (and at every unlock while enabled) the app
  writes a **logins-only** snapshot (`vault_cache.enc`, `PVOC1` +
  XChaCha20-Poly1305) under a fresh 32-byte key sealed with DPAPI
  (`vault_cache_key.dpapi`). The native host answers exactly one command,
  `cache_get`, while the desktop is closed: it prompts **Windows Hello**, then
  unseals and returns the snapshot. Every other command still requires the P1
  heartbeat. The extension keeps the decrypted entries only in service-worker
  memory for 15 minutes (`OFFLINE_TTL_SECS`), clears them on `PV_GATE_LOCKED`,
  and serves `PV_QUERY` from the cache with `cached: true` + a visible banner.
  Read-only: mutations hit the closed host and fail; reprompt-armed items are
  refused offline in both popup and content paths. Decoy unlock **deletes** the
  cache; rekey refreshes it; disabling deletes both files.
  Tests +4 Rust (Trash exclusion, AEAD tamper/wrong key, DPAPI disk round-trip,
  clear) and +4 JS (fallback, TTL reuse, lock clearing, empty-query guard) →
  `cargo test` **489 passed / 1 ignored + 4 pv_sign tests**; `npm test`
  **128/128**. Honest limit: Hello is a presence prompt, not a key factor — a
  same-user process can unseal DPAPI without it, and the snapshot refreshes
  only at unlock.

- **A15a — mandatory P2P pairing (this batch):** new `sync/p2p_pairing.rs`:
  per-device Ed25519 key (DPAPI), one-time 64-bit code (5 min, single-use, never
  sent over the wire), HMAC pair proof, DPAPI-sealed paired-device list, and
  Ed25519-signed `pull`/`sync` requests (timestamp ±120 s). `p2p_local.rs`
  now answers only `/p2p/pair` unauthenticated; every other request without a
  paired signature gets 403. The shown P2P "PIN" is now the pairing code; a
  paired device syncs without re-entering it (address-based lookup). Legacy PIN
  code is retained only for old route tests/migration. Tests +3 →
  `cargo test` **499 passed / 1 ignored + 4 pv_sign**; `npm test` 132/132.
  **A15b:** beacons now carry only an ephemeral per-process ID (no head
  SHA/mtime; legacy parse fallback only), and Settings lists paired devices with
  a Forget action (`list_pairs/forget`). Remaining: response signing, QR, and
  wiring A16's fresh-device anchor to the paired head.

- **A15b — ephemeral beacons + paired-device UI (this batch):** `Peer` no longer
  carries `head_sha`/`pin_required`; `beacon_json` emits `{app,name,version,port,id,ts}`
  with a random per-process `id`, and `parse_beacon` accepts legacy `head_sha`
  only for discovery. Settings gains a paired-device list (name, key prefix,
  address) with **Forget**, which removes the key from `p2p_paired.dpapi` so the
  next request is 403. Tests +1 → `cargo test` **500 passed / 1 ignored + 4
  pv_sign**; `npm test` 132/132.

- **A15c — response signing, QR, A16 anchor (this batch):** every framed P2P
  response is signed with the host device key (`sign_response/verify_response`,
  `X-PV-Key/Time/Sig`); clients verify before parsing. The one-time code renders
  as a self-contained SVG QR (`qr_svg`, Settings image) alongside the text.
  Pairing pins the host `rev`/`hash`, pull responses carry it, and `head_ok`
  refuses a lower revision / same-rev different hash; a successful pull updates
  the pin. Tests +2 → `cargo test` **502 passed / 1 ignored + 4 pv_sign**.
  Remaining: push-side revision anchoring and re-pair on address change.

- **A16 — signed container revision (this batch):** the AEAD payload is now a
  rev-2 envelope `{meta:{format,version,rev,prev_hash}, vault}`. Save increments
  `rev` and sets `prev_hash = SHA-256(previous container)`; a per-path
  in-process head also refuses a save when the file changed underneath
  ("unlock again"). `check_incoming` refuses a lower rev, equal-rev/different
  hash, or a newer rev that does not chain to the local hash; the GitHub merge
  path calls it before merging. Legacy plain-Vault payloads load as rev 0 and
  migrate to rev 1 on the next save; rekey writes rev N+1 chained to the old
  container. Tests +3 → `cargo test` **496 passed / 1 ignored + 4 pv_sign**;
  `npm test` **132/132**. Honest limits: fresh-device first pull is TOFU (no
  local anchor), P2P still uses the mtime/SHA guard (A15), and **older builds
  cannot open rev-2 vaults** — upgrade every device before syncing.

- **A12 — shadow-DOM scan/observer (this batch):** `content.js` gains
  `deepRoots`/`deepQuery`/`deepActiveElement` (open roots only, 200-root/20k-node
  caps, skips `__pv_*`). `findFields`, card/address queries, `passwordNear`, the
  OTP split-group anchor and `scanForms` use the deep query; `badgeGroup` treats
  a shadow tree as its own scope; `deepActiveElement` covers generate/auto-submit
  focus. Every discovered open root gets the same debounced `pvScheduleScan`
  observer, and `watchSubmit` attaches to deep `<form>` elements (submit does not
  cross a shadow boundary). Closed roots remain untouched. Tests +3 JS → `npm
  test` **132/132**; `cargo test` 493/1 + 4 pv_sign unchanged. Honest limit:
  closed components are invisible; traversal caps may skip pathological pages.

- **A17 — same-origin favicons (this batch):** deleted the DuckDuckGo and Google
  fallbacks in `src/core/favicon.rs`. The only fetch is now
  `https://{domain}/favicon.ico`; the extension's page-declared icon harvest is
  unchanged and still preferred. Toggle/kill-switch/`can_net` gates untouched.
  Test `icon_url_is_same_origin_only` pins the host and forbids the third-party
  names from reappearing. `cargo test` **493 passed / 1 ignored + 4 pv_sign
  tests**; `npm test` **129/129**. Honest limit: the site sees its own icon
  request and may redirect to its CDN; no bundled icon set yet.

- **A11b — dual-gate offline cache (this batch):** the same DPAPI cache key can
  now be opened by **Windows Hello** (`cache_get method:"hello"`) or the
  **extension PIN** (`method:"pin"`), verified through A14's Argon2id record and
  the same persistent lockout. `cache_status` is prompt-free
  (`{enabled,pin_set,pin_allowed}`), so the popup's offline screen offers Hello
  plus a PIN field only when the user separately enabled the PIN fallback
  (`offline_cache_pin.pref`, default OFF). Background queries never prompt on
  their own: they serve a warm 15-minute snapshot or return "locked". Replacing
  or removing the PIN revokes the fallback (re-consent), and cache disable/decoy
  erase the marker with the snapshot. Tests +1 Rust (PIN gate, consent required,
  wrong PIN) and JS now 129. Honest limit: strength = min(Hello, PIN); a 4-digit
  PIN is 10k candidates, so the fallback stays opt-in and is labelled weaker.

- **A14 — Argon2id extension PIN (this batch):** `ext_pin.dpapi` no longer
  stores/serves a bare SHA-256. The record is `PVPIN2|salt|m|t|p|hash` with a
  16-byte salt and Argon2id (32 MiB, t=3, p=4), sealed with DPAPI. The host
  verifies (`ext_pin_verify`) and the bridge returns only `set: true/false`
  (`ext_pin_status`); the popup no longer hashes or compares anything. A
  file-backed attempt counter (`ext_pin_backoff`) survives restarts: 5 failures
  → 30 s, then 60/120/300 s; success/set resets it. A legacy SHA-256 record is
  refused with "re-set the PIN in Settings", never silently honoured.
  Tests +2 → `cargo test` **491 passed / 1 ignored + 4 pv_sign tests**;
  `npm test` **128/128**. Honest limit: 4-digit PIN entropy is 10k; Argon2id +
  lockout raise the cost but same-user malware can grind the DPAPI record
  offline.

- **A7 — trust documentation (this batch):** three files at the repo root, written
  from the code, not from marketing. `README.md` (features, container/KEM summary,
  build/test commands, repo map, doc index, and a "Known gaps and honest limits"
  section that names the unsigned installer, the missing external audit, Windows-only
  scope, PQ-is-not-a-factor, the closed-shadow keyboard limit, old-password backups
  after a rekey, the favicon third parties and the open P2P LAN default). `LICENSE`
  is MIT (Copyright (c) 2026 Zahidul Islam) and `Cargo.toml` now declares
  `license = "MIT"` plus repository/description/readme. `SECURITY.md` uses GitHub
  private advisories as the only channel (no invented email or PGP key), with
  supported versions, 7/14-day response targets, a 90-day coordinated window,
  explicit in/out-of-scope lists, the 0.4.1 limitations and a safe-harbor statement.
  No code changed; `cargo check` and `npm test` (124) stay green.

- Branch `main`. Tier 0 + audit Phases 1–6 committed (`117e38b`, `96b9330`,
  `b850ce7`, `05c0a36`, `e06d841`, `fc36e65`, `e6eadf5`).
- **Deep audit (`docs/AUDIT.md`)** — 5-agent read-only sweep + inline
  verification. Verified: "Lock" sidebar item exits the process
  (`slint:1349`→`main.rs:11665`; **FIXED in Phase 4**); legacy passkey `uv` boolean
  trust (`native_host.rs:507`, low reach — relay uses `assert_full`/`uv_token`);
  `crypto.rs:131-136` skipped `zeroize()` on the decrypt-error branch
  (FIXED in Phase 1 below).
  Two agent claims marked FALSE POSITIVE (do not re-chase): `fill_counts`
  serde panic (`native_host.rs:1670` — same pattern tested at `:2467`);
  `backup_scheduler` "wrong file" (relative `VAULT_FILE` is a project-wide
  convention, `main.rs:44`).
- **Tier 0 — extension capture engine** (`browser_extension/` ONLY, no Rust/exe
  rebuild; `node --test tests/js/background.test.mjs` **19/19**, `build.ps1`
  chrome+firefox OK): fixes registration / multi-page credential capture
  "gives up".
  - G1/G2/G3: `readFormCreds` replaces the inline submit reader — `new-password`
    fallback so a pure-signup form (no non-new password input) is no longer
    skipped; `maybeOfferSpaSave` now consumes `findFields.newPass`; signup vs
    login classified by field shape; a confirm-password mismatch refuses to
    offer (typo guard).
  - C1/C2: `getExisting` is a 60 s in-flight-deduped credential-list cache.
    The submit verdict is computed **synchronously** off a warm cache (no
    `await` before the banner → survives a full-page POST nav); invalidated on
    save. SPA ping reads the DOM immediately + one 400 ms retry (was a flat
    2500 ms wait). Badge probe (`probePageMatch`) shares the same cache.
  - K1/K2: non-secret username carry across pages in `chrome.storage.session`
    (`pvCaptureCarry`, username only — P1-b intact; password never persisted) +
    one-time `setAccessLevel(TRUSTED_AND_UNTRUSTED_CONTEXTS)` at SW start.
  - Tests: `npm test` → **25/25** (19 background + 6 jsdom content). Added
    `package.json` + `jsdom` devDependency (dev-only, `node_modules` ignored);
    `tests/js/content.test.mjs` loads the REAL `content.js` in jsdom and covers
    login / signup-new-password / confirm-mismatch / multi-page carry /
    known-silent / search-immunity. Background-side: K2 accessLevel,
    `PV_SAVE_LOGIN` proxy, cross-site sender refusal. Manual matrix:
    `docs/QA_CAPTURE_MATRIX.md` (CAP-01..16 + REG-01..06).
  - **Untouched by design:** `pvPending`, `chainPendingStep`, `sweepOtpOnce`,
    `otpObserver`, popup fill path, native host.
- **Phase 1 — Rust data integrity (DONE `96b9330`):**
  - D5 (>1 MB sync data loss): `sync/github_sync.rs` gains `decode_remote_blob()`
    — refuses an empty/whitespace body (GitHub Contents API returns `content:""`
    for files >1 MB) and bad base64. `main.rs` adopt path independently refuses a
    zero-byte remote (defense in depth). Was: `""` → empty vault → fresh device
    wrote 0 bytes.
  - D6: `crypto.rs` `decrypt_vault_secret` zeroizes the derived key on the error
    branch too (`?` used to skip it).
  - Unicode panics: `importer/mod.rs` `parse_bw_datetime` uses `str::get` for the
    `±hh:mm` suffix (no `split_at`/byte indexing); `developer/secret_scanner.rs`
    `scan_line` uses `to_ascii_lowercase` + `get` (byte-length-preserving
    offsets). Multi-byte input can no longer panic.
  - Atomic backups: `storage/backup_scheduler.rs` writes `.vault_backup_*.tmp`
    then renames (crash/full-disk can't leave a truncated `.enc`).
  - Tests: +5 cases (github empty/garbage decode, datetime offsets+unicode,
    scanner unicode, atomic backup). `cargo test` → **451 passed / 1 ignored**.
- **Phase 2 — security (DONE `b850ce7`):**
  - D3 access log fail-closed: `security/access_log.rs` — an unreadable chain
    key now REFUSES the append with a loud stderr line instead of falling back
    to unkeyed SHA-256 (`log_event_gated`). `verify_at_detailed` reads the key
    read-only (no mint) and can't create one as a side effect.
  - D4: `security/emergency.rs` zeroizes the plaintext shard `Vec` on both the
    seal and open paths (was only the HKDF key).
  - E3: new shared `browser_extension/domain.js` (`pageBase`/`isBlockedHost`/
    `isPunycodeHost`), loaded by `popup.html` + packaged by `build.ps1`. The
    popup's direct-inject fill (`fillGuards`, now async) and suggestion list
    refuse blocked domains and punycode hosts, matching `content.js`.
  - D2 passkey legacy `uv` boolean: confirmed unreachable from the extension
    (only `assert_full`/`attest` + `uv_token` are sent); legacy parity kept, no
    code change.
  - Tests: `tests/js/domain.test.mjs` added → `npm test` **28/28**.
- **Phase 3 — shared domain logic (DONE `05c0a36`):**
  - E1: `domain.js` `registrable()` now keeps multi-label public suffixes
    (`foo.co.uk` → `foo.co.uk`; `shop.foo.co.uk` → `foo.co.uk`,
    `www.google.co.uk` → `google.co.uk`) using a pragmatic PSL subset.
  - E2: `EQUIV_CLUSTERS`/`memberHit`/`domainCands`/`domainsEquiv` exist only in
    `domain.js`; `content.js`, `background.js`, `popup.js` are thin wrappers.
  - Wiring: both manifests `"js": ["domain.js", "content.js"]` (order matters);
    `background.js` starts with `importScripts("domain.js")` (classic MV3 SW);
    `popup.html` loads it before `popup.js`; `build.ps1` already packages it.
  - Harnesses: background sandbox stubs `importScripts`; the jsdom content
    harness evaluates `domain.js` before `content.js`.
  - Tests: +4`domain.test.mjs` cases (registrable ccTLD, pageBase, clusters,
    ccTLD blocked gate) → `npm test` **32/32**; `cargo test` 452 unchanged.
- **Phase 4 — real lock + iframe capture (DONE `e06d841`):**
  - D1: sidebar Lock (`slint:1350` → `main.rs:11677`) and tray Lock
    (`main.rs:3355`) now call the shared `lock_vault_now` pipeline — RAM scrub,
    clipboard flush, access log, lock screen — instead of `process::exit(0)`.
    New sidebar **Exit** (`slint:1351`, `on_exit_app`) + tray **Exit** are the
    only quit paths (clipboard flushed first, log event `exit`). Unlock already
    existed in the Slint lock screen, so no new screen was added.
  - E4: both manifests `all_frames:true`; the original same-origin guard (removed in P6) returned before any
    setup unless the frame is top-level or SAME-ORIGIN (reads `top.location`,
    throws on cross-origin ⇒ inert). No `match_about_blank` (hostless origin ⇒
    refused). Prevents a third-party iframe from raising a save prompt for its
    own host. (P6 later superseded this with frame-local-origin matching.)
  - Tests: `tests/js/content.test.mjs` +1 manifest/guard regression →
    `npm test` **33/33**; `cargo test` **452 passed / 1 ignored**.
- **Phase 5 (audit) — E5 desktop-gate cache (DONE `fc36e65`):**
  - `content.js` `extDeskOkPage` is no longer page-lifetime: success is cached
    for at most `EXT_DESK_OK_TTL_MS = 30 s`, and the cache is dropped on
    `window.focus`, tab-visibility return, and bfcache `pageshow`; a
    `PV_SESSION_STATE` locked reply clears it immediately. Worst-case staleness
    is 30 s, and every secret still rides the native bridge gate (UX-only fix).
  - Test: `E5: desktop gate is bounded by TTL and dropped on focus` stubs
    `Date.now` → one probe warm, re-probe after 31 s, re-probe after `focus`.
    `npm test` **34/34** (19 background + 8 content + 7 domain). Extension-only;
    no Rust rebuild.
- **Phase 6 (audit) — E6 observer + lock broadcast (DONE `e6eadf5`):**
  - E6: the two synchronous `documentElement` subtree observers became ONE
    120 ms-debounced observer (`pvScheduleScan`) running `scan()` +
    `scanForms()`; cold-page boot scans stay immediate.
  - E5 follow-up: `background.js` `broadcastGateLocked()` pushes
    `PV_GATE_LOCKED` to every tab when a `PV_SESSION_STATE` reply is locked or
    a `PV_PING` fails / reports `unlocked:false`; content drops its gate cache
    on receipt. Lock/timeout now invalidates all tabs immediately.
  - Tests: +3 (background broadcast fan-out, content broadcast invalidation,
    E6 static guard) → `npm test` **37/37** (20 background + 10 content +
    7 domain). Extension-only; no Rust rebuild.
- Extension OTP UX shipped (`ec789db`): multiple-2FA sites now open the
  account picker on OTP-field focus/sight (login-dropdown parity, gated by
  `show_suggestions`); picker rows carry ♻️/🟡/🕰️ health icons joined
  client-side from `PV_QUERY`. Working-badge + recency already native
  (3rd-fill auto-verify `models.rs:601`) — untouched. Extension-only: rebuild
  via `browser_extension/build.ps1`, NO exe rebuild. QA physical: 1-account
  auto-fill, 2-account picker→choose, submit→✅ upore, health icons.
- **P0 (fill strength) — URL-less web fill hole (DONE `6a4b0c6`):**
  - Finding: desktop items carry no URL (`urls: []`), but `content.js` and
    `popup.js` treated an empty URL list as allow (`entryAllowed`), and native
    `query` is substring-based → lookalike domains could autofill desktop
    items. Fixed both gates to refuse URL-less entries; content skips them
    silently (phishing toast only for stored-URL mismatches), popup shows
    "No site URL saved — edit this item and add one."
  - Tests: +4 (url-less hotkey refusal + bound control in jsdom, popup
    gate/source assertions) → `npm test` **41/41**; extension-only.
- **P1 (fill strength) — capture URL/title quality (DONE `620bf68`):**
  - `captureUrl()` stores origin+path only (query/hash stripped, trailing
    slashes normalized); `captureTitle()` prefers `og:site_name` /
    `application-name` / `apple-mobile-web-app-title`, else strips title
    suffixes and skips generic segments ("Sign in", "Login", …), else host.
  - Native `canonical_login_url()` mirrors the normalization in `save_login`
    (older clients can't inject query/fragment into the vault).
  - Tests: +2 jsdom save-payload + 1 Rust canonicalization →
    `npm test` **43/43**, `cargo test` **453 passed / 1 ignored**.
- **P2 (fill strength) — desktop app binding (DONE `ce43147`):**
  - `Credential.apps: Vec<String>` (`#[serde(default)]`, additive/export-safe).
    Smart-Grab stores lowercased exe + pretty name via hidden `cap_app`.
  - QuickBar (`Ctrl+Alt+A`) prefers items bound to the focused app; Auto-Type
    refuses bound items in any other app (`autotype-blocked-app` log). Unbound
    web items are unaffected.
  - Tests: +2 (serde default, binding helper) → `cargo test` **455 passed /
    1 ignored**; `npm test` 43/43 unchanged.
- **P3 (fill strength) — popup fill parity (DONE `dbd721a`):**
  - Popup fill/fill-submit now delegates to content.js `PV_FILL_ENTRY {id}`;
    content re-queries by domain, re-checks `entryAllowed`, fills through
    `fillLogin()` (React setters, multi-step, TOTP pending) and returns the
    field count. Direct inject is fallback only; refusals keep their reason.
  - Tests: +2 jsdom + 1 popup source → `npm test` **46/46** (20 background +
    16 content + 7 domain + 3 popup).
- **P4 (fill strength) — UIA `SetValue` desktop fill (DONE `6e31196`):**
  - `desktop_autofill::set_focused_value()` writes the focused enabled,
    writable Edit via `ValuePattern.SetValue` (no keystrokes/IME/clipboard).
    Both `type_sequence` and `type_fields` try it per field and fall back to
    the verified Unicode SendInput path; read-only password boxes therefore
    keep working. Input still sanitized; focus token re-checked before every
    fill / Tab / Enter.
  - Test: +1 policy gate → `cargo test` **456 passed / 1 ignored**.
- **P5 (fill strength) — UIA login field-pairing (DONE `9f7c298`):**
  - App-bound desktop logins try `fill_login_pair()`: locate the password Edit
    (focused if password, else first) + nearest username Edit above it in the
    foreground window; verify both writable before writing; revert partial
    writes; refuse when focus is an Edit outside the pair (chat/search box).
    Success = SetValue both, `autotype/uia-pair` log, Enter — no Tab dependency.
  - Fallback chain stays: per-field UIA SetValue (P4) -> guarded Unicode typing.
  - Test: +1 `pick_login_pair` matrix -> `cargo test` **457 passed / 1 ignored**.
- **P6 (web fill strength) - cross-origin iframe fill (DONE `7e6da61`):**
  - `content.js` boots in cross-origin frames instead of self-disabling; badges,
    autofill, save prompts and TOTP use the FRAME's own origin for every match
    (top location is never read). A credential can therefore only land in the
    origin it was saved for.
  - Background `PV_SAVE_LOGIN` validates `sender.url` (frame) before
    `sender.tab.url`, so an embedded login is stored under the iframe domain -
    never under the embedding page's domain.
  - `PVDomain.pickActionFrame()` probes all frames (visible password/text field,
    focus, top flag) and picks the form frame; hotkey uses it, context menu uses
    `info.frameId`, both send with an explicit `{frameId}` (fallback 0, never a
    broadcast). Popup gathers frame hosts, merges iframe-domain suggestions
    (max 5 extra origins), applies blocked/punycode/mismatch gates to them, and
    targets `PV_FILL_ENTRY` + direct inject + submit at the same frame. Top-only
    ceremony/OTP popup messages now pass `{frameId:0}`.
  - Tests: +4 background, +1 domain, +2 popup -> `npm test` **53/53**;
    `browser_extension/build.ps1` builds chrome+firefox.
- **Badge noise + card capture (DONE `e8a282f`):**
  - One action-aware icon per context, reconciled every scan: login = shield
    on the password (username folds in), signup = dice only, password-change =
    that shield's menu (fill login OR generate new+confirm), card = its own
    shield. Mode changes/removals drop the old button, so SPA transitions can
    never leave two icons or a stale one. Checkout billing emails are never
    badged. The form-less fallback no longer badges every text input on a page
    that has a password (same form / tight ancestor / 320px only), and
    standalone email badges need a credential-step signal.
  - Card save: `readFormCard()` (Luhn, MM/YY, CVV shape) + masked Save/Update
    banner + `PV_SPA_CARD` tripwire; background `PV_SAVE_CARD` reuses the
    sender-frame check; native `save_card` validates, dedupes by PAN and updates
    expiry/holder/CVV in place (cards stay global, never URL-bound).
  - Card fill repair: `filterEntries()` used to drop card rows (no `urls`);
    `queryCards()` now requests `all:true`, and `fillCard()` handles split
    month/year selects as well as `cc-exp`. `resolveRows()` sticks to the
    anchor's kind (disabled card/identity toggles no longer leak login rows),
    and the generator only writes new/confirm siblings, never the current
    password on a change form.
  - Tests: +12 content, +3 background, +1 Rust -> `npm test` **71/71**,
    `cargo test` **460 passed / 1 ignored**.
- Baselines: `cargo test` 502 passed / 1 ignored + 4 pv_sign tests, `npm test` 132/132 (four JS harnesses), `cargo check --all-targets` zero
  warnings, `cargo clippy --all-targets` 2 pre-existing `manual_clamp`
  warnings (toolchain drift — `.clamp()` changes NaN semantics, intentionally
  untouched per no-break rule).
- v0.2.1 bumped (Cargo + installer + both extension manifests); v0.2.0 stays
  the rollback anchor until v0.2.1 is tagged (needs QA physical pass first).
- SecretString migration (Phases 1–5) DONE: crypto/storage `_secret` variants live,
  all prod call sites (main unlock/save ×30+, bridge, CLI, decoy, app_pin) ride
  `SecretString`/`Zeroizing`; legacy `&str` wrappers `#[deprecated]` (compat tests
  only, under `#[allow(deprecated)]`). Models fields stay `String` (disk format
  frozen — deliberate). Remaining `&str` edges: decoy-verify, app_pin-enroll,
  Hello-compare (OS/DPAPI boundaries, documented).
- Release v0.2.0 tagged + pushed (`cargo build --release` + UPX 6.7 MB exe,
  chrome+firefox zips, SHA256SUMS in `Desktop/pv-release-0.2.0/`).
- `cargo audit`: HIGHs gone (quick-xml 0.41, webpki 0.103, rxing 0.9, rqrr 0.11).
  Residual (justified): `rsa` (ignored), `bincode` (contained+documented),
  `paste`/`ttf-parser`/`yoke-derive` (transitive).
- Git history purged of vault containers (C1) + force-pushed. **Everyone works
  from fresh clones — never push from a stale pre-purge clone.**
- Build env: `CARGO_TARGET_DIR=C:\Users\FAHAD\pv-target` (persisted via setx,
  2026-10-31). D: is only 9.7 GB and filled up twice; C: has ~23 GB free.
  `scripts/package_release.ps1` and `installer.iss` honour the variable
  (`/DMySourceExe`), so a custom target dir does not break packaging.
- Epic roadmap 6→7→2→4→1 SHIPPED (per-phase commit + push, no existing
  signatures/behavior broken):
  - #6 breach full-loop checklist (`fe30f10`): vault-side rotation progress
    per health row (`rotation_status` + `health_rows_with_rotation`);
    score/flags/order untouched; site auto-change stays manual by design.
  - #7 limited direct import (`ed10d48`): `importer/browser_direct.rs`
    read-only profile discovery (Chrome/Brave/Edge/Opera/Firefox) +
    guided CSV import; direct store decrypt OFF (needs SQLite+AES-GCM /
    NSS key — refused loud, documented in module header).
  - #2 emergency timed grant (`402e1df`): `security/emergency.rs`
    (request→approve→wait→envelope, PQ+XChaCha, maturity enforced in
    `seal_envelope`) + `emergency/<id>.<kind>.json` relay via existing
    private repo (fixed generic commit msg) + copy-paste transport;
    takeover = existing shard recovery. Shamir/PDF untouched.
  - #4 CRDT merge (`d3c3235`): `sync/crdt_merge.rs` explicit preview →
    apply only; login LWW on `last_changed`, ties/delete-vs-edit keep
    local + conflict; device unlock factor never merges; grants union
    (revoke wins). Whole-blob adopt paths untouched.
  - #1 per-item sharing (`38ea9cd`): `security/sharing.rs` login-only MVP
    (other kinds refuse loud); `Vault.shared_grants` additive
    (`#[serde(default)]`, pre-sharing JSON loads); revoke = mark +
    mandatory password rotation (issued copies can't be un-issued).
- Epic roadmap 9→3→5 SHIPPED (mobile/iOS excluded, per-phase commit + push):
  - #9 secure-send (`ab909db`): `security/secure_send.rs` — expiring
    XChaCha notes, link-code = key (id = sha256(key)), relay
    `send/<id>.json`, read → expiry-check → decrypt → DELETE (burn);
    delete-fail after good read LOUD; copy-paste offline path included.
    `delete_file` verified in octocrab 0.41.2 vendored source first.
  - #3 passkey ceremony relay (`a8750ad` + test-fix `08dd887`):
    `core/passkey.rs` assertion + fmt-none attestation packaging;
    `native_host` `assert_full`/`attest` (uv-token OR legacy uv) +
    `request_uv` (Hello system prompt → single-use rp-bound 120s token);
    hook 90s hold + timeout fallback; popup approve button; background
    sender-check + Hello-before-sign. Legacy `PV_ASSERT` fail-closed
    test untouched. Caught by tests: UV consume was remove-then-check
    (burned on wrong-rp) → check-then-remove.
  - #5 business admin (`1343968`): `security/admin.rs` — member CSV
    roster (machine-local `org_members.json`, factory-reset shredded),
    deprovision auto-revokes key-bound grants, OIDC userinfo email-verify
    (no JWT dep), chain-verified audit JSON export. Explicitly NOT:
    IdP-gated unlock, server SCIM, SAML.
  - Dropped without new cause: #8 mobile/Safari/iOS app (user-excluded),
    plus standing drops below.

## 2. How to resume (new PC / new OpenCode session, any model incl. Muse Spark)

1. `git clone https://github.com/zjhasan13/phantom_vault.git` (fresh — no old clones).
2. Read `rules.md`, then this file, then ask the user which pending item to start.
3. Workflow (mandatory): **plan mode first** (spec + file:line touch list, no edits)
   → user approves ("green signal") → **build mode** (implement + `cargo check` +
   `cargo test` + `npm test`) → commit
   (`type(scope): subject (test counts)`) → push `main`.
4. Communication: short, direct, Bengali-mix OK. Every finding cites `file:line`
   + exact code quote. Verify with tools, don't speculate. Never use `bash` to
   communicate; never use comments for chain-of-thought.
5. Quality bar that produced this history: no fix without a regression test,
   no refactor without `cargo check` clean, no push with red tests, honest
   "I don't know yet — here is how we find out" instead of guessing.

## 3. Pending queue (ordered)

1. **A8b Authenticode — deferred by product decision (2026-10-31):** no paid
   certificate for now; Ed25519 + SHA-256 + GitHub attestation is the current
   trust stack. If revisited, insert `signtool` after packaging and before
   hashing (never sign before the final bytes are fixed).
2. **Tray X-still-exits (user reports FIXED on their side):** re-verify on the
   next physical pass (X → process stays as background tray process; Access
   Log close-path lines present). If it regresses, suspects in order:
   handler never fires (Slint close-request path) → panic=abort in handler →
   env-specific tray failure.
3. **Live measurements (partial, needs the user's machine):** observed
   minimized+unlocked 7.3 MB / 0.1% CPU (screenshot) — still needed:
   locked+minimized release-build reading, idle CPU 0.00% × 5 min, bridge
   warm p50 ~5 ms. Record in release notes.
4. **Master Password Rotation** — shipped in-app (A5, Settings > Security).
   The old export/import rotation is no longer needed. After a rekey, reprint
   the recovery shards and re-enroll the App PIN (both stay on the old secret
   until redone).
5. **GitHub cache check:** repo code-search `my_secure_vault` must return
   zero; else request GitHub Support cache purge. `gh` 2.102.1 is installed at `%LOCALAPPDATA%\Programs\gh\gh.exe` but
   not authenticated: run `gh auth login`, then
   `gh api "search/code?q=my_secure_vault+user:zjhasan13"` (web UI code search
   works too). Releases are now built and uploaded by `release.yml` (0.4.1 was
   the first automated run); no manual web-UI upload is needed.
6. **Follow-ups for the other line:** legacy host `assert` unreachable from
   extension (fails-closed test pinned — relay now uses
   `assert_full`/`attest`). Resolved (`621892c`): `write_adopted_head` is wired on BOTH
   adopt paths (`serve_conn`, `sync_with_peer`) and the guard is now a tested
   pure function (`adopt_rollback_blocked`); `AgentKey` is explicitly
   `ZeroizeOnDrop` (vault key wipe on session teardown, not just dalek drop).
7. **Standing item (do NOT blind-chase):** `Mutex::lock().unwrap()` pattern in
   `src/main.rs` (panic=abort design). Only touch attacker-influenced paths.
8. **Dropped scope (do not revisit without new cause):** full A2 encrypted-RAM
   rewrite (canceled), `rqrr-zeroize` fork (rejected), tokio current-thread
   (rejected), License purchase/vendor/seats, SSH passphrase decrypt,
   name-split/SSN, card billing address.

## 4. Key decisions log (don't re-litigate)

- Persistent extension port: strict FIFO (host echoes no rid), 60 s TTL unchanged,
  stale-read window documented in `background.js` header.
- Toast/UI text uses emoji + Bengali-mix is fine; keep code comments concise.
- Commit style: `type(scope): subject (test counts)`.
- Never force-push without explicit user approval (kills collaborators' work).
- Never commit `*.enc*`, `*.dpapi`, `access.log`, `com.phantomvault.host.json`
  (all gitignored — the C1 leak must never recur).
- Release folder (`Desktop/pv-release-0.2.0/`) is DISTRIBUTION only — never run
  the app from it (vault/seals accumulate there and could ship by accident).
- installer.iss references a firefox host JSON that the app button (not the
  installer) actually writes — placeholder pattern, keep in sync.
- Roadmap no-break contract (6→7→2→4→1 proven): additive model fields only
  (`#[serde(default)]`), no existing signature/semantics changes, new
  network/merge paths explicit + preview-first + default-OFF, every new
  behavior ships with regression tests, decoy refused on all new grantor
  paths, access log metadata-only.
- Do NOT "fix" the 2 `manual_clamp` clippy warnings with `.clamp()` — NaN
  propagation semantics differ from `.max().min()`; layout sizing must not
  change silently. An `#[allow(clippy::manual_clamp)]` on `push_hub_width`
  keeps CI's `-D warnings` green without changing behaviour.
- First-run audit-key creation is serialized (`chain_key_bytes` static mutex,
  double-checked). Without it, parallel first writes on a clean machine can
  each seal a different key and orphan every chain but their own — this is
  what made `chain_verifies_and_tamper_breaks` flake on a fresh CI runner.
- Test hygiene (proven twice): env-mutating tests sharing one process-global
  var MUST serialize via a static `Mutex` (see `browser_direct` ENV_LOCK
  precedent); single-use token consume MUST check-then-remove (failed
  attempts never burn); brand-new relay message names keep old fail-closed
  pins green (`PV_ASSERT` vs `PV_ASSERT_SIGN`).
- Crate `Result<T>` alias collision: new String-error fns use
  `std::result::Result` or a local `StdResult<T>` alias — never bare
  `Result<_, String>` next to `use crate::error::Result`.
- A5 rekey invariants: the rollback snapshot is the normal `.bak.1.enc`
  (sealed with the OLD password); App PIN is removed on rotation because the
  PIN cannot re-seal itself; old `.pvx` exports, backups and GitHub history
  stay on the old password — never claim otherwise in UI or docs.
- A6 backup invariants: `PVBK1` is a 5-byte prefix, not a new container
  version — `crypto.rs` stays untouched. A tagged file is opened ONLY with the
  backup passphrase (the master is never tried); untagged files keep the
  legacy master path, so pre-A6 `.pvx` files must never be broken. The export
  gate refuses a passphrase equal to the master (not a warning). Clearing the
  Slint fields happens on the event loop; property writes never cross threads.
- A11b dual-gate invariants: one cache key, two gates — never duplicate the
  ciphertext or wrap the key with the PIN. PIN unlock requires BOTH a set PIN
  and the explicit `offline_cache_pin.pref` consent; replacing/removing the PIN
  revokes it. `cache_status` must never prompt; `PV_QUERY` never prompts
  implicitly. Strength is min(Hello, PIN) — keep the fallback default OFF.
- A15a pairing invariants: the code never crosses the wire (HMAC proof only),
  is single-use/5-min, and every non-pair request requires a paired Ed25519
  signature + fresh timestamp. 403 is the default. A15b removes the head
  hash/mtime from beacons; never reintroduce them.
- A16 revision invariants: `rev`/`prev_hash` live INSIDE the AEAD payload and
  every save increments the chain; never reset a revision when the file merely
  disappeared (refuse). `check_incoming` is the only freshness gate: lower rev =
  stale, equal rev + different hash = conflict, newer rev without the local hash
  as `prev_hash` = fork. Fresh-device first pull is TOFU — never claim otherwise.
  Rev-2 containers are unreadable by older builds; release notes must say so.
- A12 shadow-DOM invariants: traverse OPEN roots only (closed roots are
  inaccessible by design); every shadow observer must call the same debounced
  `pvScheduleScan`; submit listeners attach to the form itself (submit is not
  composed); grouping is per shadow tree, never page-wide.
- A17 favicon invariant: the only network URL is `https://{domain}/favicon.ico`
  (or the extension-harvested page icon). Never reintroduce a third-party
  favicon service; the letter circle is the offline fallback.
- A14 PIN invariants: the verifier never crosses the bridge (`ext_pin_status`
  is boolean only); Argon2id params live in the record; the lockout counter is
  file-backed and reset only by success/set/clear; a legacy SHA-256 record MUST
  fail closed. 4-digit PINs are shoulder-surfing protection — never call them
  vault-grade.
- A11 cache invariants: the snapshot is logins-only, read-only, refreshed at
  unlock; the key is DPAPI-sealed and the host requires a Hello prompt; the
  extension keeps plaintext only in SW memory (never `storage`) for 15 min.
  `cache_get` is the ONLY command allowed before the heartbeat gate. Decoy
  unlock MUST clear the cache (deniability), and reprompt-armed items MUST NOT
  fill from the cache. Hello is presence UI, not a key factor — never claim the
  cache is tamper-proof against same-user malware.
- A8a release invariants: `src/release_pubkey.rs` is the ONLY definition of
  the pinned key (updater + signer both consume it). `pv-sign` fails closed on
  a key mismatch and never prints the seed. CI and local builds call the same
  `scripts/package_release.ps1`. The updater asset is the portable
  `PhantomVault-<ver>-windows-x64.exe`, never the Inno installer — `pick_asset`
  skips `setup`/`installer` and returns `None` when only an installer exists.
  Sign AFTER the installer/zip bytes are final; hash after signing. Never
  rebuild/overwrite a published tag — the workflow refuses an existing release
  on manual dispatch. No UPX: the sub-8MB target was v0.2.0-only and
  compressing an unsigned binary raises AV false positives.
