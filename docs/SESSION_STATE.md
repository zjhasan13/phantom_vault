# SESSION_STATE — PhantomVault (read me first)

> Short, current snapshot for a fresh agent/session. Deeper history lives in
> `docs/HANDOFF.md`; invariants live in `rules.md`; the agent contract lives in
> `AGENTS.md`. Keep this file under ~150 lines and update it at the end of every
> batch.

## Snapshot

| Field | Value |
|---|---|
| Date | 2026-11-15 |
| Branch / HEAD | `main` @ `55e449f` (A27 L2b signed host replies) |
| App version | 0.4.2 (`Cargo.toml`) |
| Extension version | 0.4.2 (`browser_extension/manifest.json`) |
| Installer present | 0.4.2 built locally, **unsigned** — `installer-output/PhantomVault-Setup-0.4.2.exe` (10.06 MB) and `dist/release-0.4.2/` |
| Open work | `docs/baki kaj.md` — security gaps and logic/UX gaps not yet fixed |
| Manual QA | `docs/MANUAL_TEST_GUIDE.md` — non-technical, feature-by-feature checklist + 15-min smoke pass |
| Rust modules | 88 `.rs` files under `src/` |
| UI | one file: `ui/appwindow.slint` (~3.8k lines) |

## Last code batch (2026-11-16a) — A27 L1, breach scoping, loopback test hygiene

- **L1 step 2 is in.** `serve_cli` now refuses (release builds) a spawn whose
  parent is not a browser, not Authenticode-signed, or signed by the wrong
  vendor. `src/windows_native/authenticode.rs` does the Win32 work:
  `WinVerifyTrust` (`GENERIC_VERIFY_V2`, no UI, cache-only URL retrieval,
  `WTD_REVOKE_NONE`) then `CryptQueryObject` →
  `CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)` →
  `CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT)` → `CertGetNameStringW`.
  `host_provenance::spawn_refusal` is the single decision point and is
  unit-tested for every verdict.
- **Vendor pinning, not just "signed".** `publisher_matches_image` requires the
  signer token to fit the image (`chrome.exe`→google, `msedge.exe`→microsoft,
  `firefox.exe`→mozilla, `brave.exe`→brave, `chromium.exe`→google/chromium,
  `vivaldi.exe`→vivaldi, `opera.exe`→opera), so a signed but unrelated binary
  renamed to `chrome.exe` is refused and logged with its publisher.
- **Escape hatch, documented.** `PV_ALLOW_UNSIGNED_BROWSER=1` accepts a
  *missing* signature (LibreWolf, ungoogled Chromium) and audit-logs that it was
  used; it does not cover a broken chain or a wrong publisher. `SECURITY.md`
  says plainly that a process spawning the host can set the variable itself, so
  the hatch is a usability valve, not a boundary.
- **Honest limits:** revocation is not checked (host start must stay offline and
  fast), and a byte-identical copy of a signed browser passes. Both are in
  `SECURITY.md` and `docs/A27_HOST_PAIRING.md` §3 L1.
- Tests: `cargo test -j 1` **643 passed / 0 failed / 4 ignored**
  (`TEST_EXIT=0`); `cargo clippy --all-targets -j 1 -- -D warnings`
  **CLIPPY_EXIT=0**; `npm test` **191 pass / 0 fail**; `npm run test:tokens` →
  `UI tokens OK: 21 palette values`. The real WinTrust FFI is exercised by
  `a_real_signed_browser_is_trusted_when_present`, which uses the machine's
  Edge install (skip-guarded) — on this box `Get-AuthenticodeSignature` reports
  `Valid | CN=Microsoft Corporation, O=Microsoft Corporation` and the test
  accepts it as `Trusted`.
- **`PV_BREACH` is top-frame only.** Any content-script sender could ask the
  host for a breach verdict, which made the extension a free HIBP proxy and a
  timing oracle for arbitrary candidate passwords. Content scripts already run
  in the top frame only, so the gate costs nothing: a sender with a tab must be
  an `http(s)` frame with `frameId 0`, else the request is refused *before* the
  host is spawned. The popup (no sender tab) still gets the vault-derived `reuse`
  count. Manual guide notes that a cross-origin iframe login gets no breach hint.
- **Three loopback/KDF flakes defused** (`share_serve` one-view, `api::local`
  `os error 10053`, `crypto::tests::test_legacy_v2_still_opens`). All three were
  test-harness races on Windows, not product bugs: `share_serve` now waits for a
  side-effect-free `/health` before asserting, treats an empty/unparsable reply
  as a retryable transport error, and never retries the one-view request (a
  retry after a lost reply would fake a 404); `api::local` retries `client_get`
  up to 5×50 ms and the assertions do not count pending requests; the crypto
  test flakes because one Argon2id call allocates 64 MiB × 4 lanes and
  `-j 4` runs several KDF tests at once, so `derive_key_secret` takes a
  test-only `KDF_TEST_LOCK` (production never touches it). Proven by 15
  consecutive `-j 4` runs of each test.

## Last code batch (2026-11-15c) — A27 L2b: the host signs its replies

- **The gap this closes.** L2 proved *the caller* holds the pairing secret, but
  nothing proved *the answer* came from the real host. A look-alike process on
  the port could feed the popup fabricated items. Now every reply carries
  `"mac":"<64 hex>"` =
  `HMAC(secret, "pv1r|req_cmd|req_seq|req_ts|sha256(canonical_reply)")`, and the
  popup refuses a reply whose MAC is missing, wrong, or belongs to another
  request. An unsigned request still gets an unsigned reply (unpaired installs
  are unaffected).
- **Canonical form, not raw bytes.** Requests can be MACed over the wire bytes
  (`JSON.stringify` once, host strips `mac`), but Chrome hands the extension a
  **parsed object** for replies, so key order and `1.0` vs `1` are gone. Both
  sides canonicalise: recursively sorted keys, integral floats printed without a
  fraction. Rust `host_pairing::canonical_json` / `reply_mac`; JS
  `canonicalJson` / `verifyReply`. Shared known-answer vector
  `4a0b4fe89bb5b65197d7c4e01af4bd58e370a247a5e629faabb59549e625ada8` is asserted in
  both suites, so the two implementations cannot drift.
- **Rust wiring without touching 20 call sites.** `serve_cli` writes through a
  `SignedOut<W>` stdout wrapper: it sees one complete frame per `write_all`,
  re-encodes it with the MAC, and is a pass-through when there is nothing to
  sign (no secret, or a request with no `seq`/`ts`). `emit_err` became a free
  function over that writer. `output.bind(&req)` runs once per frame.
- **JS wiring keeps FIFO.** Reply verification is async, so the port listener
  resolves/rejects and only then pumps the next queued frame — still exactly one
  frame in flight. The one-shot fallback path verifies too. `PV_PAIR` maps a
  failed reply MAC to "That code did not match the desktop — check the code and
  try again." instead of showing a crypto string.
- **Docs corrected for honesty.** `SECURITY.md` no longer claims the host lacks
  a pairing secret (release builds enforce it, replies are signed); it now
  states the remaining non-goal: a same-user process that can read
  `chrome.storage.local` or DPAPI-unseal the secret still wins.
- Tests: `cargo test -j 1` **637 passed / 0 failed / 4 ignored**
  (`TEST_EXIT=0`); `cargo clippy --all-targets -j 1 -- -D warnings`
  **CLIPPY_EXIT=0**; `npm test` **189 pass / 0 fail**; `npm run test:tokens` →
  `UI tokens OK: 21 palette values`.
- New JS tests: signed reply accepted; unsigned reply refused; tampered body
  refused; replayed reply from an earlier `seq` refused; unpaired install still
  accepts unsigned replies; reply KAT. New Rust tests: reply KAT + canonical-JSON
  fixed point (nested, unicode, `-0.0`, `2.5`).
- Still open in A27: the Authenticode publisher check (L1 step 2). Live E2E with
  the installed build + reloaded extension is still a manual pass.

## Last code batch (2026-11-15b) — A27 L2: pairing UI + step-2 enforcement + manual QA guide

- **The user-facing half of A27 L2 is now on screen.** Settings → **Sync &
  Devices** → *Extension pairing* has `Show pairing code` and `Revoke pairing`.
  The code is the DPAPI-sealed 20-byte secret printed as 8 Crockford groups
  (`FM6C-G96Y-CW5K-…`), minted on first use and **re-shown rather than rotated**
  when one already exists, so pairing a second browser cannot silently break the
  first. Revoke deletes the seal and logs `pairing revoked`.
- **Popup side:** `Desktop pairing` row in Settings (code field, Pair, Unpair).
  `parsePairCode` mirrors `host_pairing::parse_code` (I/L→1, O→0, hyphens and
  spaces skipped, trailing bits must be zero, exactly 20 bytes), stores only the
  decoded bytes in `chrome.storage.local.pv_pair_secret`, then sends `PV_PAIR`.
  A refused code wipes the secret instead of leaving a dead one behind.
- **`pair_confirm` is answered before the heartbeat/unlock gate.** The reply is
  only `{ok,paired}` or an error string, so it leaks no vault content; that lets
  the popup prove a typed code while the desktop app is locked or closed.
- **Fixed a real split-brain bug found during the on-screen pass:** the seal was
  written to `pairing_path()`, which resolves through the host's
  `%LOCALAPPDATA%\PhantomVault\project_dir.txt` marker. A stale marker (a dev
  install that recorded the repo root) put the app's seal in the repo while the
  host would look elsewhere. The desktop app now rewrites the marker at startup
  (`native_host::record_data_dir`, unit-tested), so portable mode and moved vault
  dirs follow.
- Tests: `npm test` **181 pass / 0 fail** (73 in `background.test.mjs`, incl.
  `PV_PAIR` accepted/refused); `display_code`'s vector
  (`000G-40R4-0M30-E209-185G-R38E-1W81-24GK`) is asserted in both Rust and JS;
  tokens OK. On screen: code + status line captured after unlocking the demo
  vault.
- **Step 2 is in (`enforce_pairing`).** `serve_cli` sets
  `enforce_pairing = !cfg!(debug_assertions)`: a release build refuses every
  unverified frame (offline cache included) with a message that names the fix,
  and a debug build stays warn-only so a dev loop does not need a re-pair per
  rebuild. `pair_confirm` stays exempt — it is how a user pairs, and its reply
  carries only the MAC verdict. `pairing_refusal()` is the single place that
  decides "serve or refuse" and is unit-tested.
- **Manual QA guide:** `docs/MANUAL_TEST_GUIDE.md` — 14 sections written for a
  non-technical tester (setup with `PHANTOM_VAULT_DIR=C:\pv-demo`, reset, report
  template, feature-by-feature expected results, 15-min smoke pass, known
  traps, honest "still open" list). `tests/js/manual_guide.test.mjs` guards it:
  every section, the release pairing warning, the four gate commands, the reset
  path, and the absent-by-design list must stay in the file.
- Tests: `cargo test -j 1` **635 passed / 0 failed / 4 ignored**
  (`TEST_EXIT=0`); `cargo clippy --all-targets -j 1 -- -D warnings`
  **CLIPPY_EXIT=0**; `npm test` **0 fail** (181 + 6 new guide tests);
  `npm run test:tokens` → `UI tokens OK: 21 palette values`.
- On screen (dev build, demo vault): code shown as
  `T2AA-RVRX-PWB3-HDT3-PHM8-QYXF-WPGB-NHKW`, seal written to
  `%TEMP%\pv-ui\host_pairing.dpapi`, `Revoke pairing` removed it and logged
  `pairing revoked`.
- Still open in A27: response MACs and the Authenticode publisher check (L1
  step 2).

## Last code batch (2026-11-15a) — dependency audit: jsonwebtoken 9 -> 10

- **Closed the open Dependabot alert.** It was `jsonwebtoken 9.3.1`
  (GHSA-h395-gr6q-cpjc, type confusion → authz bypass, fixed in 10.3.0), pulled
  transitively by `octocrab 0.41`. `octocrab = "0.50"` is the first release that
  requires `jsonwebtoken ^10`; the lock now has **jsonwebtoken 10.4.0**.
  - `octocrab 0.50` also adds three transitive crates (`camino`,
    `cargo-platform`, `cargo_metadata`). No direct dependency was added, and no
    call site changed: `client()` and `is_not_found()` compile as they were.
- **Found by scanning the whole lock, not by guessing.** `npm audit` is clean;
  the Cargo side was checked by querying OSV for all 875 locked crates and then
  evaluating each advisory's affected ranges locally (the raw OSV batch result
  lists every historical advisory for a crate name, so 118 "hits" collapse to
  16 real ones).
- **Corrected a stale audit note.** `audit.toml` / `security.yml` claimed
  `rsa` and `crypto-bigint` were "not in the build graph". They are:
  `cargo tree -i rsa` → `rsa 0.9.10 <- jsonwebtoken 10.4.0 <- octocrab`. Both
  stay ignored, but now with the real reason: the vulnerable operation is
  unreachable (no JWT is ever signed or verified — the app uses a personal
  access token, not GitHub App auth), so RUSTSEC-2023-0071's decryption oracle
  has no code path here.
- Remaining lock advisories are informational: unmaintained crates (`bincode`,
  `paste`, `pin-utils`, `ttf-parser`, `zvariant`/`zbus_names` — the last two are
  Linux-only via `nokhwa`) plus `quinn-proto`/`rustix`/`zlib-rs`, none on a path
  this app exercises.
- Gates: `cargo check` **EXIT=0** (5m20s); `cargo test -j 1` **633 passed /
  0 failed / 4 ignored** (`TEST_EXIT=0`); `cargo clippy --all-targets -j 1 --
  -D warnings` **CLIPPY_EXIT=0**.

## Last code batch (2026-11-14d) — A27 L2 core: pairing secret + frame MAC

- **`src/security/host_pairing.rs` (new).** 20-byte (160-bit) CSPRNG secret,
  DPAPI-sealed at `host_pairing.dpapi`; Crockford-base32 code as 8 groups of 4
  (`display_code` / `parse_code`, I/L→1, O→0); `mint_at` / `load_at` / `clear_at`;
  `canonical("pv1|cmd|seq|ts|sha256(body)")`, `frame_mac`, constant-time
  `verify_frame`, `ts_fresh` (±60 s), and `FrameGuard` (per-session `seq` must
  strictly increase).
  - **Doc correction:** the first draft said "32 CSPRNG bytes / 8 groups of 4".
    8×4 = 32 characters = 160 bits, so the secret is 20 bytes; a 32-byte secret
    would need 52 characters. `docs/A27_HOST_PAIRING.md` §3 L2 now says 20 bytes.
- **How the MAC input is defined (no key-order trap).** The body is the frame
  *without* the `mac` field, byte for byte. The extension stringifies
  `{...request, seq, ts}` for the MAC and posts `{...request, seq, ts, mac}`;
  `JSON.stringify` keeps insertion order, so the host rebuilds the exact input by
  removing `,"mac":"…"` from the raw line (`strip_mac_field`, tested with `mac`
  first/middle/last). `decode_frame_raw` keeps the raw bytes for this.
- **`serve_cli` (step 1, warn-only).** Loads the secret if present, verifies every
  frame's `seq`/`ts`/`mac`, and logs `host mac rejected: <reason>`. Serving is
  unchanged — step 2 flips the verdict into a refusal.
- **Extension.** `background.js`: `signFrame` adds `seq`/`ts`/`mac` to every
  `hostRequest` when `chrome.storage.local.pv_pair_secret` holds 20 bytes
  (WebCrypto HMAC-SHA256); unpaired installs send plain frames.
- **Cross-language proof.** One known-answer vector, computed with .NET
  `SHA256`+`HMACSHA256` and asserted by both suites:
  `pv1|list|7|1763000000|8198cfed…567b` → `b80c4528…278d`.
- Not shipped yet: the desktop **Pair extension** button (Slint + Rust callback),
  the popup code-entry UI, `pair_confirm`, response MACs, and step 2 enforcement.
- Gates: `cargo clippy --all-targets -j 1 -- -D warnings` **CLIPPY_EXIT=0**;
  `cargo test -j 1` **633 passed / 0 failed / 4 ignored** (`TEST_EXIT=0`);
  `npm test` **178 pass / 0 fail** (4 new A27 tests); `npm run test:tokens` OK
  (21 palette values).

## Last code batch (2026-11-14c) — content-sized modals (U1) + A27 L1 probe

- **U1 (all of it).** Nine more dialogs had no `height` on their inner
  `Rectangle`, so they took the parent's and rendered full-window tall. Fixed by
  binding the content layout's `preferred-height`: duplicate-confirm, What's New,
  attachment preview, factory reset, new-PC, webcam, access log, shred source,
  recovery shards (`ui/appwindow.slint`).
  - `ScrollView` reports `preferred-height: 100%`, so the two dialogs that hold
    one pin it: access log `max-height: 340px`, recovery shards `max-height:
    360px` (its five long shards are now scrollable instead of overflowing).
  - Recovery shards also caps the dialog itself:
    `Math.min(shardsdlg_lay.preferred-height, parent.height - 24px)`.
- **A27 L1, step 1 (warn-only).** New `src/windows_native/host_provenance.rs`:
  Toolhelp snapshot → parent PID → `QueryFullProcessImageNameW` → file-name
  allow-list (`chrome/msedge/brave/firefox/chromium/vivaldi/opera`). `serve_cli`
  logs one line per start (`parent ok: chrome.exe` / `WARN parent not a known
  browser: <path>`). No behaviour change; step 2 (refuse) is the next release.
  - **Doc correction:** `docs/A27_HOST_PAIRING.md` claimed the updater already
    links `WinVerifyTrust`. It does not — `src/sync/updater.rs` uses a SHA-256
    sidecar plus a detached Ed25519 `.sig`. The Authenticode check is therefore
    still open, and the doc now says so.
  - Honest limit: without the signature check a renamed `chrome.exe` passes, so
    this layer is a speed bump until step 2 + Authenticode land.
- Verified on screen: `+ Add Custom Field` (content-sized), Vault Health Report,
  Recovery Sheet (scrollable shards, fits the 730px window).
- Gates: see the gate line below.

## Last code batch (2026-11-14b) — G2 follow-up + content-sized dialog

- **G2 was shipped visually broken in `610df02`.** The toggle existed in the
  model (`toggle_custom_field`) but the row drew nothing: the `Text` glyph inside
  a `TouchArea` never rendered, and the follow-up `Rectangle` + `Text` form drew
  nothing either. It is now a drawn box — `Rectangle` with a 1.5px border plus a
  `Path` tick when `cf.value == "true"` (`ui/appwindow.slint:3094`) — so it does
  not depend on font coverage of `☐`/`☑`.
- **`+ Add Custom Field` dialog was full-window tall.** The inner `Rectangle` had
  no `height`, so it took the parent's (AGENTS.md §6 trap). It now binds
  `height: cfdlg_lay.preferred-height` (`ui/appwindow.slint:3388`).
- Verified on screen (dev build, `SLINT_SCALE_FACTOR=0.85`, 1280x730):
  dialog is content-sized (`%TEMP%\pv-g2e-dialog.png`); the row shows an empty
  box and clicking it paints the primary fill + tick
  (`%TEMP%\pv-g2e-row.png` → `%TEMP%\pv-g2e-toggled-zoom.png`).
- **Not verified:** that the toggled value survives Save. The harness `setedit`
  (UIA `ValuePattern`) renders text in the field but the Slint binding does not
  receive it, so the draft failed validation ("Login needs a title + key
  fields") and nothing was written (`my_secure_vault.enc` mtime unchanged). The
  flip logic itself is covered by `checkbox_field_tests`.
- Remaining same-class bug: eight other modals still stretch to the window
  height (`docs/baki kaj.md`, U1) — one at a time with a screen check, because a
  `ScrollView` inside a content-sized dialog reports `preferred-height: 100%`.
- Gates on this batch: `cargo test -j 1` **619 passed / 0 failed / 4 ignored**
  (`TEST_EXIT=0`); clippy / build / `npm test` — see the gate line below.

## Last code batch (2026-11-14a) — `610df02`

- **G1**: the item detail pane grew a logo button (`ui/appwindow.slint:3234`)
  wired to `override_favicon`; the Rust handler already existed and had no
  emitter, so a custom icon could only be set by editing the vault file.
- **G2**: a checkbox custom field toggles in place
  (`callback toggle_custom_field(int)`, `main.rs:11552`). Anything that is not
  exactly `"true"` is treated as unchecked (`flipped_checkbox_value`).
- **G6**: a remote that fails `check_incoming` is no longer a dead end. The union
  merge is still staged, prefixed with `merge_fork_note()`, and `Apply` merges
  **locally only** — `trigger_sync_push` is skipped and the audit log records
  `merge forced (local only, push skipped)`. `PendingMerge.forced` drives both.
  The staged merge (a full secret copy) is now dropped on lock; the struct
  comment had promised that since it was written.
- **G8 (UI half)**: `access_log_header()` / `access_log_report()` — the audit
  viewer says how many appends were lost in this session instead of showing a
  clean `VALID` chain over a gap.
- **Extension**: `PV_BREACH` no longer returns the vault-derived `reuse` count to
  a content-script sender; an empty password is rejected before the host spawns.
- Tests added: `merge_fork_tests` (2), `access_log_header_tests` (2),
  `checkbox_field_tests` (2), two JS router tests.
- **Gate trap found**: `Instant::now() - Duration` panics on Windows when the
  monotonic origin is younger than the offset (`std\time.rs:446`). The two
  `activity_touch_tests` now build their idle clock with `checked_sub`.
- Gates on `610df02`: `cargo test -j 1` **618 passed / 1 failed / 4 ignored** —
  the single failure is the documented `api::local` `os error 10053` flake and
  passes alone (`1 passed; 0 failed`); clippy `--all-targets -j 1 --
  -D warnings` **EXIT=0**; `cargo build -j 1` **EXIT=0**; `npm test` **174/174**.
- Not verified on screen yet: G1 and G2 need the dev build + a throwaway vault.
- `docs/A27_HOST_PAIRING.md` is a design only (parent-process provenance +
  HMAC pairing secret); `SECURITY.md` now documents the permission breadth and
  the missing pairing secret as accepted limitations.

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

## Release 0.4.2 — `a51fb35`

- Version bumped to **0.4.2** in `Cargo.toml`, both manifests, the popup chip
  and `installer.iss`; `CHANGELOG.md` added; README/SECURITY/AGENTS claims
  refreshed (test counts and the iframe/clipboard behaviour changes).
- The offscreen document and its permission are gone (dead since B8).
- An independent review of the 16-commit series found four real problems, all
  fixed: hotkey/context-menu fills aimed at a dead iframe id; a reprompt-armed
  login's hidden custom fields and linked-password field still revealed the
  secret; auto-lock ignored an open editor and could discard an unsaved item;
  the sync-adoption path treated an unreadable local vault as empty.
- Gates: `cargo test` **607 passed / 0 failed / 4 ignored**; clippy
  `--all-targets -j 1 -- -D warnings` **EXIT=0** (10m09s); `npm test` 172/172;
  tokens 21.
- Artifacts built locally (unsigned): `installer-output/PhantomVault-Setup-0.4.2.exe` (10.06 MB) and `dist/release-0.4.2/` (portable exe 25.2 MB, chrome/firefox zips, SHA256SUMS). No `.sig` files: the updater will refuse this build until it is signed. No on-screen E2E.

## Last code batch (2026-11-13a) — `eecf3de`

- **Firefox native messaging** (functional break): Firefox launches the bridge
  with the add-on id as `argv[1]`, not an origin. `is_native_host_launch`
  (`main.rs:139`) now accepts `FIREFOX_ADDON_ID` and any id registered in
  `native-host-firefox.json`; `origin_allowed` (`native_host.rs:179`) falls
  through to the registered gecko id list; the Firefox registration writes
  `allowed_extensions`. **Not verified in a real Firefox** — only the code path
  and the manifest writer are tested.
- **G3**: export failures surface in the UI; all three `eprintln!` paths are
  gone (0 `export refused` matches left in `main.rs`).
- **G4**: the clipboard fallback checks `set_text` and clears only when the
  clipboard still holds our text, so a failed copy cannot toast "Copied".
- Gates on `eecf3de`: `cargo test -j 1` **607 passed / 0 failed / 4 ignored**
  (117.11s), `npm test` **172/172**, `npm run test:tokens` **21**.
- Tests: `grid_tests::native_host_launch_detection` already covered the three
  accepted spellings; this batch adds the three negatives that were missing
  (`moz-extension://…`, an id that only prefixes ours, a leading space).

## Last code batch (2026-11-12g) — `b81c766`

- **B8**: `clipboardRead` removed from the Chrome manifest; content scripts now
  run in the **top frame only** (`all_frames:false`, both manifests). Embedded
  cross-origin login widgets are no longer autofilled or captured. The
  background no longer reports a failed clipboard clear as success.
- **B9**: `hook.js` stays web-accessible for the MAIN-world tripwire, but only
  on `http(s)` pages (no `file://`).
- Behaviour change: the extension-side clipboard auto-clear can no longer verify
  (it needs read access) and now reports "not cleared"; the native host's copy
  path (Win+V exclusion + TTL flush) is the auto-clear that still works.
- Gates: `npm test` **172/172**, tokens 21. No Rust change.
- Follow-up: the offscreen document is now only used by the dead clear path;
  removing it (and its `offscreen` permission) is cleanup, not a fix.

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

## Known traps

- Run Rust gates with `-j 1` (slower but calm on a RAM-tight machine). The three
  old flakes — `share_serve::…served_share_is_one_view_and_revocable`,
  `api::local::…loopback_get_waits…` (os 10053) and
  `crypto::…test_legacy_v2_still_opens` — are defused in the harness, not by
  loosening an assertion: readiness probe + retry for the two socket tests, and a
  test-only `KDF_TEST_LOCK` for the Argon2 memory spike. Each was run 15× at
  `-j 4` to prove it.
- A cold `cargo build --release -j 1` took **106m** on this machine and
  succeeded; a >1h build is not a hang. `Allocation failed` linker errors mean
  RAM is tight (close Chrome and retry), not a code defect.
- `.zwork/` is agent runtime state (build logs, subagent reports) and is
  git-ignored. Never commit it.
- The dropdown and Continue-as rows live in **closed** shadow roots; tests must
  query them through the harness `shadowOf(host)`, never the page tree.
- `cargo clippy -- -D warnings` fails on deprecated calls: use the `*_secret`
  crypto/storage entry points, not the `&str` ones.

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
