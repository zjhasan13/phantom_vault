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

Unverified agent reports (kept for a later pass, **not** reproduced here):
`security/access_log.rs:96-99` (HMAC→SHA256), `security/emergency.rs:259-264`
(shards in heap), `main.rs:2011` toast scope, `content.js:843` session-cache
invalidation.

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
| E4 | Login iframes are never scanned (`all_frames:false`, no `match_about_blank`) | `manifest.json:36-42` |
| E5 | `extDeskOkPage` session cache never invalidated | `content.js:843` |
| E6 | Broad `MutationObserver` on `documentElement` (perf) | `content.js:2383-2384` |

## 3. Desktop findings (separate line — not Tier 0)

| ID | Finding | Location | Sev |
|---|---|---|---|
| D1 | "Lock" = process exit (see §0) | `main.rs:11665-11670`, `slint:1349` | High (UX) |
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
- **Tier 4 (tests):** content-script harness coverage.

## 5. Accepted decisions

- **Lock semantics:** intended = real lock screen with the process alive, plus a
  separate Exit. (Deferred to Tier 3.)
- **Tier 0 scope:** extension capture engine only.
- **Multi-page carry:** username only (non-secret). Password is **never**
  persisted to `storage.session`/`local` (P1-b policy intact).
- **iframe capture:** deferred to a later phase.

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
- **Phase 3 — shared domain logic (DONE, awaiting commit):** E1 `registrable()`
  now keeps multi-label public suffixes (`foo.co.uk` → `foo.co.uk`, not
  `co.uk`) via a pragmatic PSL subset; E2 `EQUIV_CLUSTERS` / `memberHit` /
  `domainsEquiv` live only in `domain.js`. Wiring: manifest `js` order
  (`domain.js` before `content.js`) in both manifests, `importScripts()`
  (classic MV3 SW) in `background.js`, `popup.html` already loads it.
  Harnesses updated (background `importScripts` stub, content jsdom loads
  `domain.js` first). `npm test` **32/32**; `cargo test` 452 unchanged.
- Next: Phase 4 (D1 lock + E4 iframes).
