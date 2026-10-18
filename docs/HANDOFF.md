# Session Handoff — PhantomVault

> Read this fully in a fresh session BEFORE doing anything. Last updated: epic roadmap 9→3→5 shipped, mobile/iOS excluded (446 tests).
> Companion: `rules.md` (architecture invariants — non-negotiable).

## 1. Where we are

- Branch `main`, pushed, working tree clean.
- Extension OTP UX shipped (`ec789db`): multiple-2FA sites now open the
  account picker on OTP-field focus/sight (login-dropdown parity, gated by
  `show_suggestions`); picker rows carry ♻️/🟡/🕰️ health icons joined
  client-side from `PV_QUERY`. Working-badge + recency already native
  (3rd-fill auto-verify `models.rs:601`) — untouched. Extension-only: rebuild
  via `browser_extension/build.ps1`, NO exe rebuild. QA physical: 1-account
  auto-fill, 2-account picker→choose, submit→✅ upore, health icons.
- Baselines: `cargo test` 446 passed / 1 ignored, `node --test
  tests/js/background.test.mjs` 16/16, `cargo check --all-targets` zero
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
- Build env: `CARGO_TARGET_DIR=D:\pv-target` (persisted via setx). C: was
  filling up (40 GB target dirs) — all builds go to D: now.
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
   `cargo test` + `node --test tests/js/background.test.mjs`) → commit
   (`type(scope): subject (test counts)`) → push `main`.
4. Communication: short, direct, Bengali-mix OK. Every finding cites `file:line`
   + exact code quote. Verify with tools, don't speculate. Never use `bash` to
   communicate; never use comments for chain-of-thought.
5. Quality bar that produced this history: no fix without a regression test,
   no refactor without `cargo check` clean, no push with red tests, honest
   "I don't know yet — here is how we find out" instead of guessing.

## 3. Pending queue (ordered)

1. **Tray X-still-exits (user reports FIXED on their side):** re-verify on the
   next physical pass (X → process stays as background tray process; Access
   Log close-path lines present). If it regresses, suspects in order:
   handler never fires (Slint close-request path) → panic=abort in handler →
   env-specific tray failure.
2. **Live measurements (partial, needs the user's machine):** observed
   minimized+unlocked 7.3 MB / 0.1% CPU (screenshot) — still needed:
   locked+minimized release-build reading, idle CPU 0.00% × 5 min, bridge
   warm p50 ~5 ms. Record in release notes.
3. **Master Password Rotation — Option A** (user-side, after C1 purge): export
   Bitwarden JSON → fresh vault + new password → import → verify count → export
   Recovery Sheet PDF → shred temp JSON → delete all `*.dpapi` → shred old backup.
4. **GitHub cache check:** repo code-search `my_secure_vault` must return zero;
   else request GitHub Support cache purge. Then publish the v0.2.0 Release
   object in web UI (tag pushed; no `gh` CLI on the machine).
5. **Follow-ups for the other line:** `write_adopted_head` unwired
   (`src/sync/p2p_local.rs`, `#[allow(dead_code)]` + NOTE); legacy host
   `assert` unreachable from extension (fails-closed test pinned —
   relay now uses `assert_full`/`attest`); `AgentKey` lacks
   explicit `Zeroize` derive (relies on dalek drop).
6. **Standing item (do NOT blind-chase):** `Mutex::lock().unwrap()` pattern in
   `src/main.rs` (panic=abort design). Only touch attacker-influenced paths.
7. **Dropped scope (do not revisit without new cause):** full A2 encrypted-RAM
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
  change silently.
- Test hygiene (proven twice): env-mutating tests sharing one process-global
  var MUST serialize via a static `Mutex` (see `browser_direct` ENV_LOCK
  precedent); single-use token consume MUST check-then-remove (failed
  attempts never burn); brand-new relay message names keep old fail-closed
  pins green (`PV_ASSERT` vs `PV_ASSERT_SIGN`).
- Crate `Result<T>` alias collision: new String-error fns use
  `std::result::Result` or a local `StdResult<T>` alias — never bare
  `Result<_, String>` next to `use crate::error::Result`.
