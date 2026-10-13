# Session Handoff — PhantomVault

> Read this fully in a fresh session BEFORE doing anything. Last updated: SecretString migration done (Phases 1–5).
> Companion: `rules.md` (architecture invariants — non-negotiable).

## 1. Where we are

- Branch `main`, pushed, working tree clean.
- Baselines: `cargo test` 409 passed / 1 ignored, `node --test tests/js/` 12/12,
  `cargo check --all-targets` zero warnings, `cargo clippy --all-targets` 1 pre-existing
  warning (`tray.rs:381` redundant match, untouched).
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

1. **Tray X-still-exits (ACTIVE DEBUG, user-reported):** pref ON + new build, yet
   X fully exits. Evidence so far: process gone (not stranded), Access Log has
   NO close-path lines (handler seemingly never ran). Just added close-path
   logging (`tray / minimize accepted`) — next step: user reproduces on the new
   build and reports Access Log lines + console output from `cargo run`
   (`System tray icon live.` vs `Tray unavailable (…)`). Suspects in order:
   handler never fires (Slint close-request path) → panic=abort in handler →
   env-specific tray failure.
2. **Live measurements (needs the user's machine):** Task Manager working set
   locked+minimized (target ≤30–40 MB), idle CPU 0.00% × 5 min, bridge warm p50
   ~5 ms. Record in release notes.
3. **Master Password Rotation — Option A** (user-side, after C1 purge): export
   Bitwarden JSON → fresh vault + new password → import → verify count → export
   Recovery Sheet PDF → shred temp JSON → delete all `*.dpapi` → shred old backup.
4. **GitHub cache check:** repo code-search `my_secure_vault` must return zero;
   else request GitHub Support cache purge. Then publish the v0.2.0 Release
   object in web UI (tag pushed; no `gh` CLI on the machine).
5. **Follow-ups for the other line:** `write_adopted_head` unwired
   (`src/sync/p2p_local.rs`, `#[allow(dead_code)]` + NOTE); host `assert`
   unreachable from extension (fails-closed test pinned); `AgentKey` lacks
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
