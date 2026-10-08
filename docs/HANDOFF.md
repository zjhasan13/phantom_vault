# Session Handoff — PhantomVault

> Read this fully in a fresh session BEFORE doing anything. Last updated: HEAD `0461835`.
> Companion: `rules.md` (architecture invariants — non-negotiable).

## 1. Where we are

- Branch `main`, pushed, working tree clean. HEAD `0461835`
  `feat: drop dead ext_pin_state host cmd, one-click SSH agent Start/Stop with lock-kill (384 tests green)`.
- Baselines: `cargo test` 384 passed / 1 ignored, `node --test tests/js/` 12/12,
  `cargo check --all-targets` zero warnings, `cargo clippy --all-targets` zero warnings.
- `cargo audit`: HIGHs gone (quick-xml, webpki). Residual (all justified, see §4):
  `rsa` (ignored), `bincode` (contained), `paste`/`ttf-parser`/`yoke-derive` (transitive).
- Git history was purged of vault containers (C1) + force-pushed. **Everyone works
  from fresh clones — never push from a stale pre-purge clone.**

## 2. How to resume (new PC / new session)

1. `git clone https://github.com/zjhasan13/phantom_vault.git` (fresh — no old clones).
2. Read `rules.md`, then this file, then ask the user which pending item to start.
3. Workflow (mandatory): **plan mode first** (spec + file:line touch list, no edits)
   → user approves → **build mode** (implement + `cargo check` + `cargo test` +
   `node --test tests/js/background.test.mjs`) → commit → push `main`.
4. Communication: short, direct, Bengali-mix OK. Every finding cites `file:line`
   + exact code quote. Verify, don't speculate.

## 3. Pending queue (ordered)

1. **Low-resource build, Phase 1 — Slint software-only renderer.** `slint`
   (`Cargo.toml:25`) still has defaults ON (femtovg + software linked). Goal:
   `default-features = false` + `backend-winit` + `renderer-software`, keep
   `raw-window-handle-06`. Risk: scroll perf on weak CPU. Verify: tray GPU 0.
2. **Phase 2 — image format trim.** `image = "0.25"` full defaults (avif/exr/tiff…).
   Target: `default-features = false` + `png,ico,jpeg,gif,bmp`. Note: webp custom
   logos will reject — say so in the error text.
3. **Phase 3 — reqwest/tokio trim (do last, riskiest).** `reqwest` defaults ON;
   keep `socks` (Tor proxy support is a documented feature). tokio `rt-multi-thread`
   → `new_current_thread` only where parallelism is unneeded. One dep at a time.
4. **Live measurements (needs the user's machine):** Task Manager working set
   locked+minimized (target ≤30–40 MB), idle CPU 0.00% × 5 min, bridge warm p50
   ~5 ms (10× `PV_QUERY`, expect 1 KDF in host log). Record in release notes.
5. **Master Password Rotation — Option A** (user-side, after C1 purge): export
   Bitwarden JSON → fresh vault + new password → import → verify count → export
   Recovery Sheet → shred temp JSON → delete all `*.dpapi` → shred old backup.
6. **GitHub cache check:** repo code-search `my_secure_vault` must return zero;
   else request GitHub Support cache purge.
7. **Follow-ups for the other line:** `write_adopted_head` unwired
   (`src/sync/p2p_local.rs`, marked `#[allow(dead_code)]` + NOTE); host `assert`
   command unreachable from extension (fails-closed test pinned); `AgentKey`
   lacks explicit `Zeroize` derive (relies on dalek drop).
8. **Standing item (do NOT blind-chase):** ~92× `Mutex::lock().unwrap()` in
   `src/main.rs` (panic=abort design). Only touch attacker-influenced paths.
9. **Audit residuals:** `rqrr-zeroize` fork evaluated and REJECTED (official
   crate solved it — do not revisit without new cause).

## 4. Key decisions log (don't re-litigate)

- Full A2 encrypted-RAM rewrite: CANCELED (vault ~500 KB, saves <1 MB — wrong lever).
- `rqrr-zeroize` fork: rejected, official `rqrr 0.11` used.
- Persistent extension port: strict FIFO (host echoes no rid), 60 s TTL unchanged,
  stale-read window documented in `background.js` header.
- Toast/UI text uses emoji + Bengali-mix is fine; keep code comments concise.
- Commit style: `type(scope): subject (test counts)`, e.g.
  `feat: drop dead ext_pin_state host cmd, one-click SSH agent Start/Stop (384 tests green)`.
- Never force-push without explicit user approval (kills collaborators' work).
- Never commit `*.enc*`, `*.dpapi`, `access.log`, `com.phantomvault.host.json`
  (all gitignored — the C1 leak must never recur).
