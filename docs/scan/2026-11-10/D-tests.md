# D-tests — objective-health audit of the PhantomVault docs

**Auditor role:** QA auditor (read-only). Repo files were not modified. Scratch scripts live in
`%TEMP%\pv-scan\` (`scan.mjs`, `reconcile.mjs`).
**Run date:** 2026-11-10. **Worktree HEAD:** `116f57a567b0ef2f8267291fc02a79063282ba03`
(`116f57a`, 2026-11-07 20:25:03 +0600, `docs: record the HUD 2.0 decision and the extension view/edit gap`),
branch `main`, `git status --short` → only `?? .zwork/` (untracked tool dir, not code).

**Verdict in one line:** the two JS gates are genuinely green at HEAD; the Rust test *count* claim
(581/0/4) reconciles exactly with a static census — but CI does not run two of the four documented
gates, and the `SESSION_STATE.md` snapshot table is stale by two commits.

---

## 1. JS gates — executed

### `npm test` → PASS, exit 0

Command actually run: `node --test tests/js/background.test.mjs tests/js/content.test.mjs tests/js/domain.test.mjs tests/js/equiv.test.mjs tests/js/popup.test.mjs`

Tail of the real output:

```
ℹ tests 160
ℹ suites 0
ℹ pass 160
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 22729.2611
```

`exitCode: 0`. 160/160 — matches the doc claim **exactly**. No failure text to quote (none occurred).

### `npm run test:tokens` → PASS, exit 0

```
> powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check_ui_tokens.ps1

UI tokens OK: 21 palette values match tokens.json -> Slint + CSS.

EXITCODE=0
```

21 palette values — matches the doc claim **exactly**.

---

## 2. Static Rust test census vs the "581 passed, 0 failed, 4 ignored" claim

Method: line-anchored regex over all `*.rs` under `src/` (target/node_modules excluded), then a
brace-matching body scanner to re-count and inspect each test function.

| Measure | Count |
|---|---|
| `.rs` files under `src/` | **88** (matches doc) |
| `.rs` files under `tests/` (Rust integration tests) | **0** — `tests/` holds only `js/` |
| `#[test]` attributes | **582** |
| `#[tokio::test]` attributes | **3** |
| **test functions total** | **585** |
| `#[ignore]` attributes | **4** |
| `#[cfg(test)]` occurrences | 98 |
| `#[bench]` | 0 |
| `#[should_panic]` | 0 |

### Is 581 plausible? Yes — arithmetically exact, and the confounders are closed

- **585 − 4 ignored = 581.** That is precisely the claimed pass count.
- **No doctests to inflate the number:** there is no `src/lib.rs` (`Test-Path src/lib.rs` → `False`),
  no `[lib]` section in `Cargo.toml`, and **0** fenced code blocks in `///`/`//!` comments
  (`FENCED_DOC_LINES=0`). So `cargo test` has no doc-test target.
- **No hidden integration tests**, no `benches/`; 0 `#[should_panic]` (a `should_panic` test would
  still count as passed, so no distortion either way).
- **Nothing cfg-gated off:** the only feature is `default = ["camera"]` and the only
  feature-gated test is `camera_scanner.rs:212` `list_cameras_never_panics` under
  `#[cfg(feature = "camera")]` — which is on by default. The `#[cfg(windows)]` items are production
  code paths, not test gates.
- **Independent cross-check on staleness:** the docs say `cargo test` 581 at `4a38695`, and the
  later commits added no tests —
  `a4c2bfc +tests=0 -tests=0`, `774420a +tests=0 -tests=0`, `da1de56 +tests=0 -tests=0`,
  `116f57a +tests=0 -tests=0`. So 581 is still the right number at HEAD, not a stale-low figure.

**Not verified:** the *execution* (`581 passed, 0 failed`). My mandate let me run the JS gates only,
and no fresh Rust test binary exists — `target\debug\deps\phantom_vault-*.exe` is dated **11/2/2026**
and **10/21/2026** while the newest `src/` file is **11/7/2026 22:36**, so a real run means a full
relink (the documented `Allocation failed` RAM risk). To close it:
`cargo test -j 1 2>&1 | Tee-Object %TEMP%\pv-scan\cargo-test.txt` and compare the summary line.

### One scanner artefact, resolved by hand (do not misread as 4 missing tests)

Brace-matching could not segment 4 tests because of braces inside string literals;
`reconcile.mjs` reports `ATTRS=585 SCANNED=581 MISSING=4` —
`storage.rs:888`, `storage.rs:998`, `storage.rs:1020`, `proximity_lock.rs:424`.
All four were read manually and all four contain real assertions (e.g. `storage.rs:899`
`assert_eq!(crate::crypto::detect_version(&file_bytes), VaultVersion::V2Portable);`).

---

## 3. Coverage hole map — modules with NO `#[cfg(test)]`

**78 of the 88 `src/` files** contain `#[cfg(test)]`; **10 do not**. **12** files contain zero test
functions (2 of those — `api/mod.rs`, `sync/mod.rs` — have a cfg(test) block that defines no tests).

Ten biggest `src/` modules with **no** test module, by line count:

| # | File | Lines | Notes |
|---|---|---|---|
| 1 | `src/share_cli.rs` | **589** | Real production code, not a stub |
| 2 | `src/windows_native/hello.rs` | **88** | Windows Hello gate |
| 3 | `src/i18n.rs` | 26 | |
| 4 | `src/release_pubkey.rs` | 23 | pinned Ed25519 pubkey constant |
| 5 | `src/error.rs` | 22 | |
| 6 | `src/security/mod.rs` | 21 | re-export module |
| 7 | `src/api/mod.rs` | 16 | re-export module |
| 8 | `src/windows_native/mod.rs` | 12 | re-export module |
| 9 | `src/sync/mod.rs` | 10 | re-export module |
| 10 | `src/authenticator/mod.rs` | 8 | re-export module |

**The hole map is thin, not broad:** 8 of the 10 are ≤26 lines and are mostly `mod.rs` re-exports or
constants. There are only two substantive holes:

- **`src/share_cli.rs` (589 lines) — the real one.** Declared `mod share_cli;` at `src/main.rs:15`,
  dispatched at `src/main.rs:4195` (`"share" => share_cli::share_cli(&argv[2..]),`). It implements
  `create / serve / open / list / revoke` plus `pub(crate) fn parse_ttl` (`share_cli.rs:55`), which is
  called from `main.rs:14949`. `parse_ttl` is referenced 3 times repo-wide and **none** is a test, so
  TTL parsing (`24h`, `--views`, `--passphrase`, `--relay`) has no test at all. Neighbouring
  `share.rs` (6), `share_store.rs` (2) and `share_serve.rs` (1) cover the primitives, not the CLI
  surface or its argument validation.
- **`src/windows_native/hello.rs` (88 lines)**, a security boundary (Windows Hello / PIN gate) with no
  unit test.

For contrast, the big files *are* tested: `main.rs` 17,856 lines / 65 tests,
`native_host.rs` 6,002 / 71, `models.rs` 2,059 / 19, `p2p_local.rs` 1,930 / 13,
`storage.rs` 1,444 / 23.

---

## 4. Tests that cannot fail

- `assert!(true)` / `assert_eq!(true, true)` / `assert!(1 == 1)`: **0 occurrences.**
- Empty test bodies: **0.**
- Tautological asserts (`is_ok() || is_err()` style): **0** real hits (the 4 grep hits were ordinary
  `if` conditions in production code, e.g. `main.rs:2970`).
- **6 tests carry no assertion token at all.** All 6 were read; none is a fake test, but 4 are
  panic-only smoke tests that cannot fail on a wrong answer:

| Test | Location | Judgement |
|---|---|---|
| `agent_key_wipes_on_drop` | `developer/ssh_agent.rs:421` | Compile-time trait bound (`assert_zeroize_on_drop::<AgentKey>()`). Fails to compile if the bound breaks — legitimate, but never fails at runtime. |
| `sweep_runs_without_panic` | `security/anti_debug.rs:91` | `let _ = sweep();` Documented as environment-dependent. Panic-only. |
| `mitigations_apply_without_panic` | `windows_native/process_guard.rs:106` | Four `let _ = ...;` OS calls. Panic-only. |
| `probe_never_panics` | `windows_native/session_lock.rs:91` | `let _ = workstation_locked();` Panic-only. |
| `tray_actions_fire_without_handlers` | `windows_native/tray.rs:451` | Callbacks fire, no handler asserts. Panic-only. |
| `seed_ui_demo_vault_manual` | `storage.rs:1366` | `#[ignore]`d manual demo seeder — not a test. |

- **`#[ignore]` without a reason string: 1 of 4.** The other three are fine:
  `attachment_store.rs:869` `#[ignore = "50 MiB manual QA: run with --ignored"]`,
  `storage.rs:1365` `#[ignore = "manual UI demo seed: ..."]`,
  `pq_profile.rs:449` `#[ignore = "requires a TPM 2.0 device"]`.
  The bare one is **`security/breach_check.rs:503`**:

  ```rust
      // Live-API test, ignored by default (needs network).
      #[test]
      #[ignore]
      fn live_api_marks_password_breached() {
  ```

  It *is* explained by the preceding comment, but not in a machine-readable reason string, so
  `cargo test -- --ignored --list` shows no justification, and it hits the live HIBP API when run.

---

## 5. Docs drift — `docs/SESSION_STATE.md` vs reality

| Claim in the snapshot table | Reality | Verdict |
|---|---|---|
| `Date` = **2026-11-05** | HEAD commit date **2026-11-07 20:25:03 +0600** | **Stale** |
| `Branch / HEAD` = `main` @ **`da1de56`** | HEAD = **`116f57a`**; `git merge-base --is-ancestor da1de56 HEAD` → `ANCESTOR_EXIT=0`, i.e. `da1de56` is **2 commits behind** (`da1de56` → `93623ca` → `116f57a`) | **Stale** |
| App version **0.4.1** (`Cargo.toml`) | `version = "0.4.1"` | Correct |
| Extension version **0.4.1** | `"version": "0.4.1",` in `browser_extension/manifest.json` | Correct |
| `Installer present` = `installer-output/PhantomVault-Setup-0.4.1.exe` (20,582,400 bytes) | `installer-output/` is **absent**; `.gitignore:3` is `/installer-output/` | **Unverifiable** — expected to be missing in a clone, but the size/date claim cannot be checked here |
| `Rust modules` = 88 `.rs` | **88** | Correct |
| `UI` = `ui/appwindow.slint` **~3.7k** lines | **4,201** lines | **Understated by ~500** |
| `cargo test` **581 passed, 0 failed, 4 ignored** | static 585 − 4 `#[ignore]` = **581** | Consistent (execution not run — see §2) |
| `npm test` **160/160** | **160 pass / 0 fail**, exit 0 | Correct, re-verified today |
| `npm run test:tokens` **21 palette values OK** | `UI tokens OK: 21 palette values ...` | Correct, re-verified today |
| "Last code batch (2026-11-07) - `4a38695`" | 7 commits landed after `4a38695` (`738f322`, `a4c2bfc`, `889ee17`, `774420a`, `5800802`, `da1de56`, `93623ca`, `116f57a`) | **Stale** section header, though it correctly says 581 |

### "Next move" accuracy against the code

1. **Installer/live E2E — still blocked.** Not code-verifiable here (needs the installed 0.4.1 build).
   The claimed cause ("`bridge refuses` a 0.4.0 build") was **not** located in `native_host.rs`; treat
   the *reasoning* as unverified even though the *blocked* status is consistent with the missing installer.
2. **HUD 3.0 declined** — a decision, nothing to verify.
3. **"Extension item view + edit — real gap" — STILL ACCURATE.** `openItemEditor` is still edit-first:
   `popup.js:1304` `function openItemEditor(entry, kind = "login") {`, and the only entry point opens it
   directly (`popup.js:1284` `openItemEditor(await fetchEntry(KIND_NUM[kind] || 1, id), kind);`).
   The read-only block at `popup.js:1415` is *inside* the editor and login-only
   (`// Read-only detail sections (login only for now): retired passwords and ...`).
   SSH/licence rows still expose only Copy (`buildSshRow` `popup.js:2758`, `buildLicenseRow` `:2787`).
   Only the cited line number drifted: doc says `popup.js:1280`, actual is `:1304`.
4. Items 4 (`da1de56`) and 5 (`a4c2bfc`) marked done — both commits exist with the described subjects.
5. Item 6 (A26 BN) — the named remainder is real: `src/main.rs:652`
   `ui.set_notification_text(format!("⚠️ Auto-Type: {e}").into());` still an untranslated English prefix.
6. Item 8 lists 13 fix-batch commits — all resolve via `git cat-file -t` (spot-checked
   `4a38695`, `171eb92`, `b399b06`, `774420a` → all `commit`).

---

## 6. CI vs the four documented gates

Only **two** workflow files exist (`.github/workflows/`): `release.yml`, `security.yml`.

`security.yml` — triggers `push`, `pull_request`, weekly cron; job `build-and-test` on
`windows-latest`, verbatim `run:` lines:

```
L37: - run: cargo check --all-targets
L38: - run: cargo clippy --all-targets -- -D warnings
L39: - run: cargo test
L40: - run: cargo test --manifest-path tools/pv-sign/Cargo.toml
```

(plus a separate `rustsec/audit-check` job.)

`release.yml` — triggers **tags `v*`** and `workflow_dispatch` only; does `npm ci`, then runs
`./scripts/package_release.ps1 -SignKeyEnv PV_SIGNING_KEY`. That script does run the JS gate —
`scripts/package_release.ps1:66` `Invoke-Native "npm test" { npm test }` — but it is skippable
(`-SkipTests`, line 20/68).

| Documented gate | On every push / PR? | Where it actually runs |
|---|---|---|
| `cargo test -j 1` | Yes (but **no `-j 1`**) | `security.yml:39` |
| `cargo clippy --all-targets -j 1 -- -D warnings` | Yes (no `-j 1`, otherwise identical) | `security.yml:38` |
| `npm test` | **No** | only `release.yml` → `package_release.ps1:66`, skippable |
| `npm run test:tokens` | **No — nowhere** | **not wired into any workflow or script**; only docs/README mention it |

Two consequences worth flagging:

- **The token gate is unenforced.** `grep` for `check_ui_tokens|test:tokens` across `*.yml`, `*.ps1`,
  `*.json`, `*.md` returns only `package.json:8`, docs (`HANDOFF.md:164`, `UI_PARITY_MAP.md:25,370`,
  `UI_TOKENS.md:34,36,97`, `README.md:249`), `AGENTS.md:61`, and the script itself. A palette drift
  can merge green.
- **CI contradicts the documented flake trap.** `AGENTS.md`/`SESSION_STATE.md` say the
  `share_serve::tests::served_share_is_one_view_and_revocable` test flakes without `-j 1`, yet
  `security.yml:39` runs plain `cargo test` (default parallelism). Expect the documented red-CI /
  green-local asymmetry.
- Minor: CI has no `cargo build` step (only `check --all-targets`), which is defensible since the
  release script builds, but it is a third documented command not mirrored on PRs.

---

## 7. `package.json` scripts and JS test pickup

```json
"test": "node --test tests/js/background.test.mjs tests/js/content.test.mjs tests/js/domain.test.mjs tests/js/equiv.test.mjs tests/js/popup.test.mjs",
"test:tokens": "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check_ui_tokens.ps1"
```

`tests/js/` contains exactly 5 `*.test.mjs` files (`background`, `content`, `domain`, `equiv`, `popup`)
plus three non-test helpers (`harness.mjs`, `content-harness.mjs`). **All 5 test files are named
explicitly in the script → 5/5 picked up, 0 orphaned test files.** No `*.test.mjs` exists anywhere
else in the repo (checked recursively, `node_modules` excluded).

**Fragility (not a current bug):** the list is hardcoded, so a future `tests/js/foo.test.mjs` would be
silently skipped — `npm test` would stay green while the new file never runs. `node --test tests/js/`
or a glob would remove the trap.

---

## 8. What I did NOT verify

1. **`cargo test` execution** — the "581 passed, 0 failed, 4 ignored" line is *arithmetically consistent*
   (585 attrs − 4 ignores) but was not run; no fresh test binary, full relink needed, and my mandate was
   the JS gates. Also unverified: `cargo check`, `cargo build`, `cargo clippy`.
2. **The installer artefact** (`installer-output/...exe`, 20,582,400 bytes) — absent and gitignored.
3. **The "0.4.0 build cannot talk to the 0.4.1 extension (bridge refuses)"** mechanism — no matching
   version-refusal code found in `src/windows_native/native_host.rs`; needs the live build to test.
4. **A26 BN completeness** — only the one named `Auto-Type: {e}` remainder was spot-checked; no
   full sweep of dialog strings vs `ui_lang`.
5. **Visual/DPI claims** (item 7) — requires the dev build + screenshots; out of scope for a static audit.
6. **`share_serve` flake reproduction** — would require running `cargo test -j 4`.

---

## 9. Reproduction

```powershell
# JS gates (both green today)
npm test                      # tests 160 / pass 160 / fail 0, exit 0
npm run test:tokens           # UI tokens OK: 21 palette values, exit 0
$LASTEXITCODE

# static Rust census
Get-ChildItem src -Recurse -Filter *.rs |
  % { Select-String -LiteralPath $_.FullName -Pattern '^\s*#\[(tokio::)?test' }   # 585
Get-ChildItem src -Recurse -Filter *.rs |
  % { Select-String -LiteralPath $_.FullName -Pattern '^\s*#\[ignore' }           # 4

# body scanner / reconciliation (scratch, outside the repo)
node "$env:TEMP\pv-scan\scan.mjs"      (Get-Location).Path
node "$env:TEMP\pv-scan\reconcile.mjs" (Get-Location).Path

# docs drift
git log -1 --format="%h%n%ci%n%s"
Select-String Cargo.toml,browser_extension/manifest.json -Pattern 'version'
```

## 10. Suggested follow-ups (out of scope, not done)

- Wire `npm test` + `npm run test:tokens` into `security.yml` so all four documented gates are enforced
  per push/PR (or drop the "four gates" wording from `AGENTS.md`).
- Add `-j 1` to CI's `cargo test`, or fix the `share_serve` test's isolation.
- Replace `#[ignore]` at `breach_check.rs:503` with `#[ignore = "needs network (live HIBP API)"]`.
- Add tests for `share_cli::parse_ttl` and the `share` subcommand argument validation (589 untested lines).
- Refresh the `SESSION_STATE.md` snapshot table (Date, HEAD, installer row, `~4.2k` Slint lines).
- Switch `npm test` to a directory/glob so new test files cannot be silently skipped.
