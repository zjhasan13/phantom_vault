# TestAndDocAuditor — run 33a85550 participant 3

Report delivered. Findings below.

**Gates (HEAD `116f57a`):** `npm test` → 160 pass / 0 fail / 0 skipped, exit 0. `npm run test:tokens` → "UI tokens OK: 21 palette values", exit 0. Both match the doc claims exactly.

**Rust 581/0/4 — plausible, arithmetic exact:** 585 test fns (582 `#[test]` + 3 `#[tokio::test]`), 4 `#[ignore]` → 585−4=581. No `lib.rs`/doctests, no `tests/*.rs`, no `#[should_panic]`, nothing cfg-gated off (`default = ["camera"]` includes the one gated test). Post-`4a38695` commits added 0 tests, so 581 isn't stale-low.

**Coverage:** 78/88 src files have `#[cfg(test)]`. Biggest untested module: **`src/share_cli.rs`, 589 lines** (share CLI + `parse_ttl`, wired at `main.rs:4195`); next is `hello.rs` at 88, then only ≤26-line `mod.rs` files — a thin hole map, not a broad one.

**Drift:** snapshot Date `2026-11-05` vs actual `2026-11-07`; HEAD claimed `da1de56` vs actual `116f57a` (2 commits behind); `installer-output/` absent (gitignored) so the 20,582,400-byte row is unverifiable; `appwindow.slint` 4201 lines vs "~3.7k". Versions 0.4.1/0.4.1 and "88 modules" are correct. Next-move #3 still accurate (`openItemEditor` edit-first, `popup.js:1304`).

**CI:** only 2 of 4 gates. `security.yml` runs check/clippy/test per push+PR but **without `-j 1`** (the documented `share_serve` flake can red CI); `npm test` runs only on tag releases via `package_release.ps1` (skippable); `test:tokens` is in **no** workflow.

**Not verified:** `cargo test`/check/clippy not executed (JS-only mandate; cached test binary predates last src change by 5 days). Bare `#[ignore]` without reason: `breach_check.rs:503`.