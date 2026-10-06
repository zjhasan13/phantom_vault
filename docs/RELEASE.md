# Release Process — PhantomVault

> Read this fully before tagging any release. Last verified against the
> v0.1.0→v0.2.0 cycle (bridge MAC + candidates shape BREAKING changes).

## 1. SmartScreen / unsigned binary (expected, not a bug)

- The `.exe` and installer are **not code-signed** (no cert yet).
- First launch on a fresh machine shows Windows SmartScreen
  *"Unknown publisher"* warning. Users click **More info → Run anyway**.
- Say this IN the release notes, verbatim-ish, so it never reads as a
  compromise indicator:
  > "Windows SmartScreen will warn (unsigned build). Verify the SHA-256
  > below matches, then More info → Run anyway."
- Every release MUST attach `SHA256SUMS.txt` (hashes of setup exe +
  extension zip). No hashes = no release.

## 2. Old-version interop matrix (must re-check per release)

| Pair | Works? | Note |
|---|---|---|
| new desktop ↔ new extension | ✅ | Normal path |
| new desktop ↔ old extension | ⚠️ Partial | Old extension sends plaintext `pin` / reads `codes[]` → refused/empty. **Upgrade both.** |
| old desktop ↔ new extension | ❌ | `cache_favicon`, `totp_lookup` unknown cmds; MAC auth fails |
| new P2P ↔ old P2P | ❌ | Challenge-response only; legacy `pin` field refused (BREAKING since MAC rollout) |

Rule: P2P sync and bridge sync peers/extensions MUST run the same
release. State the minimum peer version in the notes.

## 3. Rollback plan (tag discipline)

- NO tags exist yet — the first release tag BECOMES the rollback anchor.
- Before publishing release N+1, confirm tag `vN` exists on GitHub with
  its artifacts attached (setup exe + extension zip + SHA256SUMS).
- Rollback = users reinstall `vN` artifacts; vault file format is
  forward-compatible within major (verify `load_vault_versioned`
  migration notes in rules.md before claiming otherwise).
- Never delete/replace a published tag. A bad release gets a NEW
  patch version, never a force-push.
- Suggested first tags: `v0.1.0` (last known-good baseline, tag
  retroactively on the pre-MAC commit if needed) → then `v0.2.0`.

## 4. Release checklist (per release)

- [ ] `cargo test` green + count → rules.md baseline sync
- [ ] `cargo clippy --all-targets -- -D warnings` green
- [ ] `node --check` ×4 + `node --test tests/js/` green
- [ ] Idle footprint gate (lightweight release): locked + minimized to tray,
  Task Manager working set ≤40MB sustained 1 min; CPU 0.00% sustained 5 min
  (locked AND unlocked-hidden). Bridge warm-frame p50 ~5ms (10× `PV_QUERY`,
  1 KDF in host log). Record all three numbers in the release notes
- [ ] `cargo build --release` + UPX → record size (target: sub-8MB)
- [ ] `exe_integrity.dpapi` reset (fresh seal on first launch)
- [ ] Native-host pipe smoke test on the PACKED binary (ping/query/assert)
- [ ] Installer build (Inno) smoke on clean profile
- [ ] Extension zip (manifest version == Cargo version)
- [ ] QA_CHECKLIST §11–13 manual pass
- [ ] CHANGELOG: breaking changes called out (bridge shape, P2P auth)
- [ ] Tag `vX.Y.Z` + push tag; GitHub Release with artifacts + SHA256SUMS
- [ ] SmartScreen + interop notes pasted (sections 1–2 above)
