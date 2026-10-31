# Release Process — PhantomVault

> Read this fully before tagging any release. Last verified against the
> v0.1.0→v0.2.0 cycle (bridge MAC + candidates shape BREAKING changes) and
> updated for the 2026-10-31 certificate-free trust pipeline (A8a).

## 1. SmartScreen / unsigned binary (expected, not a bug)

- The `.exe` and installer are **not Authenticode-signed** (no certificate yet,
  roadmap A8b).
- First launch on a fresh machine shows Windows SmartScreen
  *"Unknown publisher"* warning. Users click **More info → Run anyway**.
- Say this IN the release notes, verbatim-ish, so it never reads as a
  compromise indicator:
  > "Windows SmartScreen will warn (unsigned build). Verify the SHA-256
  > below matches, then More info → Run anyway."
- Every release MUST attach `SHA256SUMS.txt` (setup exe + both extension zips).
  No hashes = no release.
- Every `.exe` / `.zip` the updater may download MUST also ship a detached
  Ed25519 `<asset>.sig`. Missing `.sig` = the updater refuses the download.
  This is separate from Authenticode: it is the in-app updater's trust root.
- Releases ship **two** exes on purpose:
  `PhantomVault-Setup-<ver>.exe` (humans, Inno) and
  `PhantomVault-<ver>-windows-x64.exe` (the in-app updater, which swaps this
  portable binary over the live one). The updater skips `setup`/`installer`
  names; never rename the portable asset without updating `pick_asset`.

## 2. Old-version interop matrix (must re-check per release)

| Pair | Works? | Note |
|---|---|---|
| new desktop ↔ new extension | ✅ | Normal path |
| new desktop ↔ old extension | ⚠️ Partial | Old extension sends plaintext `pin` / reads `codes[]` → refused/empty. **Upgrade both.** |
| old desktop ↔ new extension | ❌ | `cache_favicon`, `totp_lookup` unknown cmds; MAC auth fails |
| new P2P ↔ old P2P | ❌ | Challenge-response only; legacy `pin` field refused (BREAKING since MAC rollout) |

Rule: P2P sync and bridge sync peers/extensions MUST run the same
release. State the minimum peer version in the notes.

**Vault format rev 2 (A16):** a vault saved by this build carries `rev` +
`prev_hash` inside the AEAD payload. Builds before it cannot open that
container, so the notes MUST require upgrading every device before syncing.
Pre-A16 backups still load and migrate on the next save. A fresh device's first
pull is TOFU; later stale pulls are refused.

## 3. Rollback plan (tag discipline)

- `v0.4.1` is tagged + pushed and published — it is the current rollback
  anchor (v0.4.0 remains the previous anchor).
- Before publishing release N+1, confirm tag `vN` exists on GitHub with
  its artifacts attached (setup exe + extension zips + SHA256SUMS).
- Rollback = users reinstall `vN` artifacts; vault file format is
  forward-compatible within major (verify `load_vault_versioned`
  migration notes in rules.md before claiming otherwise).
- Never delete/replace a published tag. A bad release gets a NEW
  patch version, never a force-push. The release workflow enforces this for
  `workflow_dispatch` rebuilds (it refuses an existing release).

## 4. Release checklist (per release)

- [ ] `cargo test` green + count → rules.md baseline sync
- [ ] `cargo test --manifest-path tools/pv-sign/Cargo.toml` green (signer)
- [ ] `cargo clippy --all-targets -- -D warnings` green
- [ ] `node --check` ×4 + `node --test tests/js/` green
- [ ] Idle footprint gate (lightweight release): locked + minimized to tray,
  Task Manager working set ≤40MB sustained 1 min; CPU 0.00% sustained 5 min
  (locked AND unlocked-hidden). Bridge warm-frame p50 ~5ms (10× `PV_QUERY`,
  1 KDF in host log). Record all three numbers in the release notes
- [ ] Versions agree: `Cargo.toml`, `installer.iss` `#define MyAppVersion`,
  both extension manifests (the workflow and `package_release.ps1` fail on drift)
- [ ] **No UPX.** It was only ever used for v0.2.0; it inflates AV false
  positives on an unsigned binary. Record the real size instead (v0.4.0:
  19.55 MB exe, 8.54 MB installer; v0.4.1 published: 19.77 MB portable exe,
  8.98 MB installer). If size becomes a goal, treat UPX as a new decision with
  a measured AV/SmartScreen comparison, not an assumed default.
- [ ] `exe_integrity.dpapi` reset (fresh seal on first launch)
- [ ] Native-host pipe smoke test on the PACKED binary (ping/query/assert)
- [ ] Installer build (Inno) smoke on clean profile
- [ ] Extension zips, one per browser (`browser_extension/build.ps1 -Browser all`;
  both manifests' versions == Cargo version): chrome zip + firefox zip
- [ ] QA_CHECKLIST §11–13 manual pass
- [ ] CHANGELOG: breaking changes called out (bridge shape, P2P auth)
- [ ] Tag `vX.Y.Z` + push tag; the `release` workflow builds, tests, signs,
  hashes, SBOMs, attests and uploads everything
- [ ] Verify the published assets: `SHA256SUMS.txt`, per-asset `.sha256` and
  `.sig` for **both** the installer and `PhantomVault-<ver>-windows-x64.exe`
  (the updater asset), both `*.zip.sig`, SBOM, provenance attestation
- [ ] SmartScreen + interop + one-time signing-key migration notes pasted
  (sections 1–2 and 5 below)

## 5. Release signing key (Ed25519)

- The public key is pinned in `src/release_pubkey.rs`; the updater
  (`src/sync/updater.rs`) refuses any asset whose signature does not verify.
- The private seed is **only**:
  1. in the GitHub Actions secret `PV_SIGNING_KEY` (64 hex chars), and
  2. in the maintainer's offline backup at
     `%USERPROFILE%\.phantomvault\release_signing.key` (hex text, user-only ACL).
  It is never in the repo, a release asset, a log, or a chat message.
- `tools/pv-sign` signs and verifies (its own crate: `cargo run --manifest-path
  tools/pv-sign/Cargo.toml -- ...`). It refuses to sign when the supplied
  key derives a different public key, so a wrong secret fails before publishing.
- Local packaging:
  ```powershell
  .\scripts\package_release.ps1 -SignKeyPath "$env:USERPROFILE\.phantomvault\release_signing.key"
  ```
- CI packaging: push a `v*` tag; the `release` workflow reads the secret and
  calls the same script.

### Key rotation (one-time manual step for old clients)

The pre-rotation key had no available private half, so 2026-10-31 introduced a
new key. Clients built before that date pin the old public key and **cannot**
verify the new signatures: they need one manual reinstall. After that, updates
verify normally. If the key is ever rotated again:

1. `cargo run --manifest-path tools/pv-sign/Cargo.toml -- keygen --out <offline path>`
2. Update `UPDATER_PUBLIC_KEY` + `UPDATER_PUBLIC_KEY_HEX` in
   `src/release_pubkey.rs`; run `cargo test pv_sign`.
3. Replace the `PV_SIGNING_KEY` GitHub secret with the new seed.
4. Release notes MUST say that a manual reinstall is required once.
