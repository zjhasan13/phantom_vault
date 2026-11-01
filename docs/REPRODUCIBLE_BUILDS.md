# Reproducible Builds — PhantomVault

> Scope: what a third party can independently rebuild today, what cannot be
> reproduced byte-for-byte yet, and the exact commands. Last verified against
> the 0.4.1 release pipeline (A8a).

## 1. What is pinned

| Input | Pin |
|---|---|
| Source | the release tag (`vX.Y.Z`), never a branch |
| Rust dependencies | `Cargo.lock` (committed) |
| Rust toolchain | record `rustc -Vv` in the release notes; build with `--locked` |
| MSVC / Windows SDK | record `cl.exe` / SDK version for the release |
| Inno Setup | record `ISCC.exe` version |
| Node (extension zips only) | record `node -v` (zips ship source, not a bundle) |
| Packaging | `scripts/package_release.ps1` (same script as CI) |

The repository does **not** pin the toolchain in `rust-toolchain.toml` yet; a
release is only reproducible against the toolchain recorded with it. Pinning the
channel is a follow-up.

## 2. Rebuild from a clean clone

```powershell
git clone https://github.com/zjhasan13/phantom_vault.git
cd phantom_vault
git checkout vX.Y.Z

rustc -Vv                     # record this
cargo build --release --locked

iscc installer.iss            # installer-output\PhantomVault-Setup-X.Y.Z.exe
.\browser_extension\build.ps1 -Browser all
```

The release workflow does the same through one script:

```powershell
.\scripts\package_release.ps1 -SignKeyPath <offline key>
```

It runs the test gates, builds the exe, the Inno installer, both zips, the
CycloneDX SBOM, hashes every asset (`<asset>.sha256` + `SHA256SUMS.txt`) and
writes detached Ed25519 `<asset>.sig` files.

## 3. Verify a downloaded release

```powershell
# 1. Hash matches the published sidecar and SHA256SUMS.txt
Get-FileHash .\PhantomVault-Setup-X.Y.Z.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt

# 2. Detached Ed25519 signature against the pinned updater key
cargo run --manifest-path tools\pv-sign\Cargo.toml -- verify .\PhantomVault-Setup-X.Y.Z.exe

# 3. GitHub build provenance
gh attestation verify .\PhantomVault-Setup-X.Y.Z.exe --repo zjhasan13/phantom_vault
```

`SHA256SUMS.txt` covers the installer, the portable updater exe, both extension
zips and the SBOM. A missing `.sig` means the in-app updater refuses the asset.

## 4. What is not byte-for-byte reproducible yet

Be honest: the current pipeline is **verifiable**, not yet **bit-reproducible**.

- The PE/COFF linker (MSVC `link.exe`) writes a timestamp and may embed
  machine-specific paths; `lto = "fat"` and codegen can vary by toolchain build.
- Slint generates Rust at build time; generated symbol ordering can vary with
  the compiler version.
- Inno Setup embeds its own timestamp and compression decisions.
- Cargo registry crates are content-addressed but the toolchain itself is not
  pinned in-repo.

The hashes and signatures still prove **what was published**; they do not yet
prove that **your rebuild is identical**.

### Target for the next step (T5b)

1. Pin `rust-toolchain.toml` to the release channel and record it in the tag.
2. Set `SOURCE_DATE_EPOCH` to the source commit time and pass
   `--remap-path-prefix` so absolute build paths never enter the binary.
3. Add a CI job that rebuilds the tag on two clean runners and compares the
   exe + installer hashes; fail the release on a mismatch.
4. Publish `BUILD_INFO.json` (toolchain, MSVC, Inno, commit, epoch) beside the
   assets.

## 5. Honest limits

- The Authenticode installer is still unsigned (A8b); SmartScreen will warn.
- Ed25519 signatures cover the asset bytes, not the build environment.
- A compromised build machine can sign a malicious asset; provenance narrows
  that to the workflow, not to a reproducible build.
- Extension zips are source folders, so their hash is reproducible from the tag
  as long as the files are byte-identical (line endings included).

## 6. How to verify this document

```powershell
Select-String -Path .github\workflows\release.yml -Pattern 'package_release|cargo test|attest'
Select-String -Path scripts\package_release.ps1 -Pattern 'cargo build --release|iscc|SHA256SUMS|pv_sign'
Test-Path docs\REPRODUCIBLE_BUILDS.md
gh release view vX.Y.Z --json assets
```
