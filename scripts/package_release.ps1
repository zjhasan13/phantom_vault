# PhantomVault release packaging — the one implementation used locally AND in CI.
#
# Builds the app, the Inno installer and the extension zips, writes a CycloneDX
# SBOM, hashes every asset, and (when a key is supplied) writes the detached
# Ed25519 `<asset>.sig` files the updater requires. Refuses to sign with a key
# that does not match the pinned public key in src/release_pubkey.rs.
#
# Usage:
#   .\scripts\package_release.ps1 -SignKeyPath C:\path\release_signing.key
#   .\scripts\package_release.ps1 -SignKeyEnv PV_SIGNING_KEY      # CI
#   .\scripts\package_release.ps1 -SkipTests -SkipSbom             # local QA only
#
# Output: dist\release-<version>\ (upload every file to the GitHub Release).
# No UPX: the compressed-exe target is historical (see docs/RELEASE.md).

[CmdletBinding()]
param(
    [string]$SignKeyPath = "",
    [string]$SignKeyEnv = "",
    [switch]$SkipTests,
    [switch]$SkipBuild,
    [switch]$SkipSbom
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $root
try {
    function Invoke-Native([string]$what, [scriptblock]$cmd) {
        # Windows PowerShell 5.1 turns native stderr (cargo progress, ISCC
        # notices) into error records; with ErrorActionPreference=Stop that
        # would abort a successful build. Keep the exit code authoritative.
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & $cmd 2>&1 | ForEach-Object { Write-Host $_ }
        } finally {
            $ErrorActionPreference = $prev
        }
        if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
    }

    function Find-Iscc {
        $cmd = Get-Command iscc -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        foreach ($p in @(
                "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
                "C:\Program Files\Inno Setup 6\ISCC.exe")) {
            if (Test-Path $p) { return $p }
        }
        throw "Inno Setup (ISCC.exe) not found. Install it from https://jrsoftware.org/isdl.php"
    }

    $ver = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
    $issVer = (Select-String -Path installer.iss -Pattern '#define MyAppVersion "([^"]+)"').Matches[0].Groups[1].Value
    if ($issVer -ne $ver) { throw "version drift: installer.iss is $issVer, Cargo is $ver" }
    Write-Host "PhantomVault $ver - release packaging"

    # 1. Gates
    $signerManifest = Join-Path $root "tools\pv-sign\Cargo.toml"
    if (-not $SkipTests) {
        Invoke-Native "cargo test" { cargo test }
        Invoke-Native "signer tests" { cargo test --quiet --manifest-path $signerManifest }
        Invoke-Native "npm test" { npm test }
    } else {
        Write-Warning "Skipping test gates (-SkipTests); do not publish this build."
    }

    # 2. Build
    if (-not $SkipBuild) {
        Invoke-Native "cargo build --release" { cargo build --release }
    } else {
        Write-Warning "Using the existing target\release build (-SkipBuild)."
    }

    # 3. Installer (bytes are final before signing)
    $iscc = Find-Iscc
    Invoke-Native "Inno Setup compile" { & $iscc installer.iss }
    $setup = Join-Path $root "installer-output\PhantomVault-Setup-$ver.exe"
    if (-not (Test-Path $setup)) { throw "installer not produced: $setup" }

    # 4. Extension zips (build.ps1 also checks both manifests == Cargo version)
    Invoke-Native "extension build" { & (Join-Path $root "browser_extension\build.ps1") -Browser all }

    $staging = Join-Path $root "dist\release-$ver"
    if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
    New-Item -ItemType Directory -Path $staging | Out-Null

    Copy-Item -LiteralPath $setup -Destination $staging
    # The in-app updater swaps a portable exe over the live binary; it must
    # never receive the Inno installer. Keep this name stable: the updater
    # prefers "update"/"portable", then "windows/win64", and always skips
    # names containing "setup"/"installer".
    $appExe = Join-Path $root "target\release\phantom_vault.exe"
    if (-not (Test-Path $appExe)) { throw "release binary missing: $appExe" }
    Copy-Item -LiteralPath $appExe -Destination (Join-Path $staging "PhantomVault-$ver-windows-x64.exe")
    foreach ($browser in @("chrome", "firefox")) {
        $dir = Join-Path $root "browser_extension\dist\$browser"
        if (-not (Test-Path $dir)) { throw "missing extension build: $dir" }
        Compress-Archive -Path (Join-Path $dir "*") -DestinationPath (Join-Path $staging "phantomvault-$browser-$ver.zip") -Force
    }

    # 5. SBOM (CycloneDX from cargo metadata, not a binary scan)
    if (-not $SkipSbom) {
        $cdx = Get-Command cargo-cyclonedx -ErrorAction SilentlyContinue
        if (-not $cdx) {
            throw "cargo-cyclonedx not installed. Run: cargo install cargo-cyclonedx --locked"
        }
        $stem = "phantom_vault-$ver.cdx"
        Invoke-Native "cargo cyclonedx" { cargo cyclonedx --format json --override-filename $stem }
        $sbom = Get-ChildItem -LiteralPath $root -Filter "$stem*" -File | Select-Object -First 1
        if (-not $sbom) { $sbom = Get-ChildItem -LiteralPath $root -Filter "bom*.json" -File | Select-Object -First 1 }
        if (-not $sbom) { throw "cargo-cyclonedx produced no JSON SBOM" }
        Move-Item -LiteralPath $sbom.FullName -Destination (Join-Path $staging "phantom_vault-$ver.cdx.json") -Force
    } else {
        Write-Warning "Skipping SBOM (-SkipSbom)."
    }

    # 6. Sign every distributable binary (both exes + zips) with the release key.
    $signing = $SignKeyPath -ne "" -or $SignKeyEnv -ne ""
    if ($signing) {
        $keyArg = if ($SignKeyPath -ne "") { @("--key-file", $SignKeyPath) }
        elseif ($SignKeyEnv -ne "") { @("--key-env", $SignKeyEnv) }
        else { @() }
        $signBase = @("run", "--quiet", "--release", "--manifest-path", $signerManifest, "--")
        foreach ($asset in (Get-ChildItem -LiteralPath $staging -File | Where-Object { $_.Extension -in @(".exe", ".zip") })) {
            Invoke-Native "sign $($asset.Name)" { cargo @signBase sign $asset.FullName @keyArg }
            Invoke-Native "verify $($asset.Name)" { cargo @signBase verify $asset.FullName }
        }
    } else {
        Write-Warning "No signing key supplied: the updater will REFUSE this release. Pass -SignKeyPath or -SignKeyEnv."
    }

    # 7. Integrity: per-asset `<name>.sha256` (bare hash, updater's preferred form)
    #    plus a GNU-style SHA256SUMS.txt for humans and the release page.
    $assets = Get-ChildItem -LiteralPath $staging -File |
        Where-Object { $_.Extension -in @(".exe", ".zip", ".json") } |
        Sort-Object Name
    $sums = New-Object System.Collections.Generic.List[string]
    foreach ($asset in $assets) {
        $hash = (Get-FileHash -LiteralPath $asset.FullName -Algorithm SHA256).Hash.ToLower()
        Set-Content -LiteralPath (Join-Path $staging "$($asset.Name).sha256") -Value $hash -Encoding ascii
        $sums.Add("$hash  $($asset.Name)")
    }
    Set-Content -LiteralPath (Join-Path $staging "SHA256SUMS.txt") -Value $sums -Encoding ascii

    Write-Host ""
    Write-Host "Release staging: $staging"
    Get-ChildItem -LiteralPath $staging -File | Sort-Object Name |
        ForEach-Object { "{0,10:N0}  {1}" -f $_.Length, $_.Name }
    if (-not $signing) {
        Write-Warning "This build has no .sig files and is NOT updater-verifiable."
    }
} finally {
    Pop-Location
}
