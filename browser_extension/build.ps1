# Build packaged extensions from this single source dir (no drift).
# Usage: .\build.ps1 [-Browser chrome|firefox|all]  (default: all)
# Output: dist/chrome/, dist/firefox/ — load unpacked (Chrome) or
# temporary add-on (Firefox about:debugging) straight from dist/.
param([string]$Browser = "all")

$ErrorActionPreference = "Stop"
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$files = @("background.js", "content.js", "domain.js", "hook.js", "popup.js", "popup.html")

function Test-Json($p) {
    try { Get-Content $p -Raw | ConvertFrom-Json | Out-Null }
    catch { throw "invalid JSON: $p ($($_.Exception.Message))" }
}

# Version lock: both manifests + Cargo.toml must agree (RELEASE.md gate).
$cargoVer = (Select-String -Path (Join-Path $src "..\Cargo.toml") -Pattern '^version = "([^"]+)"').Matches[0].Groups[1].Value
foreach ($m in @("manifest.json", "manifest.firefox.json")) {
    $p = Join-Path $src $m
    Test-Json $p
    $mv = (Get-Content $p -Raw | ConvertFrom-Json).version
    if ($mv -ne $cargoVer) { throw "version drift: $m is $mv, Cargo is $cargoVer" }
}

function Build-One($name, $manifestSrc) {
    $dst = Join-Path $src "dist\$name"
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    New-Item -ItemType Directory -Path $dst | Out-Null
    foreach ($f in $files) { Copy-Item (Join-Path $src $f) $dst }
    if (Test-Path (Join-Path $src "icons")) {
        Copy-Item (Join-Path $src "icons") (Join-Path $dst "icons") -Recurse
    }
    Copy-Item (Join-Path $src $manifestSrc) (Join-Path $dst "manifest.json")
    # Fail-closed: every referenced file must exist in dist.
    $man = Get-Content (Join-Path $dst "manifest.json") -Raw | ConvertFrom-Json
    $refs = @($man.background.service_worker) +
        $man.content_scripts.js +
        $man.web_accessible_resources.resources +
        @($man.action.default_popup) +
        @($man.action.default_icon.PSObject.Properties.Value) +
        @($man.icons.PSObject.Properties.Value)
    foreach ($r in ($refs | Where-Object { $_ } | Sort-Object -Unique)) {
        if (!(Test-Path (Join-Path $dst $r))) { throw "dist\$name missing referenced file: $r" }
    }
    Write-Output "built dist\$name"
}

if ($Browser -in @("chrome", "all")) { Build-One "chrome" "manifest.json" }
if ($Browser -in @("firefox", "all")) { Build-One "firefox" "manifest.firefox.json" }
