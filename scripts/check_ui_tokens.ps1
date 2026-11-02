# Verify that the design tokens are identical in:
#   design/tokens.json      (source of truth)
#   ui/appwindow.slint      (Slint PhantomTheme, canonical names)
#   browser_extension/design-tokens.css (extension --pv-* variables)
# Usage: powershell -NoProfile -File scripts/check_ui_tokens.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$tokensPath = Join-Path $root "design\tokens.json"
$slintPath = Join-Path $root "ui\appwindow.slint"
$cssPath = Join-Path $root "browser_extension\design-tokens.css"

if (!(Test-Path $tokensPath)) { throw "missing $tokensPath" }
$tokens = Get-Content $tokensPath -Raw | ConvertFrom-Json

# json key -> Slint property name
$slintMap = [ordered]@{
    canvas = "canvas"; surface_lowest = "surface-lowest"; surface_low = "surface-low"
    surface = "surface"; surface_high = "surface-high"; surface_highest = "surface-highest"
    border = "border"; border_strong = "border-strong"
    text = "text"; text_muted = "text-muted"; text_dim = "text-dim"
    primary = "primary"; primary_container = "primary-container"; on_primary = "on-primary"
    secondary = "secondary"; on_secondary = "on-secondary"
    success = "success"; on_success = "on-success"
    error = "error"; on_error = "on-error"; warning = "warning"
}

$slint = Get-Content $slintPath -Raw
$block = [regex]::Match($slint, '(?s)global PhantomTheme \{(.*?)\r?\n\}').Groups[1].Value
if (!$block) { throw "PhantomTheme block not found in $slintPath" }

foreach ($key in $slintMap.Keys) {
    $prop = [regex]::Escape($slintMap[$key])
    $m = [regex]::Match($block, "property <color>\s+$prop\s*:\s*(#[0-9a-fA-F]{6})\s*;")
    if (!$m.Success) { throw "Slint token missing: $($slintMap[$key])" }
    $want = ([string]$tokens.palette.$key).ToLowerInvariant()
    $got = $m.Groups[1].Value.ToLowerInvariant()
    if ($got -ne $want) {
        throw "Slint token $($slintMap[$key]) is $got, tokens.json says $want"
    }
}

$css = Get-Content $cssPath -Raw
$base = ($css -split '@media', 2)[0]
foreach ($key in $slintMap.Keys) {
    $name = "--pv-" + ($key -replace '_', '-')
    $m = [regex]::Match($base, [regex]::Escape($name) + '\s*:\s*(#[0-9a-fA-F]{6})\s*;')
    if (!$m.Success) { throw "CSS token missing: $name" }
    $want = ([string]$tokens.palette.$key).ToLowerInvariant()
    $got = $m.Groups[1].Value.ToLowerInvariant()
    if ($got -ne $want) {
        throw "CSS token $name is $got, tokens.json says $want"
    }
}

$paletteCount = ($tokens.palette.PSObject.Properties | Measure-Object).Count
Write-Output "UI tokens OK: $paletteCount palette values match tokens.json -> Slint + CSS."
