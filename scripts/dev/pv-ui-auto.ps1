#requires -Version 5.1
<#
.SYNOPSIS
  Dev-only UI automation harness for the PhantomVault Slint desktop app.

.DESCRIPTION
  Drives the *dev build* (never the installed app) through Windows UI Automation
  and synthetic clicks, and saves PNG screenshots to %TEMP% so a UI change can be
  verified instead of assumed.

  Why this exists: Slint exposes only Text nodes for buttons, and Chrome steals
  focus. This harness sets per-monitor DPI awareness, focuses the app with
  AttachThreadInput, reads the live UIA rect and clicks it in the same process.

  Do NOT call ShowWindow(SW_RESTORE) between reading a rect and clicking it: it
  can restore/move the window and invalidate every coordinate.

.PARAMETER Action
  dump        print the UIA tree (name + rect) of the app window
  click       click the first Text whose name matches -Arg (exact, then contains)
  shot        focus the app and screenshot to %TEMP%\-Arg
  unlock      fill the master-password field with -Password and submit
  wheel       -Arg "x,y,notches" (positive = scroll up)
  navshot     -Arg "Label,out.png" (click Label, wait, screenshot)
  clickshot   -Arg "x,y,out.png" (raw coordinate click, then screenshot)
  hovershot   -Arg "x,y,out.png"
  place       -Arg "x,y,w,h" (move/resize the app window once)
  twosheets   launch, unlock, open the 2FA import and export sheets, screenshot
  verify      launch, unlock, screenshot the health/import/export dialogs

.PARAMETER Exe
  Path to the dev phantom_vault.exe. Defaults to $env:PV_EXE, then
  $env:CARGO_TARGET_DIR\debug\phantom_vault.exe.

.PARAMETER VaultDir
  Value for $env:PHANTOM_VAULT_DIR. Use a throwaway directory: the harness
  launches the app against it. Defaults to $env:TEMP\pv-ui.

.PARAMETER Password
  Master password of the throwaway vault. Defaults to Demo-Pass-123!.

.EXAMPLE
  powershell -File scripts/dev/pv-ui-auto.ps1 -Action verify `
    -Exe "C:\Users\me\pv-target\debug\phantom_vault.exe" `
    -VaultDir "$env:TEMP\pv-ui" -Password "Demo-Pass-123!"

.NOTES
  Windows 10/11 only. Creates/uses a local vault directory; never point it at a
  real vault. Screenshots are full-screen and may contain other windows.
#>
param(
  [string]$Action = "dump",
  [string]$Arg = "",
  [string]$Exe = "",
  [string]$VaultDir = "",
  [string]$Password = "Demo-Pass-123!"
)

$ErrorActionPreference = 'Stop'

if (-not $Exe -or $Exe -eq "") {
  if ($env:PV_EXE) { $Exe = $env:PV_EXE }
  elseif ($env:CARGO_TARGET_DIR) { $Exe = Join-Path $env:CARGO_TARGET_DIR "debug\phantom_vault.exe" }
  else { $Exe = Join-Path (Get-Location) "target\debug\phantom_vault.exe" }
}
if (-not (Test-Path $Exe)) {
  throw "Dev exe not found: $Exe (build it first: cargo build -j 1)"
}
if (-not $VaultDir -or $VaultDir -eq "") { $VaultDir = Join-Path $env:TEMP "pv-ui" }
$script:ExePath = (Resolve-Path $Exe).Path
$script:VaultDir = $VaultDir
$script:MasterPw = $Password

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class PW {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr v);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int w, int ht, uint f);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, int d, UIntPtr e);
  public struct R { public int L,T,Rr,B; }
}
"@
[PW]::SetProcessDpiAwarenessContext([IntPtr](-4)) | Out-Null
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$WINDOW_TITLE = 'PhantomVault - Zero-Knowledge Native Vault'

function Get-AppWindow {
  $p = Get-Process phantom_vault -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $p) { return $null }
  $target = $p.Id
  $script:found = @()
  $cb = [PW+EnumProc]{
    param($h, $l)
    $pid2 = 0
    [PW]::GetWindowThreadProcessId($h, [ref]$pid2) | Out-Null
    if ($pid2 -eq $target -and [PW]::IsWindowVisible($h)) {
      $r = New-Object PW+R
      [PW]::GetWindowRect($h, [ref]$r) | Out-Null
      $script:found += [pscustomobject]@{ H = $h; L = $r.L; Tp = $r.T; W = ($r.Rr - $r.L); Ht = ($r.B - $r.T) }
    }
    return $true
  }
  [PW]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
  return ($found | Sort-Object { $_.W * $_.Ht } -Descending | Select-Object -First 1)
}

function FocusApp {
  $best = Get-AppWindow
  if (-not $best) { return $false }
  $script:wh = [IntPtr]$best.H
  $fg = [PW]::GetForegroundWindow()
  $fgPid = 0
  $fgTh = [PW]::GetWindowThreadProcessId($fg, [ref]$fgPid)
  $myTh = [PW]::GetCurrentThreadId()
  [PW]::AttachThreadInput($myTh, $fgTh, $true) | Out-Null
  [PW]::BringWindowToTop($script:wh) | Out-Null
  [PW]::SetForegroundWindow($script:wh) | Out-Null
  [PW]::AttachThreadInput($myTh, $fgTh, $false) | Out-Null
  Start-Sleep -Milliseconds 400
  return $true
}

function NormalizeWindow {
  $best = Get-AppWindow
  if (-not $best) { return $false }
  $h = [IntPtr]$best.H
  [PW]::ShowWindow($h, 9) | Out-Null
  [PW]::SetWindowPos($h, [IntPtr]::Zero, 40, 30, 1500, 940, 0x0040) | Out-Null
  Start-Sleep -Milliseconds 500
  return $true
}

function Get-UiaWindow {
  $root = [System.Windows.Automation.AutomationElement]::RootElement
  $wc = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::NameProperty, $WINDOW_TITLE)
  return $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $wc)
}

function Get-TextElements {
  $w = Get-UiaWindow
  if (-not $w) { return @() }
  $tc = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::Text)
  return @($w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc))
}

function Click-Rect($r) {
  [PW]::SetCursorPos([int]($r.X + $r.Width / 2), [int]($r.Y + $r.Height / 2)) | Out-Null
  Start-Sleep -Milliseconds 220
  [PW]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
  Start-Sleep -Milliseconds 70
  [PW]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
  Start-Sleep -Milliseconds 500
}

function FindTextRect([string]$label, [switch]$Exact) {
  $texts = Get-TextElements
  foreach ($t in $texts) {
    if ($t.Current.Name -eq $label) { return $t.Current.BoundingRectangle }
  }
  if ($Exact) { return $null }
  foreach ($t in $texts) {
    if ($t.Current.Name -like "*$label*") { return $t.Current.BoundingRectangle }
  }
  return $null
}

function Dump {
  $w = Get-UiaWindow
  if (-not $w) { "NO_WINDOW"; return }
  $all = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants,
    [System.Windows.Automation.Condition]::TrueCondition)
  "COUNT=$($all.Count)"
  foreach ($e in $all) {
    $n = $e.Current.Name
    $ct = $e.Current.ControlType.ProgrammaticName
    if ($n -and $n.Trim().Length -gt 0) {
      "{0}|{1}|{2}" -f $ct, $n, $e.Current.BoundingRectangle
    }
  }
}

function Save-Screenshot([string]$name) {
  FocusApp | Out-Null
  Start-Sleep -Milliseconds 350
  $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp = New-Object System.Drawing.Bitmap($b.Width, $b.Height)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
  $path = Join-Path $env:TEMP $name
  $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose()
  $bmp.Dispose()
  "SHOT=$path"
}

function Wheel([int]$x, [int]$y, [int]$notches) {
  FocusApp | Out-Null
  [PW]::SetCursorPos($x, $y) | Out-Null
  Start-Sleep -Milliseconds 200
  for ($i = 0; $i -lt [Math]::Abs($notches); $i++) {
    $d = if ($notches -gt 0) { 120 } else { -120 }
    [PW]::mouse_event(0x0800, 0, 0, $d, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 60
  }
  Start-Sleep -Milliseconds 300
  "WHEEL=$notches"
}

function Click-Name([string]$label) {
  NormalizeWindow | Out-Null
  FocusApp | Out-Null
  $w = Get-UiaWindow
  if (-not $w) { "NO_WINDOW"; return }
  $hits = @()
  foreach ($t in (Get-TextElements)) {
    if ($t.Current.Name -eq $label) { $hits += $t }
  }
  if ($hits.Count -eq 0) {
    foreach ($t in (Get-TextElements)) {
      if ($t.Current.Name -like "*$label*") { $hits += $t }
    }
  }
  "HITS=$($hits.Count)"
  foreach ($h in $hits) { "  $($h.Current.Name) :: $($h.Current.BoundingRectangle)" }
  if ($hits.Count -gt 0) {
    Click-Rect $hits[0].Current.BoundingRectangle
    "CLICKED=$label"
  } else {
    "MISS=$label"
  }
}

function Unlock([string]$pw) {
  NormalizeWindow | Out-Null
  FocusApp | Out-Null
  $w = Get-UiaWindow
  $ec = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::Edit)
  $ed = $null
  foreach ($e in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $ec)) {
    $r = $e.Current.BoundingRectangle
    if ($r.Width -gt 150) { $ed = $e; break }
  }
  if (-not $ed) { "NO_EDIT"; return }
  $vp = $ed.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
  $vp.SetValue($pw)
  Start-Sleep -Milliseconds 400
  $btn = $null
  foreach ($t in (Get-TextElements)) {
    if ($t.Current.Name -match 'Enter') { $btn = $t; break }
  }
  if ($btn) { Click-Rect $btn.Current.BoundingRectangle }
  else { [System.Windows.Forms.SendKeys]::SendWait('{ENTER}') }
  Start-Sleep -Seconds 7
  "UNLOCKED"
}

function TapLabel([string]$label, [int]$sidebarX = 200, [int]$sidebarY = 500) {
  $r = FindTextRect $label
  if (-not $r) {
    for ($i = 0; $i -lt 14 -and -not $r; $i++) {
      Wheel $sidebarX $sidebarY -5
      $r = FindTextRect $label
    }
  }
  if (-not $r) {
    for ($i = 0; $i -lt 28 -and -not $r; $i++) {
      Wheel $sidebarX $sidebarY 5
      $r = FindTextRect $label
    }
  }
  if (-not $r) { "MISS=$label"; return $false }
  Click-Rect $r
  "TAP=$label :: $r"
  return $true
}

function Alive { return [bool](Get-Process phantom_vault -ErrorAction SilentlyContinue) }

function Start-FreshApp {
  $env:PHANTOM_VAULT_DIR = $script:VaultDir
  Get-Process phantom_vault -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 2
  Start-Process -FilePath $script:ExePath | Out-Null
  Start-Sleep -Seconds 9
  Unlock $script:MasterPw
  NormalizeWindow | Out-Null
  Start-Sleep -Seconds 1
  "STEP=unlock ALIVE=$(Alive)"
}

function VerifyAll {
  Start-FreshApp

  TapLabel 'Security Audit' | Out-Null
  Start-Sleep -Seconds 2
  Save-Screenshot 'pv-v-health.png'
  "STEP=health ALIVE=$(Alive)"
  TapLabel 'Close' | Out-Null
  Start-Sleep -Seconds 1

  TapLabel '2FA Hub' | Out-Null
  Start-Sleep -Seconds 2
  TapLabel '+ Add 2FA' | Out-Null
  Start-Sleep -Seconds 2
  Save-Screenshot 'pv-v-import.png'
  "STEP=import ALIVE=$(Alive)"
  TapLabel 'Cancel' | Out-Null
  Start-Sleep -Seconds 1

  TapLabel 'Export' | Out-Null
  Start-Sleep -Seconds 3
  Save-Screenshot 'pv-v-export.png'
  "STEP=export ALIVE=$(Alive)"
  TapLabel 'Done' | Out-Null
  "VERIFY_DONE"
}

function TwoSheets {
  Start-FreshApp
  TapLabel '2FA Hub' | Out-Null
  Start-Sleep -Seconds 2
  TapLabel '+ Add 2FA' | Out-Null
  Start-Sleep -Seconds 2
  Save-Screenshot 'pv-h-import.png'
  TapLabel 'Cancel' | Out-Null
  Start-Sleep -Seconds 1
  TapLabel 'Export' | Out-Null
  Start-Sleep -Seconds 3
  Save-Screenshot 'pv-h-export.png'
  "TWO_SHEETS_DONE ALIVE=$(Alive)"
}

switch ($Action) {
  "dump"      { Dump }
  "click"     { Click-Name $Arg }
  "shot"      { Save-Screenshot $Arg }
  "unlock"    { Unlock $(if ($Arg) { $Arg } else { $script:MasterPw }) }
  "focus"     { FocusApp }
  "wheel"     { $p = $Arg -split ','; Wheel ([int]$p[0]) ([int]$p[1]) ([int]$p[2]) }
  "place"     { $p = $Arg -split ','; NormalizeWindow | Out-Null; "PLACED" }
  "clickshot" { $p = $Arg -split ','; FocusApp | Out-Null; Click-Rect (New-Object System.Windows.Rect([int]$p[0], [int]$p[1], 2, 2)); Start-Sleep -Seconds 2; Save-Screenshot $p[2] }
  "hovershot" { $p = $Arg -split ','; FocusApp | Out-Null; [PW]::SetCursorPos([int]$p[0], [int]$p[1]) | Out-Null; Start-Sleep -Milliseconds 500; Save-Screenshot $p[2] }
  "navshot"   {
    $p = $Arg -split ','
    NormalizeWindow | Out-Null
    FocusApp | Out-Null
    $r = FindTextRect $p[0]
    if (-not $r) { "MISS=$($p[0])"; Save-Screenshot $p[1]; return }
    "TARGET=$($p[0]) :: $r"
    Click-Rect $r
    Start-Sleep -Seconds 2
    Save-Screenshot $p[1]
  }
  "twosheets" { TwoSheets }
  "verify"    { VerifyAll }
  default     { "unknown action: $Action" }
}
