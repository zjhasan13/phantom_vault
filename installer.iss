; ==============================================================================
; PhantomVault — Inno Setup 6 production installer.
; Bureaucracy-free: per-user install (no admin), HKCU native-messaging keys,
; full uninstall. Bump AppVersion together with Cargo.toml on every release.
; Build the exe first:  cargo build --release   (then ISCC installer.iss)
; ==============================================================================

#define MyAppName "PhantomVault"
; KEEP IN SYNC with Cargo.toml [package] version.
#define MyAppVersion "0.3.1"
#define MyAppPublisher "PhantomVault Security Foundation"
#define MyAppExeName "phantom_vault.exe"
; Host manifests are GENERATED at install time by WriteHostManifest below
; (nothing checked in — intentional, see [Code]). Same for the .firefox one.
#define HostJsonName "com.phantomvault.host.json"

[Setup]
AppId={{3F7A9B2C-8D4E-4A1F-9C6B-1E5F7A2B4D8C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=installer-output
OutputBaseFilename=PhantomVault-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#MyAppName}
; Never vaporize the user's vault: data files are NOT tracked below.

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
  GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\app.ico"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "browser_extension\*"; DestDir: "{app}\browser_extension"; \
  Excludes: "dist\*"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
  IconFilename: "{app}\assets\app.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
  IconFilename: "{app}\assets\app.ico"; Tasks: desktopicon

; Native Messaging host keys (HKCU — no admin). The default value of each key
; is the host manifest path. The app's "Install Browser Extension Host"
; button later rewrites these to %LOCALAPPDATA%\PhantomVault\native-host.json
; with allowed_origins locked to the user's real extension ID.
[Registry]
Root: HKCU; \
  Subkey: "Software\Google\Chrome\NativeMessagingHosts\com.phantomvault.host"; \
  ValueType: string; ValueName: ""; \
  ValueData: "{app}\browser_extension\{#HostJsonName}"; Flags: uninsdeletekey
Root: HKCU; \
  Subkey: "Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.phantomvault.host"; \
  ValueType: string; ValueName: ""; \
  ValueData: "{app}\browser_extension\{#HostJsonName}"; Flags: uninsdeletekey
Root: HKCU; \
  Subkey: "Software\Microsoft\Edge\NativeMessagingHosts\com.phantomvault.host"; \
  ValueType: string; ValueName: ""; \
  ValueData: "{app}\browser_extension\{#HostJsonName}"; Flags: uninsdeletekey
; Placeholder: the app's Firefox button rewrites this to
; %LOCALAPPDATA%\PhantomVault\native-host-firefox.json (allowed_extensions).
Root: HKCU; \
  Subkey: "Software\Mozilla\NativeMessagingHosts\com.phantomvault.host"; \
  ValueType: string; ValueName: ""; \
  ValueData: "{app}\browser_extension\com.phantomvault.host.firefox.json"; Flags: uninsdeletekey

[Code]
// Write a locked-down host manifest (empty allowed_origins = no extension
// can connect until the user pairs theirs in the app). Returns False only
// on disk failure — install continues, the app button repairs it later.
// JSON strings need doubled backslashes (C:\x -> C:\\x). Written with
// plain Pascal only (no StrUtils dependency quirks across ISCC versions).
function DoubleBackslashes(const S: String): String;
var
  i: Integer;
begin
  Result := '';
  for i := 1 to Length(S) do
  begin
    if S[i] = '\' then
      Result := Result + '\\'
    else
      Result := Result + S[i];
  end;
end;

function WriteHostManifest(): Boolean;
var
  ManifestPath, ExePath, Doc: String;
begin
  ManifestPath := ExpandConstant('{app}\browser_extension\{#HostJsonName}');
  ExePath := DoubleBackslashes(ExpandConstant('{app}\{#MyAppExeName}'));
  Doc := #13#10 +
    '{ "name": "com.phantomvault.host",' + #13#10 +
    '  "description": "PhantomVault native bridge (stdio, vault-gated)",' + #13#10 +
    '  "path": "' + ExePath + '",' + #13#10 +
    '  "type": "stdio",' + #13#10 +
    '  "allowed_origins": [] }';
  Result := SaveStringToFile(ManifestPath, Doc, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not WriteHostManifest() then
      MsgBox('Host manifest could not be written. Open PhantomVault → ' +
        'Settings → Browser Bridge → Install Browser Extension Host.',
        mbInformation, MB_OK);
  end;
end;

[UninstallDelete]
; Remove the generated manifest (tracked files + shortcuts + keys go
; automatically). User vault/data files are NEVER touched.
Type: files; Name: "{app}\browser_extension\{#HostJsonName}"
