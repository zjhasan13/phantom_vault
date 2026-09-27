# ==============================================================================
# PROJECT AEGIS / PHANTOM_VAULT — SYSTEM RULES & ARCHITECTURAL SPECIFICATION
# ==============================================================================
# Target AI Agents: OpenCode Desktop (Big Pickle, Muse Spark 1.2 / 1.3)
# Target OS: Windows 10 / 11 (64-bit)
# Core Language: Pure Rust (2021 edition or newer)
# UI Framework: Slint (Pure Native, GPU-Accelerated, Zero-Chromium)
#
# PURPOSE:
# You are an elite Systems Architect and Cryptography Engineer. You are writing 
# the ultimate Windows-native, privacy-focused, zero-knowledge, developer-first 
# password manager. Never deviate from the strict invariants defined below.
# ==============================================================================

## 1. ABSOLUTE ARCHITECTURAL INVARIANTS (NON-NEGOTIABLE)

1. NO CHROMIUM / NO ELECTRON / NO WEBVIEW:
   - The UI MUST be rendered strictly using native Slint (DirectX/GPU via wgpu/FemtoVG).
   - Never inject WebView2 or HTML/JS runtimes. Maximum RAM footprint: 10–20 MB. Cold start: < 30ms.

2. MEMORY HARDENING & SECRECY:
   - Sensitive memory buffers (passwords, master keys, decrypted credentials, TOTP secrets, recovery shards) MUST implement `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`.
   - Wrap sensitive types in `secrecy::Secret<T>`. Never log, format, or print secrets to `stdout`/`stderr`.
   - Protect secrets in memory from being swapped to disk using Windows DPAPI and Win32 `VirtualLock` on sensitive pages.

3. STRICT AUDITED CRYPTOGRAPHY ("Don't roll your own crypto"):
   - Key Derivation Function (KDF): `argon2::Argon2` (Argon2id mode, memory-hard parameters).
   - Symmetric Authenticated Encryption: `chacha20poly1305::XChaCha20Poly1305` (AEAD with 192-bit nonce).
   - Post-Quantum Cryptography: NIST FIPS 203 `ml-kem` (ML-KEM-768/1024) hybrid layer (`PV2` portable envelope with master key-wrapping, zero sidecar dependency across machines).
   - True Randomness: System entropy via `rand_core::OsRng`.

4. ZERO-KNOWLEDGE, LOCAL-FIRST & UNIVERSAL SYNC:
   - The primary vault is fully local and encrypted on disk (`my_secure_vault.enc`).
   - Sync MUST be client-side end-to-end encrypted before leaving the machine.
   - Remote Sync Provider: User's Private GitHub Repository via `octocrab` REST API (zero Git CLI dependency).
   - Fallback Sync Providers: Local Wi-Fi P2P (mDNS/TLS), Air-Gapped Animated QR stream, and Decentralized Nostr relays.

5. ERROR HANDLING & GRACEFUL DEGRADATION:
   - NEVER use `.unwrap()` or `.expect()` in production/critical paths.
   - Use `thiserror` to define a unified `VaultError` enum across all modules.
   - If global hotkeys fail to register, warn the user rather than panicking.

---

## 2. PROJECT DIRECTORY STRUCTURE

The agent must maintain this clean modular organization:

```text
phantom_vault/
├── Cargo.toml
├── build.rs                   # Slint compilation + winres Windows .ico embedding
├── assets/
│   └── app.ico                # Embedded PhantomVault taskbar/executable logo
├── RULES.md
├── ui/
│   ├── appwindow.slint        # Slint native UI layouts & components
│   └── components/            # Slint widgets (VaultItem, TotpRow, QuickBar, Modals)
├── src/
│   ├── main.rs                # App entrypoint, event loop, hotkey dispatch & lifecycle
│   ├── error.rs               # Custom VaultError enum (via thiserror)
│   ├── core/
│   │   ├── mod.rs
│   │   ├── crypto.rs          # Argon2id, XChaCha20Poly1305, key wrapping (wrap_dk/unwrap_dk)
│   │   ├── pq_hybrid.rs       # NIST FIPS 203 ML-KEM-768 hybrid engine (PV2 envelope)
│   │   ├── generator.rs       # Complex symbol + 7776-word EFF Diceware generator
│   │   ├── memory.rs          # Zeroize allocators, DPAPI guard, VirtualLock paging protection
│   │   ├── passkey.rs         # Ed25519 resident WebAuthn keys, RFC 8410 DER codec, assertions
│   │   ├── storage.rs         # Portable versioned save/load, auto-migration, DoD shredder hook
│   │   └── models.rs          # Credential, PaymentCard, IdentityItem, SshKeyItem, Passkey, Folder
│   ├── authenticator/
│   │   ├── mod.rs
│   │   ├── totp.rs            # RFC 6238 TOTP, RFC 4226 HOTP, and Steam Guard 5-char generators
│   │   ├── google_migration.rs# Google Authenticator Protobuf parser (prost)
│   │   ├── qr_scanner.rs      # Screen region snip & clipboard QR decoder (rqrr)
│   │   └── camera_scanner.rs  # Live webcam video stream QR reader
│   ├── importer/
│   │   ├── mod.rs             # Unified ingestion pipeline & deduplication
│   │   ├── sniffer.rs         # Auto-format sniffer, BOM stripper, delimiter detector (, ; \t |)
│   │   ├── bitwarden.rs       # Bitwarden JSON & CSV parser (custom fields, URIs, notes)
│   │   ├── keepass.rs         # KeePass 2.x XML (<KeePassFile>) & CSV parser
│   │   ├── onepassword.rs     # 1Password CSV & 1PUX/Proton Pass JSON parser
│   │   ├── browser_csv.rs     # Chrome, Brave, Edge, Firefox, Safari (OTPAuth), LastPass CSVs
│   │   └── fuzzy.rs           # Universal heuristic fallback for unknown CSV/TSV
│   ├── windows_native/
│   │   ├── mod.rs
│   │   ├── hello.rs           # Windows Hello biometrics (WinRT UserConsentVerifier bridge)
│   │   ├── display_guard.rs   # SetWindowDisplayAffinity (WDA_MONITOR GDI/OBS/ShareX blackout)
│   │   ├── device_bind.rs     # DPAPI-sealed MachineGuid binding check (warn-only anti-clone tripwire)
│   │   ├── clipboard.rs       # Win+V exclusion formats, busy-retry, guarded 15s auto-clear
│   │   ├── autotype.rs        # Win32 SendInput unicode keystroke engine with settle timing
│   │   ├── desktop_autofill.rs# Windows UI Automation (UIA) focused field probe
│   │   ├── smart_grab.rs      # Alt+S active app capture & quick-save dialog
│   │   ├── proximity_lock.rs  # Bluetooth Low Energy (BLE) RSSI proximity auto-lock
│   │   ├── native_host.rs     # Native Messaging Host bridge for browser extensions (stdin/stdout)
│   │   └── hotkeys.rs         # Global hotkeys (Alt+Space, Alt+S, Ctrl+Alt+A, Ctrl+Shift+Alt+Q)
│   ├── developer/
│   │   ├── mod.rs
│   │   ├── ssh_agent.rs       # Named pipe \\.\pipe\openssh-ssh-agent (protocol sign/verify)
│   │   ├── git_signer.rs      # SSH-based commit signing with Windows Hello biometric confirmation
│   │   ├── vault_run.rs       # CLI process secret injection (no .env files on disk)
│   │   ├── precommit_hook.rs  # Git secret leak detection scanner (13 rules + Shannon entropy)
│   │   ├── shell_complete.rs  # PowerShell, Bash, Nushell tab-autocompletion script generator
│   │   ├── cloud_tokens.rs    # Ephemeral 1-hour AWS STS session token generator
│   │   └── db_tunnel.rs       # 1-click background SSH port-forwarding database tunnel
│   ├── security/
│   │   ├── mod.rs
│   │   ├── anti_debug.rs      # Anti-debugging watchdog (2-strike timing, Mimikatz defense)
│   │   ├── decoy.rs           # Duress/Fake secondary vault (read-only cover)
│   │   ├── canary.rs          # Honeytoken tripwire credentials with alert logging
│   │   ├── steganography.rs   # LSB PNG image locker (hide vault in carrier PNG)
│   │   ├── shredder.rs        # DoD 5220.22-M 3-pass disk overwrite (0x00, 0xFF, OsRng)
│   │   ├── shamir.rs          # Shamir's Secret Sharing (3-of-5 threshold, GF(2^8) + EFF words)
│   │   ├── pdf_sheet.rs       # Offline 1-page printable emergency recovery sheet (raw PDF 1.4)
│   │   └── travel_mode.rs     # Temporary vault stripping/hiding for border crossing
│   └── sync/
│       ├── mod.rs
│       ├── github_sync.rs     # Octocrab API integration (private repo sync, sha conflict guard)
│       ├── airgap_qr.rs       # Animated high-density QR camera sync for mobile
│       ├── p2p_local.rs       # LocalSend-style LAN sync via mDNS and TLS
│       ├── nostr_sync.rs      # Decentralized relay-based encrypted sync
│       └── crdt_merge.rs      # Conflict-free Replicated Data Type offline merging
3. EXHAUSTIVE FEATURE SPECIFICATION (A TO Z)
Category 1: Rich Vault & Item Management (Full Bitwarden Parity)
Logins & Passwords: Username, password (masked, eye toggle, generator), multi-URLs, custom fields, notes.
Embedded Authenticator (TOTP/HOTP): TOTP secret embedded directly inside login items (live 30s countdown, copy).
Backup & Recovery Codes: Multiline storage for 8–10 one-time recovery codes with a single 📋 Copy All Codes button.
Dynamic Custom Fields (Bitwarden Parity):
Text: Security questions, secondary logins, PINs.
Hidden: Masked secret keys, API tokens with eye reveal toggle.
Checkbox: Boolean flags.
Linked: Live mirror referencing username or password without duplicating secrets at rest.
Dynamic Custom Folders: Built-in folders + dynamic user-created folders (+ Folder), folder assignment, folder filter.
Item Detail & Inspection Modal: Full modal view on item click, eye toggles, copy buttons, ⚡ Fill button, ✏️ Edit, and 🗑️ Delete.
Master Password Reprompt: Gate sensitive items behind an in-memory master password re-prompt before viewing/copying.
Favorites & Trash: Star pins with sidebar filter; two-phase soft-delete (30-day DoD-shredded Trash with restore).
Password History & Rotation: Last-5 retired passwords per login with 6-month stale warnings.
Passkey Support (FIDO2 / WebAuthn): Store and manage resident credentials / passkeys for passwordless web authentication.
Multi-Type Vault Items:
📜 Software Licenses: App name, license key, purchase date, expiry date, notes, receipt attachments.
📝 Secure Notes: AES-encrypted Markdown notes.
💳 Payment Cards: Cardholder name, card number (masked/revealed), expiration, CVV, billing notes.
🪪 Identities: Full name, NID/Passport number, email, phone, physical address, notes.
🔑 SSH Keys: Key name, private key (masked), public key, fingerprint, notes.
Encrypted File Attachments: Store encrypted receipt photos, invoices, and certificates inside the container.
Password & Diceware Generator:
Complex symbol generator (guaranteed inclusion, Fisher-Yates shuffle, Shannon entropy rating).
Diceware Passphrase generator (EFF 7776-wordlist, 4–12 words with custom separators).
Category 2: 2FA & Authenticator (Proton & Google Auth Killer)
Live TOTP Engine: RFC 6238 standard, 30-second live circular countdown ring.
HOTP Engine: RFC 4226 counter-based one-time password generation.
Steam Guard 2FA: 5-character alphanumeric token algorithm for gaming accounts.
Google Authenticator 1-Click Migration: Protobuf parser (prost) decoding otpauth-migration:// export payloads.
Screen & Clipboard QR Scanner: Win+Shift+S screen snipper and clipboard image QR decoder via rqrr.
Live Webcam Scanner: Video stream QR code reader using native PC webcam.
Category 3: Universal Omni-Importer Engine (Zero-Failure)
Content Auto-Sniffer: Automatic file signature, BOM, and delimiter detection (, ; \t |).
Supported Providers:
Bitwarden (both .json and .csv with full custom fields and folders).
1Password (both .csv and 1PUX / export.data JSON).
KeePass / KeePassXC (.xml <KeePassFile> with group hierarchy and .csv).
Google Chrome, Brave, Edge, Opera (.csv).
Mozilla Firefox (logins.json and .csv).
Apple Safari / iCloud Keychain (passwords.csv with OTPAuth column).
LastPass & Dashlane (.csv).
Proton Pass (.json).
Universal Fuzzy Fallback (heuristic scoring for unknown CSV/TSV).
Fault Tolerance: Row-level error containment (bad row skipped, batch continues), intelligent deduplication.
Category 4: Windows Native & UX Mastery
GPU-Accelerated UI: Slint-driven "Phantom Aura" fluent dark theme running directly on DirectX/Vulkan.
Raycast / Spotlight Quick-Bar (Alt + Space): Floating search bar overlay; instant search and 1-click credential/TOTP copy (< 0.2s), Esc dismiss, toggleable.
Desktop In-line Autofill: UI Automation (UIA) detects focused password boxes in native apps (Steam, Discord, Telegram, Spotify, Browsers).
Smart-Grab & Auto-Capture (Alt + S): Automatically captures active application name and form data to save new credentials in 1 click.
Global Auto-Type (Ctrl + Alt + A): Direct keystroke simulation {User}{Tab}{Pass}{Enter} via Win32 SendInput with 800ms DWM settle delay.
Windows Hello Biometric Unlock: Unlock the vault in < 0.1s using Fingerprint, Face ID, or PIN via WinRT UserConsentVerifier bridge.
Clipboard Masking (Win + V Exclusion): Sets ExcludeClipboardContentFromMonitorProcessing, CanIncludeInClipboardHistory=0, and CanUploadToCloudClipboard=0.
Guarded Clipboard Auto-Flush: Clears clipboard after 15s only if the copied secret still matches.
Pastejacking Protection: Strips hidden carriage returns (\r, \n) or shell traps from copied strings.
DWM Screen Capture Blackout: SetWindowDisplayAffinity(hwnd, WDA_MONITOR) forces a pitch-black box on ShareX, Snipping Tool, OBS, Discord, and Zoom.
Memory Paging Lock (VirtualLock): Locks sensitive crypto pages in RAM to prevent swapping into pagefile.sys.
Bluetooth Proximity Auto-Lock: Measures BLE RSSI; automatically locks the vault when the user's paired phone/watch leaves proximity.
Windows App Branding (.ico): winres embeds assets/app.ico into the executable binary for the taskbar and desktop.
Category 5: Developer Superpowers
Native OpenSSH Agent: Expose \\.\pipe\openssh-ssh-agent. Confirm git push or SSH sessions via biometric touch without typing passphrases.
Git Commit Signing via SSH: Sign commits with biometric touch to get GitHub "Verified" green badges (no GPG configuration).
vault run CLI Secret Injector: Inject secrets into child processes in memory (vault run -- npm start). Zero plaintext .env files on disk.
Git Pre-Commit Secret Scanner (vault scan): Hook preventing accidental commit of API keys (13 rules + Shannon entropy).
Shell Autocomplete Script: PowerShell, Bash, and Nushell completion script generator (vault get <tab>).
Temporary Cloud Session Tokens: Ephemeral 1-hour AWS STS session token generation.
1-Click Database Tunneling: Background SSH port-forwarding database tunnel manager.
Docker / Podman Secret Mount: RAM-based tmpfs volume mounting for container secrets.
Category 6: Military-Grade & Paranoia Defense
Post-Quantum Cryptography (PQC): NIST FIPS 203 ML-KEM-768 hybrid key layer (PV2 portable container with master key-wrapped DK).
Hardware Binding (TPM 2.0 & YubiKey): DPAPI-backed Windows TPM lock and YubiKey HMAC-SHA256 Challenge-Response.
Anti-Debugging Watchdog: 2-strike timing detection against attached debuggers and Mimikatz memory dumpers.
Instant Panic Nuke Hotkey (Ctrl + Shift + Alt + Q): Best-effort RAM zeroize wipe and immediate process termination (0x1AFE).
Decoy / Duress Vault: Secondary duress password opens an isolated fake vault with dummy entries (read-only cover).
Canary Trap / Honeytokens: Trap credentials that trigger background emergency alerts if viewed or copied.
Steganography PNG Locker: Embeds and extracts encrypted vault containers inside ordinary carrier PNG images using LSB encoding (b"PSTE").
Secure File Shredder (DoD 5220.22-M): 3-pass disk overwrite (0x00, 0xFF, OsRng) before deletion.
Travel Mode: Border-control mode temporarily hiding flagged vaults/items.
Category 7: Privacy, Sync & Disaster Recovery
Private GitHub Repo Sync: Zero-knowledge encrypted sync using octocrab. Automate commit & push on changes, giving free unlimited version history.
Sync Proxy & Metadata Minimization: Fixed generic commit messages (no timestamps/counts/names); sync and HIBP traffic honor HTTPS_PROXY/HTTP_PROXY/ALL_PROXY (Tor-friendly) with proxy presence surfaced in sync status, never the URL.
Shamir's Secret Sharing (3-of-5): Mathematical Galois Field 
G
F
(
2
8
)
GF(2 
8
 )
 master key splitting into 82-word EFF shards with lock screen recovery.
Emergency Printable Sheet: 1-page printable PDF containing QR and recovery parameters.
Air-Gapped Animated QR Sync: High-density animated QR streaming for mobile sync without radio (Wi-Fi/Bluetooth).
Local P2P Wi-Fi Sync: LocalSend-style LAN sync via mDNS and TLS.
Decentralized Nostr Relays Sync: Censorship-resistant relay-based encrypted sync.
CRDT Conflict-Free Engine: Offline multi-device edits merge mathematically without sync conflict files.
Privacy Email Aliases: Addy.io / SimpleLogin API integration for throwaway forwarding emails.
Zero-Footprint Portable Mode: Run completely within a RAM-disk from a USB drive without leaving temporary SSD artifacts.
Private Metadata / Favicon Fetcher: Anonymous logo downloading via DNS-over-HTTPS (DoH) or Tor.
Password Health & Breach Checker: HaveIBeenPwned k-Anonymity API (first 5 SHA-1 characters, no plaintext leakage).
Offline Health Audit: Fully local reuse/weakness scan with zero network calls for air-gapped machines (breach verdicts reported as unknown).
Category 8: Extended Session, Process & Lifecycle Hardening (Architect's Addenda)
Session & Locking:
Workstation-Lock Auto-Lock: Vault locks instantly on Win+L / WTS session-lock events, not only on timer expiry.
RDP & Screensaver Auto-Lock: Remote-desktop disconnect and screensaver activation trigger the same RAM-wiping lock path.
Clipboard Flush on Lock/Exit: Locking the vault or exiting the process guarded-clears any resident secret from the clipboard.
Blur on Focus Loss: Secrets auto-mask the moment the window loses focus (Alt+Tab / shoulder-surfing defense).
Process & OS Hardening:
DLL-Injection Block: SetProcessMitigationPolicy (Microsoft-only binary signatures) refuses non-Microsoft DLLs in our process.
Crash-Dump Exclusion: WerAddExcludedApplication keeps full-memory crash dumps (and embedded secrets) off Microsoft servers.
Admin-Elevation Warning: Loud startup warning when running elevated, with portable-mode guidance (elevated = larger blast radius).
Startup Self-Integrity Check: DPAPI-sealed binary hash verified at launch; tampering raises a blocking warning.
IME Off in Password Fields: Cloud-IME keystroke leakage disabled in every password input (bank-grade practice).
Authentication Strength:
KDF Pepper: DPAPI-sealed machine-bound pepper mixed into the Argon2id input with transparent legacy re-seal migration (stolen-file brute-force resistance).
Password + Hello AND-Mode: Optional toggle requiring BOTH master password and Windows Hello (default remains OR-mode).
Brute-Force Backoff: Persisted wrong-attempt counter with growing unlock delay (plaintext counter, never secrets).
Secure Desktop Unlock: KeePass-style isolated-desktop master-password prompt immune to user-mode keyloggers and scrapers.
Data Lifecycle & Visibility:
Versioned Backup Rotation: Last N encrypted backups retained with DoD shred-rotation of expired generations.
Shred Import Source: After successful plaintext import (CSV/JSON), prompt to DoD-shred the lingering source file.
Password Age Reminders: Per-item last-changed tracking with stale-password (>1yr) warning badges in audit reports.
Tamper-Evident Access Log: Hash-chained append-only log of unlock/copy/export events (metadata only, never secrets) for coercion detection.
Global Offline Kill-Switch: Single master toggle silencing ALL network traffic (sync + HIBP) for hostile networks and border crossings.
4. CODING CONVENTIONS FOR AI AGENTS
DEPENDENCY SPECIFICATIONS (Must use current stable versions):
argon2 = "0.5"
chacha20poly1305 = "0.10"
zeroize = { version = "1.8", features = ["derive"] }
secrecy = "0.8"
slint = "1.8" (with raw-window-handle-06)
windows = "0.58" / windows-sys = "0.59"
tokio = { version = "1.38", features = ["full"] }
totp-rs = "5.7"
prost = "0.13"
octocrab = "0.38"
rqrr = "0.7"
bincode = "1.3"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
csv = "1.3"
quick-xml = "0.36"
rfd = "0.14"
global-hotkey = "0.6"
image = "0.25"
hkdf = "0.12"
ml-kem = "0.2"
sha2 = "0.10"
BUILD DEPENDENCIES (for Windows icon embedding):
code
Toml
[build-dependencies]
slint-build = "1.8"
winres = "0.1"
DEV & RELEASE COMPILATION OPTIMIZATIONS:
The Cargo.toml must include:
code
Toml
[profile.dev.package."*"]
opt-level = 3

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
panic = "abort"
AGENT WORKFLOW & VERIFICATION:
Build iteratively module by module.
Run cargo check and cargo test after implementing each module.
Always retain existing passing unit tests.
Supply-chain audit: `cargo audit` (RustSec) runs in CI on every push/PR (`.github/workflows/security.yml`); no known-RUSTSEC-vulnerable dependency may ship.
Never stub out security functions with "TODO" or insecure dummy fallbacks.
Keep comments concise and maintain maximum code clarity.

---

## 5. PRODUCTION BASELINE — MASTER CONSTITUTION (v0.1.0, 244 tests green)

Scale: 60+ Rust modules (61 `.rs` files), 244 unit tests passing / 0 failing
(1 ignored: live HIBP network test), `cargo check` zero-warning.

Architecture (all shipped, all tested):
- NIST FIPS 203 ML-KEM-768 hybrid key layer (`PV2` portable container with
  wrapped DK; `core/pq_hybrid.rs`, `crypto.rs`).
- Pure Slint GPU "Phantom Aura" 3-column Bitwarden UI + 2-column Proton 2FA
  Hub (`ui/appwindow.slint`); per-card live countdown rings, HOTP/Steam paths.
- Isolated 2FA Hub search (`totp_search_query`) — never cross-filters vault.
- Windows System Tray (`windows_native/tray.rs`): icon + Open/QuickBar/Lock/
  Exit menu, close-to-tray (default ON, `tray_minimize.pref`), `EmptyWorkingSet`
  trim on minimize. X with tray OFF = secure exit (never a linger).
- Automated Scheduled Backup Rotation (`storage/backup_scheduler.rs`):
  weekly default → Documents, keep 10, 3-pass shred prune, 30-min heartbeat.
- Local Wi-Fi P2P Sync, port 52199 (`sync/p2p_local.rs`): UDP beacons +
  minimal HTTP (pull/push), ciphertext-only, SHA+mtime conflict guard,
  server-side freshness gate (stale pushes → 409), DPAPI-sealed 6-digit
  pairing PIN gating BOTH endpoints (Settings shows PIN + regenerate).
- 1-Click GitHub Releases Auto-Updater (`sync/updater.rs`): semver compare,
  staged download, post-exit swap script, MANDATORY SHA-256 sidecar verify
  (fail-closed, staged file shredded on mismatch). Trust root: TLS + pinned
  repo + checksums (code-signature verify still REQUIRED before store
  distribution).
- Bengali Diceware (`core/generator.rs` + `assets/bengali_words.txt`):
  140-word list, 4–8 words + ২-digit suffix, honest Shannon bits.
- Desktop UIA Autofill + Smart-Grab (`Alt+S`) + hands-free 2FA chaining;
  card/identity TAB sequences with focus-loss abort; exe typosquat guard;
  reprompt modal. Autotype backs `trigger_autotype` per-kind requests with
  snapshot rollback on every mutation path.
- Universal Omni-Importer (Bitwarden/1Password/KeePass/Chrome/Safari/
  LastPass/Proton/Fuzzy): passwordHistory ingestion, backup-code auto-sort,
  identity email/company/state/postal preserved, otpauth-URL TOTP normalize
  (non-default params flagged, never silent), KeePass custom fields,
  content-aware dedup keys (rotations re-import visibly).
- Reverse Exporter Suite: Google Migration QR (`authenticator/
  google_migration.rs`, batched 1-based index, Steam/period loss flagged) +
  Bitwarden JSON/CSV (`importer/exporter.rs`, backup-codes + CSV roundtrip
  tested). Both master-gated (reprompt action 5, decoy refused).
- Universal 2FA ingestion (`authenticator/universal_2fa.rs`): 2FAS, Aegis,
  Steam .maFile, andOTP, FreeOTP, multi-line URIs, multi-QR images;
  encrypted exports fail LOUD with guidance; smart dedup merge.
- Generation-guarded clipboard (`windows_native/clipboard.rs`): monotonic
  `CLIPBOARD_GEN` retires stale auto-clear workers; flush retires all;
  per-handle ownership (never free OS-owned blocks).
- Heap-pinned secrets (`core/memory.rs::LockedBytes`): `VirtualLock` on the
  real buffer (the old generic pinned only the String fat pointer).
- Atomic vault writes (`security/shredder.rs::secure_write`): tmp+rename,
  never torn; stale `vault.lock` reclaimed after 60s.
- Health scoreboard (`security/breach_check.rs` + Settings card): 0–100
  score (−25/−10/−5/−2, +10 2FA bonus), gauge, click-to-filter metric cards,
  2FA coverage bar, Re-Scan.
- Anti-photography Moiré lens guard + peep-hole hold-to-reveal; blackout
  guard default OFF (`blackout.pref`).
- Native Messaging Host bridge (`windows_native/native_host.rs`): Hello-
  cached unlock, CWD fix, decoy-cover serving, save/stats/filled/cards/
  identities commands; registry install locks `allowed_origins` to one ID.
- Browser extension (`browser_extension/`): smart autofill engine, save
  prompt, badge count, popup TOTP + reprompt/domain guards, fill audit,
  settings + i18n, debounced badge.
- Resource diet: 2FA ticker + UIA probe deep-sleep when locked/hidden
  (`ui_visible` atomic); release `lto = "fat"`.
- Packaging: `installer.iss` (Inno Setup 6, HKCU host keys, full uninstall);
  release gate: `QA_CHECKLIST.md` 7 physical tests.