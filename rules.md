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
   - Sensitive memory buffers (passwords, master keys, decrypted credentials, TOTP secrets) MUST implement `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`.
   - Wrap sensitive types in `secrecy::Secret<T>`. Never log, format, or print secrets to `stdout`/`stderr`.
   - Protect secrets in memory from being swapped to disk using Windows DPAPI or `VirtualLock`.

3. STRICT AUDITED CRYPTOGRAPHY ("Don't roll your own crypto"):
   - Key Derivation Function (KDF): `argon2::Argon2` (Argon2id mode, memory-hard parameters).
   - Symmetric Authenticated Encryption: `chacha20poly1305::XChaCha20Poly1305` (AEAD with 192-bit nonce).
   - Post-Quantum Cryptography: `ml-kem` (Kyber-768/1024) hybrid layer for future-proof quantum resistance.
   - True Randomness: System entropy via `rand_core::OsRng`.

4. ZERO-KNOWLEDGE & LOCAL-FIRST:
   - The primary vault is fully local and encrypted on disk (`vault.enc`).
   - Sync MUST be client-side end-to-end encrypted before leaving the machine.
   - Remote Sync Provider: User's Private GitHub Repository via `octocrab` REST API. Zero cloud subscription fees.

5. ERROR HANDLING:
   - NEVER use `.unwrap()` or `.expect()` in production/critical paths.
   - Use `thiserror` to define a unified `VaultError` enum across all modules.

---

## 2. PROJECT DIRECTORY STRUCTURE

The agent must maintain this clean modular organization:

```text
phantom_vault/
├── Cargo.toml
├── RULES.md
├── ui/
│   ├── appwindow.slint        # Slint native UI layouts & components
│   └── components/            # Slint widgets (VaultItem, TotpRow, QuickBar)
├── src/
│   ├── main.rs                # App entrypoint, event loop & lifecycle
│   ├── error.rs               # Custom VaultError enum (via thiserror)
│   ├── core/
│   │   ├── mod.rs
│   │   ├── crypto.rs          # Argon2id, XChaCha20Poly1305, Kyber-768
│   │   ├── memory.rs          # Zeroize allocators, DPAPI bindings
│   │   ├── storage.rs         # Bincode serialization & encrypted file I/O
│   │   └── models.rs          # VaultItem, Credential, LicenseKey, Note structs
│   ├── authenticator/
│   │   ├── mod.rs
│   │   ├── totp.rs            # RFC 6238 TOTP & Steam Guard generators
│   │   ├── google_migration.rs# Google Authenticator Protobuf parser (prost)
│   │   └── screen_scanner.rs  # Windows screen region snip & QR decoder (rqrr)
│   ├── windows_native/
│   │   ├── mod.rs
│   │   ├── hello.rs           # Windows Hello biometrics (WinRT Credentials UI)
│   │   ├── display_guard.rs   # SetWindowDisplayAffinity (OBS/Discord blackout)
│   │   ├── clipboard.rs       # Win+V masking & auto-clear (15-20s timer)
│   │   ├── autotype.rs        # Win32 SendInput virtual keystroke injection
│   │   ├── uia_autofill.rs    # Windows UI Automation (desktop inline autofill)
│   │   └── hotkeys.rs         # Global hotkeys (Alt+Space, Panic Nuke)
│   ├── developer/
│   │   ├── mod.rs
│   │   ├── ssh_agent.rs       # Named pipe \\.\pipe\openssh-ssh-agent
│   │   ├── git_signer.rs      # SSH-based commit signing with biometric touch
│   │   ├── vault_run.rs       # CLI process secret injection (no .env files)
│   │   └── precommit_hook.rs  # Git secret leak detection scanner
│   ├── security/
│   │   ├── mod.rs
│   │   ├── anti_debug.rs      # Anti-debugging, Mimikatz memory dump defense
│   │   ├── decoy.rs           # Duress/Fake secondary vault
│   │   ├── canary.rs          # Honeytoken tripwire credentials
│   │   ├── steganography.rs   # Hide encrypted vault inside PNG/MP4
│   │   ├── shredder.rs        # DoD 5220.22-M secure disk overwrite
│   │   └── shamir.rs          # Shamir's Secret Sharing (3-of-5 shard recovery)
│   └── sync/
│       ├── mod.rs
│       ├── github_sync.rs     # Octocrab API integration (private repo sync)
│       ├── airgap_qr.rs       # Animated high-density QR camera sync
│       └── p2p_local.rs       # LocalSend-style LAN sync via mDNS
3. EXHAUSTIVE FEATURE SPECIFICATION (A TO Z)
Category 1: Core Vault Items
Logins & Passwords: Username, password, multi-URLs, custom fields.
Password Generator: Dice-ware passphrase generator and complex customizable symbol generator.
Software Licenses & Keys: Activation codes, purchase dates, expiry, and receipt/invoice file attachments.
Secure Notes: AES-encrypted Markdown notes.
Identities & Payment Cards: Credit/debit cards, bank accounts, passport, and National ID numbers.
Encrypted File Locker: Secure document storage inside the encrypted container.
Category 2: 2FA & Authenticator (Proton/Google Auth Killer)
Live TOTP/HOTP: RFC 6238 standard, 30-second countdown with visual circular progress ring.
Google Authenticator 1-Click Migration: Parse Google's otpauth-migration:// Protobuf payloads via prost to import all accounts instantly.
Screen QR Snipper: Crop any region on the Windows desktop, decode QR via rqrr, extract secret key directly.
Steam Guard Support: Generate Steam-compliant 5-character alphanumeric 2FA tokens.
Category 3: Windows Native & UX Mastery
GPU-Accelerated UI: Slint-driven fluent dark theme running directly on DirectX/Vulkan.
Raycast / Spotlight Quick-Bar (Alt + Space): Floating search bar overlay; instant search and 1-click credential/TOTP copy (< 0.2s).
System-Wide Desktop Autofill: Detect password boxes in native apps (Discord, Steam, Spotify, VPNs) using IUIAutomation and display inline auto-fill icon.
Global Auto-Type (Ctrl + Alt + A): Directly simulate keystrokes {User}{Tab}{Pass}{Enter} via Win32 SendInput. Completely bypasses clipboard sniffing.
Windows Hello Biometric Unlock: Unlock the vault in < 0.1s using Fingerprint, Face ID, or PIN via windows::Security::Credentials::UI.
Clipboard Masking & Auto-Flush: Exclude passwords from Windows 10/11 Win + V history via ExcludeClipboardContentFromMonitorProcessing. Auto-clear clipboard in 15–20s.
Pastejacking Protection: Sanitize hidden carriage returns (\r, \n) or shell traps from copied strings.
Category 4: Developer Superpowers
Native OpenSSH Agent: Expose \\.\pipe\openssh-ssh-agent. Confirm git push or SSH sessions via biometric touch without typing passphrases.
Git Commit Signing via SSH: Sign commits with biometric touch to get GitHub "Verified" green badges (no GPG configuration).
vault run CLI Secret Injector: Inject secrets into child processes in memory (vault run -- npm start). Zero plaintext .env files on disk.
Git Pre-Commit Secret Scanner: Hook to prevent committing API keys (OpenAI, AWS, Stripe) into repositories.
Shell Autocomplete: Native PowerShell / CMD / Bash tab autocompletion (vault get <tab>).
Temporary Cloud Credentials: Issue ephemeral 1-hour AWS STS session tokens automatically.
Category 5: Military-Grade & Paranoia Defense
OBS / Screen Share Blackout: Enforce SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) so the app renders as a pitch-black box on Discord/Zoom/OBS.
Hardware Binding (TPM 2.0 & YubiKey): Lock master key with Windows TPM 2.0 and support YubiKey HMAC-SHA256 Challenge-Response.
Anti-Debugging & Self-Defense: Detect attached debuggers or memory injection tools (Mimikatz/Process Hacker). Abort instantly (std::process::abort()) and zeroize memory on detection.
Instant Panic Nuke Hotkey (Ctrl + Shift + Alt + Q): Immediate memory wipe and process termination.
Decoy / Duress Vault: Entering a secondary duress password opens an isolated fake vault with dummy entries.
Canary Trap / Honeytokens: Trap credentials that trigger background emergency alerts if viewed or copied.
Steganography: Capability to hide the encrypted vault container inside standard PNG images or MP4 video files.
Secure File Shredder: Multi-pass random overwrite (DoD 5220.22-M standard) on deletion.
Category 6: Privacy, Sync & Disaster Recovery
Private GitHub Repo Sync: Zero-knowledge encrypted sync using octocrab. Automate commit & push on changes, giving free unlimited version history.
Air-Gapped Animated QR Sync: Sync to mobile devices without Wi-Fi, Bluetooth, or cables using high-speed animated QR code streams.
Zero-Cloud Local P2P Sync: Direct LAN synchronization using mDNS and TLS.
CRDT Conflict-Free Engine: Multi-device offline edits merge mathematically without sync conflict files.
Privacy Email Aliases: Integrate Addy.io / SimpleLogin APIs to generate random forwarding emails on the fly.
Shamir's Secret Sharing: Split master key into 3-of-5 threshold shards for family disaster recovery.
Time Machine Rollback: Micro-version history for all credentials to restore past passwords.
Zero-Footprint Portable Mode: Run completely within a RAM-disk from a USB drive without leaving temporary SSD artifacts.
4. CODING CONVENTIONS FOR AI AGENTS
DEPENDENCY SPECIFICATIONS (Must use current stable versions):
argon2 = "0.5"
chacha20poly1305 = "0.10"
zeroize = { version = "1.8", features = ["derive"] }
secrecy = "0.8"
slint = "1.7" (or latest stable)
windows = { version = "0.58", features = [...] }
tokio = { version = "1.38", features = ["full"] }
totp-rs = "5.6"
prost = "0.13"
octocrab = "0.38"
rqrr = "0.7"
bincode = "1.3"
serde = { version = "1.0", features = ["derive"] }
RELEASE COMPILATION OPTIMIZATIONS:
The Cargo.toml must include:
code
Toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
panic = "abort"
AGENT WORKFLOW:
Build iteratively module by module.
Run cargo check and cargo test after implementing each module.
Never stub out security functions with "TODO" or insecure dummy fallbacks.
Keep comments concise and maintain maximum code clarity.