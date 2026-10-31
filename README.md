# PhantomVault

**A local-first, post-quantum-hybrid password manager for Windows, with a browser autofill bridge.**

No account. No vendor server. The vault is one encrypted file on your disk; if you
enable sync, the ciphertext goes to storage *you* control.

- **Desktop:** Rust + [Slint](https://slint.dev) (software renderer — no WebView, no Electron)
- **Extension:** Manifest V3 (Chrome, Edge, Firefox) over the native-messaging bridge
- **Container:** Argon2id → XChaCha20-Poly1305 → ML-KEM-768 + X25519 hybrid
- **Status:** **0.4.1, pre-1.0.** Windows 10/11 x64. Binaries are **not signed yet**.

> Read [Security model](#security-model) and [Known gaps](#known-gaps-and-honest-limits)
> before trusting it with anything that matters. This project documents its own
> limits instead of hiding them.

---

## Why another password manager

Most managers are a hosted encrypted blob plus a client. PhantomVault flips that:

| | PhantomVault | Typical hosted manager |
|---|---|---|
| Vault location | Your disk; sync is opt-in | Vendor server by default |
| Account required | No | Yes |
| Post-quantum key exchange | ML-KEM-768 + X25519 hybrid, fresh keys per save | Rare or roadmap-only |
| Audit trail | Local HMAC-chained log with a head anchor | Server-side, not user-verifiable |
| Duress | Independent decoy vault + canary credential | Usually none |
| Clipboard | Excluded from Win+V history and cloud clipboard at the OS level | Clear-later only |

The honest version: hosted managers are better at mobile, sharing, integrations and
third-party audit. Those are tracked as concrete work in
[`docs/COMPETITIVE_GAP_ANALYSIS.md`](docs/COMPETITIVE_GAP_ANALYSIS.md), not hand-waved.

---

## Features

**Vault**
- Logins, TOTP (RFC 6238), passkeys, cards, identities, secure notes, custom fields, attachments, folders, favorites, trash
- Per-item **reprompt** (master password again before revealing/editing a secret)
- Password **history** with restore, password **health** view, duplicate detection
- **Travel Mode** hides anything not marked travel-safe
- **Master password rotation** (rekey) with an old-password rollback snapshot
- Encrypted backups with rotation, scheduled backups, chain-verified audit export

**Unlock and session**
- Master password (Argon2id), Windows Hello (DPAPI-sealed token), App PIN (device-local)
- Extension PIN is **host-verified** with Argon2id and a persistent 30s→5min lockout — the verifier never reaches the browser
- Auto-lock on idle, on session lock, and on **proximity** (paired Bluetooth device leaves)
- Panic wipe path; decoy vault with its own password

**Browser extension**
- Autofill logins, cards, identities and TOTP from the popup, context menu or `Ctrl+Shift+L`
- **Edit-before-save**: the save prompt shows editable username/password fields in a closed shadow root
- "Never save for this site", idle lock pushed to every tab, hash-guarded clipboard clear
- Clipboard writes go through the native host so Windows can exclude them from history and cloud sync
- **Opt-in offline cache**: with the desktop app closed, matching logins still fill after Windows Hello **or** an extension PIN (separate opt-in) — logins only, read-only, 15-minute session, erased on decoy/disable/rekey

**Sync (optional, ciphertext only)**
- GitHub repository via API with a DPAPI-sealed token
- Peer-to-peer over LAN with challenge-response pairing
- Import/export: Bitwarden JSON, CSV, native `.pvx` (with previews, merge modes, undo)

---

## Quick start

### Install (binary release)

1. Download `PhantomVault-Setup-<version>.exe` and `SHA256SUMS.txt` from Releases.
2. Verify the SHA-256, then run the installer.
   Windows SmartScreen will warn because the installer is **not Authenticode-signed** —
   *More info → Run anyway* is expected, but only after the hash matches.
   Every `.exe`/`.zip` also ships a detached Ed25519 `<asset>.sig` that the in-app
   updater verifies against the key pinned in `src/release_pubkey.rs`.
3. Launch PhantomVault and create a master password. There is no recovery:
   the password derives the key. Back up the vault file and your recovery shards.

### Browser extension

The desktop app registers the native-messaging host. Then:

1. Chrome/Edge: `chrome://extensions` → Developer mode → **Load unpacked** →
   select `browser_extension/`.
2. Firefox: `about:debugging` → This Firefox → **Load Temporary Add-on** → pick
   `browser_extension/manifest.firefox.json`.
3. With the vault unlocked, the extension can query and fill. The bridge refuses
   requests while the vault is locked.

### Build from source

Prerequisites: Windows 10/11 x64, Rust stable (MSVC toolchain), Visual Studio
Build Tools with the C++ workload, Node.js 20+ (tests only), Inno Setup 6
(installer only).

```powershell
git clone https://github.com/zjhasan13/phantom_vault.git
cd phantom_vault

cargo build --release            # target\release\phantom_vault.exe
cargo clippy --all-targets       # lint gate
cargo test                       # 492 passed / 1 ignored + 4 pv_sign tests at 0.4.1
cargo test --manifest-path tools\pv-sign\Cargo.toml   # 4 signer tests

npm install                      # jsdom harness for the extension
npm test                         # 129/129 at 0.4.1

iscc installer.iss               # optional: installer-output\PhantomVault-Setup-*.exe

# Full signed release (tests, installer, zips, SBOM, hashes, .sig):
.\scripts\package_release.ps1 -SignKeyPath "$env:USERPROFILE\.phantomvault\release_signing.key"
```

Extension zips: `powershell -File browser_extension\build.ps1 -Browser all`.

> Keep vault files, `*.dpapi`, `access.log*` and `*.enc` out of git. `.gitignore`
> already covers them; the app never writes them into the repository on purpose.

---

## Security model

**Container.** The master password runs through Argon2id (64 MiB, t=3, p=4). The
derived key seals the payload with XChaCha20-Poly1305. A hybrid KEM step wraps the
same key with ML-KEM-768 and X25519, so the container resists a future
"harvest now, decrypt later" attack. Every save generates a fresh salt and a fresh
PQ keypair; nothing is reused across containers.

**In memory.** Secrets are held in page-locked buffers (`VirtualLock`) and zeroized
on drop. The master password lives in RAM only while the vault is unlocked.

**Local secrets.** Windows Hello tokens, the App PIN seal, the sync PAT and the
audit-log chain key are DPAPI-sealed to the current Windows account. They are not
portable and not backed up.

**Audit.** `access.log` is an HMAC-SHA256 chain over metadata only (event, time,
detail hash). A head anchor makes tail truncation detectable; `verify()` replays the
chain and fails closed if the key is unreadable.

**Bridge.** The native host pins the allowed extension origins and authenticates
each frame with a MAC. Bulk-exfiltration caps and a `verify_master` rate limiter bound
what a compromised page or extension can drain.

**Sync.** Only ciphertext leaves the machine. There is no PhantomVault-operated
relay, no telemetry, no analytics, and no analytics SDK in either binary.

---

## Known gaps and honest limits

These are real today. They are listed here so nobody discovers them the hard way.

- **Unsigned installer.** No Authenticode certificate yet (roadmap A8b). Windows
  SmartScreen warns on every fresh download. Verify `SHA256SUMS.txt`; releases also
  carry Ed25519 `<asset>.sig` files and a GitHub build-provenance attestation.
  Installs from before the 2026-10-31 key rotation need one manual reinstall
  (see `docs/RELEASE.md` §5).
- **No third-party security audit.** `docs/AUDIT.md` is an internal, reproducible
  review; it is not a substitute for an external audit.
- **Windows only.** No macOS, Linux or mobile client (A10).
- **Post-quantum is a hedge, not a second factor.** A correct password still opens
  the portable container. A device-bound "PQ-paranoid" profile is planned (A22).
- **A closed shadow root is a DOM boundary, not a keyboard boundary.** The page
  cannot read the corrected save-toast value from the DOM, but it can still observe
  key events, exactly as it observes the original login typing.
- **Backups, `.pvx` exports and printed shards keep the old password** after a
  rekey, by design. Rotate them separately.
- **Favicon lookup** currently asks DuckDuckGo, then Google, for site icons
  (known gap P1; same-origin fetch is planned).
- **P2P sync serves ciphertext without pairing** when no PIN is configured
  (A15). Keep it off on untrusted networks.
- **No KDBX import/export** (A13), no hardware-key unlock (A21), no serverless
  Send-style share (A20), no reproducible builds yet (T5).
- **Offline cache is opt-in and read-only** (A11). It weakens closed-app
  isolation: a same-user process can unseal the DPAPI key without the Hello
  prompt, and the snapshot refreshes only at unlock. Mutations and
  reprompt-armed items still require the desktop app.

The full register, with file/line evidence and acceptance tests, is
[`docs/COMPETITIVE_GAP_ANALYSIS.md`](docs/COMPETITIVE_GAP_ANALYSIS.md).

---

## Repository layout

```
src/
  crypto.rs            container format, Argon2id, XChaCha20, PQ hybrid
  storage.rs           atomic saves, backups, rekey
  models.rs            vault schema (logins, cards, notes, passkeys, ...)
  core/                memory, PQ, favicon, health
  security/            audit chain, decoy, canary, PINs, sharing, shredder
  sync/                GitHub sync, P2P LAN
  windows_native/      native host, clipboard, Hello, tray, IME guard
  importer/            Bitwarden JSON/CSV, .pvx
ui/                    Slint UI
browser_extension/     MV3 extension (content, background, popup, offscreen)
tests/js/              jsdom harnesses for the extension
docs/                  handoff, audit, gap analysis, release process
installer.iss          Inno Setup script
```

---

## Testing

```powershell
cargo test                                  # Rust unit + integration tests
cargo clippy --all-targets -- -D warnings   # lint
npm test                                    # background, content, domain, popup
```

Current baselines: **481 Rust tests passed / 1 ignored**, **124 JS tests passing**.
Tests are the acceptance criteria for every change; a red gate is never committed.

---

## Documentation

| Document | What it is |
|---|---|
| [`docs/HANDOFF.md`](docs/HANDOFF.md) | Session-by-session build state, decisions, invariants |
| [`docs/COMPETITIVE_GAP_ANALYSIS.md`](docs/COMPETITIVE_GAP_ANALYSIS.md) | Publishable gap register with evidence and exit tests |
| [`docs/AUDIT.md`](docs/AUDIT.md) | Internal audit findings and verification |
| [`docs/RELEASE.md`](docs/RELEASE.md) | Release checklist, SmartScreen wording, interop matrix |
| [`rules.md`](rules.md) | Architecture invariants and privacy rules |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability |

---

## Contributing

Issues and pull requests are welcome. Before opening a PR, run the gates above and
keep changes consistent with `rules.md` (architecture invariants are not
suggestions). Security reports must **not** go through public issues — see
[`SECURITY.md`](SECURITY.md).

No CLA, no copyright assignment.

---

## License

MIT — see [`LICENSE`](LICENSE). Third-party dependencies keep their own licenses;
`Cargo.lock` is the authoritative list.
