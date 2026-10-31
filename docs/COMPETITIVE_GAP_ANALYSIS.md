# PhantomVault vs Bitwarden / 1Password — Gap Analysis and Roadmap

Status: 2026-10-31. Scope: this repository at `main` (post `08dadd3` plus the
A3/A4 hardening pass), plus the
installed Bitwarden Edge bundle `2026.2.0_0` used only for UI/flow parity.
Every claim below cites a file and line in this tree. No claim is based on
marketing copy.

This file is the single source of truth for the public roadmap. Section 1a is
the publishable "what still has to be built" board; sections 4 and 10 hold the
evidence behind every row.

---

## 0. Method and honesty rules

- Source of truth is the code in this repository. Line numbers were read from
  the working tree at the time of writing; they will drift as code changes.
- Bitwarden comparison uses its public source plus the installed extension
  bundle for observable behavior (prompt buttons, defer/never options). It does
  not use a decompiler on any proprietary binary.
- A gap is only listed if a user-visible or security-relevant difference is
  demonstrable from code. "Maybe", "could", and "probably" are not evidence.
- Two claims from an earlier review were wrong. They are corrected in section 2
  instead of being quietly removed.

---

## 1. Verdict

PhantomVault already beats Bitwarden and 1Password on a small set of axes that
matter to a local-first user: no server-side vault, a machine-sealed GitHub
token, clipboard history/cloud exclusion, page-locked memory, a duress vault, a
canary credential, and a native host that refuses unknown origins.

It does **not** yet beat them "in every respect". The remaining gaps cluster in
four places:

1. **Trust surface** — docs shipped (A7: README, MIT LICENSE, SECURITY.md) and
   releases now carry checksums, an Ed25519 updater signature, an SBOM and a
   provenance attestation (A8a), but the installer is still not Authenticode-signed
   (A8b). A security product that cannot be verified end-to-end is not competitive,
   regardless of crypto.
2. **Account lifecycle** — no signed container revision (separate backup
   passphrase shipped as A6, master-password change as A5).
3. **Extension hardening** — fixed in this batch (proactive idle lock and
   "Never save for this site"); a few smaller items remain.
4. **Ecosystem** — no local API or CLI, so editor/CI/Terraform workflows that
   1Password supports have no equivalent.

Enterprise items (SOC 2, SSO/SCIM, team vaults, admin console) are deliberately
out of scope. They are a different product, not a missing feature.

---

## 1a. Action board — what still has to be built

This is the publishable task list. Every row traces to a gap in section 4 or
section 10. "Done when" is the acceptance test, not a vibe.

### Shipped

| ID | Task | Evidence | Done when |
|---|---|---|---|
| A0 | 2FA picker no longer opens on generic text fields | commit `72a220d`; `content.js` `isOtpField` / `otpSweepMayPrompt` | 83 tests pass, GitHub new-repo page stays quiet |
| A1 | Proactive idle lock pushes `PV_GATE_LOCKED` | `background.js:219-240`; 5 new tests | Locked state reaches every tab within one alarm tick |
| A2 | "Never save for this site" (content + background) | `content.js:2374-2378`, `background.js:594-611`; 4 new tests | Clicking Never silences save and update prompts for the registrable domain |
| A3 | Extension item editor: add, edit, delete, move to folder | `popup.js` `openItemEditor`; `background.js` `PV_ITEM_*`; native `create_login`/`update_login`/`delete_login`; 6 new tests | A login can be created and edited entirely from the popup, with reprompt enforced |
| A4 | Extension clipboard auto-clear | native `copy_secret` (`native_host.rs:3017`) with Windows exclusion formats; `pv_clip_hash` guard (`background.js:226-292`); `offscreen.js` SHA-256 check; popup `PV_COPY_SECRET`; 7 new tests | Copied secret is cleared after the configured timeout, even if the popup closes, and a newer user copy survives |
| A4b | `verify_master` brute-force limiter | `VERIFY_MASTER_PER_MIN = 5` (`native_host.rs:220`), `verify_master_backoff_ms`, shared failure counter with `create_login`/`update_login`/`delete_login` | 6th attempt inside a minute is refused; failures delay the reply exponentially |
| A5 | Master password change / rekey | `storage::rekey_vault_secret` (`storage.rs`); `rekey_input_error` + `on_change_master_password` (`main.rs`); Settings > Security card (`ui/appwindow.slint`) | Old password fails, new password unlocks, `.bak.1.enc` opens with the old password, 6 new tests |
| A9 | Edit-before-save in the save toast | `content.js` `credentialToast` (shared builder, closed shadow root), `toastField`, `saverToast`/`updateToast`; 6 new tests; harness `shadowOf` | Username and password can be corrected before the item is stored; empty pairs and already-known pairs never reach the host |
| A6 | Separate backup passphrase for `.pvx` | `exporter::BACKUP_V2_MAGIC` (`exporter.rs:384`) + `export_native_encrypted`; `Format::PhantomBackupV2` (`sniffer.rs:19`); `parse_import_any` (`mod.rs:211`); `backup_pass_error` (`main.rs:881`); modal + import fields (`ui/appwindow.slint:617,785,2331`); 4 new tests | A `PVBK1` export opens only with the backup passphrase; the master password never opens it, and legacy `.pvx` files still open with the master |
| A8a | Certificate-free release trust pipeline | `.github/workflows/release.yml`; `scripts/package_release.ps1`; `tools/pv-sign/src/main.rs`; `src/release_pubkey.rs`; `src/sync/updater.rs` `pick_asset`; `docs/RELEASE.md` §4-5 | Tag push builds + tests the installer, the portable updater exe and both zips, writes `SHA256SUMS.txt` + per-asset `.sha256`, Ed25519 `<asset>.sig`, a CycloneDX SBOM and a GitHub provenance attestation; a key mismatch or an installer-only release refuses to publish/update |
| A14 | Argon2id extension PIN + attempt backoff | `src/security/ext_pin.rs` (`PVPIN2`, salt, Argon2id 32 MiB/t=3/p=4, file-backed lockout); host `ext_pin_verify`/`ext_pin_status`; popup quick-PIN calls the host | The verifier never leaves the host; 5 wrong PINs start a 30s→5min lockout that survives restarts; a legacy SHA-256 record is refused |
| A17 | Same-origin favicon fetch | `src/core/favicon.rs` `icon_url`/`fetch_icon_bytes` (only `https://{domain}/favicon.ico`); DDG/Google constants deleted; extension harvest unchanged | With the network off, no favicon request leaves the machine; no third party sees vault domains |
| A11 | Encrypted offline extension cache | `src/security/offline_cache.rs`; `cache_get`/`cache_status` in `native_host.rs`; `background.js` `queryWithCache`/`PV_CACHE_*`; Settings toggles; `popup.js` offline unlock screen | The popup lists and fills matching logins with the desktop app closed, after Windows Hello **or** an opt-in extension PIN (Argon2id + lockout); writes/mutations and reprompt items stay blocked; snapshot is read-only with a 15-minute session and is erased on decoy/disable/rekey |
| A7 | README, LICENSE, SECURITY.md | `README.md`, `LICENSE` (MIT), `SECURITY.md` (GitHub private advisory, 90-day window, scope + known limits) | License present at root; private disclosure channel documented; supported versions and out-of-scope list published |

### P0 — parity blockers (do first)

| ID | Task | Gap | Effort | Done when |
|---|---|---|---|---|
| A8b | Authenticode signing | T2 | 1 wk | A downloaded installer verifies against the release checksum and the Authenticode signature |

### P1 — close the structural gaps

| ID | Task | Gap | Effort | Done when |
|---|---|---|---|---|
| A10 | Platform layer: macOS and Linux desktop | E14 | 6-10 wk | Vault unlock, autofill bridge, and sync build and pass tests on both |
| A12 | Shadow-DOM field scan and observer | E8 | 1 wk | A web-component login form gets a badge and fills |
| A13 | KDBX 4 import and export | E10 | 2-3 wk | A real `.kdbx` file round-trips without data loss |
| A15 | Mandatory P2P pairing (PAKE/QR) | S1, S2 | 2 wk | An unpaired LAN client gets 403 and cannot pull bytes; beacons carry only an ephemeral ID |
| A16 | Signed container revision (`rev` + `prev_hash`) | C3 | 1 wk | A replayed older blob is refused with a visible warning |
| A18 | Indistinguishable decoy provisioning | P2 | 1 wk | File listing and sizes do not reveal that a duress vault exists |
| A19 | Remote canary alert | P3 | 1 wk | Tripping the canary notifies a paired device or dead-drop |

### P2 — differentiators and polish

| ID | Task | Gap | Effort | Done when |
|---|---|---|---|---|
| A20 | Serverless Send-style expiring share | E13 | 2-3 wk | A link opens once, expires, and the relay never sees the key |
| A21 | Hardware security key unlock (FIDO2 hmac-secret) | E12 | 2-3 wk | Vault unlocks with key + PIN; password fallback still works |
| A22 | PQ-paranoid profile (device-bound decapsulation key) | C4 | 2-3 wk | Correct password alone cannot open the container |
| A23 | Loopback API + `pv` CLI | X1 | 3-4 wk | A script reads a secret only after explicit approval; tokens expire |
| A24 | Chunked, separately encrypted attachments | E11 | 2 wk | A 50 MB attachment saves without re-encrypting the vault |
| A25 | Desktop light/high-contrast theme | E15 | 1 wk | Palette switches without restarting; contrast passes WCAG AA |
| A26 | Desktop Bengali localization | E16 | 2 wk | Every visible string has a Bengali entry; no clipped layouts |
| A27 | Safari Web Extension wrapper | E17 | 2 wk | Fill and save work in Safari with the same native host |
| A28 | Email-breach lookup (opt-in, k-anonymity) | E18 | 1 wk | Breached account is flagged only after consent |
| A29 | ARM64 Windows build | T4 | 1 wk | Release matrix produces and tests an `aarch64` installer |

### Sequence

`A3-A9` in parallel where possible, then `A10` as the long pole, then `A11-A19`,
then `A20-A29`. Anything in P0 that is not shipped blocks the claim "better than
Bitwarden", because these are table stakes.

---

## 2. Corrections to the earlier review

| Earlier claim | Reality | Evidence |
|---|---|---|
| "Save prompt has no defer option." | Wrong. It has "✕ Not Now" plus a 30 s auto-dismiss. The real gap was the missing permanent opt-out and edit-before-save. | `browser_extension/content.js:2371-2373`, `:2385` |
| "Sync has no rollback protection at all." | Too broad. P2P adopt has an mtime monotonic gate and a replay guard; GitHub sync previews merges and keeps local on divergence. What is missing is a signed epoch, so a fresh device adopts whatever remote exists without an expected-revision check. | `src/sync/p2p_local.rs:475-499`, `src/main.rs:1151-1177`, `src/main.rs:7739-7800` |
| "Post-quantum layer is a second factor." | Wrong, and the code says so itself. The DK is wrapped under the Argon2id key, so a guessed master password never touches ML-KEM. The honest description is a harvest-now-decrypt-later hedge on the container key. | `src/crypto.rs:235-242` |

Corrections matter: an inflated claim in a security product is itself a
vulnerability in the product's credibility.

---

## 3. Where PhantomVault already leads

| Strength | Evidence | Why Bitwarden/1Password do not match |
|---|---|---|
| Vault never leaves the device unless the user configures sync | `src/storage.rs:139-160` writes only the local container; sync is explicit (`src/sync/github_sync.rs:90`) | Both default to a hosted encrypted blob |
| GitHub PAT sealed with DPAPI, zeroized after use, never logged | `src/sync/github_sync.rs:7,17,95-118` | Server-side tokens live in vendor infrastructure |
| Clipboard writes excluded from Win+V history and cloud clipboard | `src/windows_native/clipboard.rs` (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0`) | Bitwarden clears later; it cannot mark the entry non-historic |
| Page-locked secret memory | `src/core/memory.rs` (`VirtualLock`, zeroize on drop) | Not exposed or verifiable in either competitor |
| Duress vault with an independent container and password | `src/security/decoy.rs:3-6,17` | 1Password has Travel Mode; neither has a duress password |
| Canary credential that trips on vault access | `src/security/canary.rs:15-69` | No equivalent in either product |
| Native host pins allowed extension origins | `src/windows_native/native_host.rs:104-138` | Browser integrations in both rely on the browser's own isolation |
| Bulk-exfiltration caps on the extension bridge | `src/windows_native/native_host.rs:361,409-410,457` | Not applicable to a server API, but absent from competitor extension bridges |
| Honest threat model in code comments | `src/crypto.rs:235-242` | Marketing pages do not usually state their own limits |

These are real differentiators. They should be documented and tested, not just
present.

---

## 4. Gap register

Severity: **S1** = data loss or defeat of a core promise; **S2** = meaningful
security or parity gap; **S3** = polish or ecosystem.

### 4.1 Container and account lifecycle

| ID | Gap | Evidence | Impact | Fix | Sev |
|---|---|---|---|---|---|
| C1 | Master-password change/rekey — **shipped (A5)** | `src/storage.rs` `rekey_vault_secret` (old-password proof, round-trip proof, atomic swap, `.bak.1.enc` rollback); Settings card + `main.rs` `on_change_master_password` | A leaked master password can now be rotated without exporting and rebuilding the vault; `.pvx` backups and printed shards stay on the old password by design | Rekey flow: decrypt with old, re-encrypt with new salt + fresh KDF, atomic swap, keep one rollback snapshot, zeroize both | S1 |
| C2 | Backup `.pvx` shares the master password — **shipped (A6)** | `exporter::BACKUP_V2_MAGIC` (`exporter.rs:384`) tags new exports; `parse_import_any` (`mod.rs:211`) opens a `PVBK1` file only with the backup passphrase and routes untagged files to the legacy master-password path | A stolen backup no longer opens with the vault master password; exporting requires a separate 12+ character passphrase that differs from the master | Optional separate export passphrase, Argon2id with its own salt, explicit "cannot be opened with the vault password" warning | S1 |
| C3 | No signed container revision / epoch | Container layout has no revision field (`src/crypto.rs:230-233`); GitHub sync has no expected-revision check on fresh restore (`src/main.rs:1151-1177`) | A fresh device (or a restore after local wipe) silently adopts whatever blob the remote holds; a forced-push of an old commit restores stale data and resurrects entries deleted after that point | Add `rev` + `prev_hash` inside the AEAD payload, sign with the vault key; refuse a lower `rev` and surface a loud warning | S1 |
| C4 | Portable PQ profile is not a second factor | `src/crypto.rs:235-242`; portable form is the default save path (`src/storage.rs:149`) | "Post-quantum" is a hedge, not a factor. A guessed password yields the whole key chain | Opt-in "PQ-paranoid" profile: DPAPI/TPM-bound decapsulation key plus password (the old `V2Legacy` model). Keep portable for sync | S2 |
| C5 | Fixed Argon2id cost | `src/crypto.rs:51-56` (64 MiB, t=3, p=4) | Below current OWASP-recommended ceilings for a high-value vault; no per-device tuning | Version the KDF parameters in the header and raise defaults for new containers; keep legacy unlock path | S2 |

### 4.2 Sync

| ID | Gap | Evidence | Impact | Fix | Sev |
|---|---|---|---|---|---|
| S1 | P2P LAN is open when no PIN is set | `src/sync/p2p_local.rs:36-38`; `GET /p2p/pull` serves ciphertext unless a PIN exists (`:424-443`) | Anyone on the same Wi-Fi can pull the encrypted vault for offline cracking and fingerprint the device | Require pairing (QR/PAKE) before serving bytes; make PIN mandatory, not opt-in | S1 |
| S2 | P2P beacon leaks device identity | `src/sync/p2p_local.rs:262-277` broadcasts `name`, `version`, `head_sha`, `pin_required` every 5 s (`:21`) | Device name + version + vault head are visible to the whole LAN even before pairing | Broadcast an ephemeral random ID only; exchange name/version after pairing | S2 |
| S3 | GitHub pull adopts on first run without revision check | `src/main.rs:1151-1177` adopts any non-empty remote when local is empty | Stale/rolled-back remote becomes the new truth on a fresh device, with no warning | Tie to C3: require `rev` >= last known or explicit user confirmation | S2 |
| S4 | No device attribution on sync | Fixed generic commit message (`src/sync/github_sync.rs:6,20`) | Good for privacy, bad for incident review: cannot tell which device pushed what | Optional local audit log (already have `access_log`) mapped to device label | S3 |

### 4.3 Desktop privacy

| ID | Gap | Evidence | Impact | Fix | Sev |
|---|---|---|---|---|---|
| P1 | Favicon prefetch sent every domain to DuckDuckGo/Google — **shipped (A17)** | Old `src/core/favicon.rs:21-22,346-351`; now `icon_url` builds only `https://{domain}/favicon.ico` and the DDG/Google constants are deleted | The set of sites in the vault leaked to two third parties; contradicted "no cloud, no tracking" | Fetch `/favicon.ico` same-origin from the site itself, or ship a bundled icon set; delete the DDG/Google paths | S2 |
| P2 | Decoy vault is detectable by file presence | `src/security/decoy.rs:17,21-22` | `decoy_vault.enc` existing tells a coercer that duress mode is provisioned; file size/mtime differ | Always provision both containers, pad to a bucket, align mtimes; or hide the decoy inside the real container | S2 |
| P3 | Canary alert is local-only | `src/security/canary.rs:7,13,58-69` | An attacker with disk access deletes `canary_alert.log`; the owner never learns the vault was opened | Send a signed alert to a paired device over P2P and/or an optional dead-drop (private repo, email) | S2 |
| P4 | Extension PIN is a bare SHA-256 — **shipped (A14)** | `src/security/ext_pin.rs` now stores a salted Argon2id record (`PVPIN2`), verifies host-side (`ext_pin_verify`) and enforces a file-backed 30s→5min lockout; the verifier is never served | 10^4-10^8 offline candidates; a local attacker with the DPAPI blob on the same account can brute-force the UI gate | Argon2id/scrypt with a per-device salt, attempt counter with exponential backoff, Windows Hello fallback | S2 |
| P5 | Plaintext password crosses to the extension per query | `src/windows_native/native_host.rs:397`; capped at 25 (`:409-410`) | Same model as Bitwarden, so not a parity gap, but the blast radius is larger than necessary | Per-fill one-time token, single-item scope, 10 s TTL; keep `query` for the popup only | S3 |

### 4.4 Extension

| ID | Gap | Evidence | Impact | Fix | Status |
|---|---|---|---|---|---|
| E1 | Idle lock was lazy, evaluated only on the next message | `browser_extension/background.js:176-190` before this batch; popup polled every 15 s (`popup.js:941`) | Up to 15 s of the UI claiming "unlocked" after the deadline; background tabs kept a warm gate cache for 30 s | `chrome.alarms` tick + push `PV_GATE_LOCKED` to all tabs | **Shipped** |
| E2 | No "Never save for this site" | `content.js:2371-2378` had only Save / Not Now | Users who never want a login stored for a site were re-prompted forever | Third button, persisted registrable-domain list, background refusal | **Shipped** |
| E3 | Edit-before-save | `content.js:2352-2412` stored the page's username/password verbatim | A typo or a masked field was saved as-is; users had to open the desktop app to fix it | **Shipped (A9)** — `credentialToast` renders editable fields in a closed shadow root and re-classifies the corrected pair before the host call | — |
| E4 | No offline cache in the extension | `background.js:140-168` requires a live native port; popup shows Retry when the desktop is closed (`popup.js:57`) | Extension is useless when the desktop app is not running, unlike Bitwarden's local cache | Encrypted read-only cache with a short TTL, unlocked by a separate extension PIN | S2 |
| E5 | No settings UI for never-save list | This batch writes `never_save_domains` (`content.js:36,2344-2351`) but no popup surface exists | Users cannot review or undo a "Never" decision | Settings list with per-domain remove | S3 |

### 4.5 Trust and distribution

| ID | Gap | Evidence | Impact | Fix | Sev |
|---|---|---|---|---|---|
| T1 | No README, LICENSE, or SECURITY.md | **Shipped (A7)** — `README.md`, `LICENSE` (MIT), `SECURITY.md` | The files were absent at repo root: no audit trail for users, no legal reuse, no disclosure channel | Root docs are now present; `SECURITY.md` documents the GitHub private advisory channel, 90-day window, in/out of scope and the 0.4.0 limitations | — |
| T2 | Installer is not Authenticode-signed | `installer.iss` still has no `SignTool`/`SignedUninstaller` directive | SmartScreen warns; enterprise deployment blocked; Authenticode tamper evidence is absent | Authenticode sign the installer and the binary in CI (needs a certificate, A8b) | S1 |
| T3 | No release/provenance workflow — **shipped (A8a)** | `.github/workflows/release.yml` builds, tests, signs, hashes, SBOMs and attests on `v*` tags; `scripts/package_release.ps1` mirrors it locally | Users can now verify a release against source: checksums, detached Ed25519 signature, SBOM and GitHub provenance | Add a build workflow with checksums, SBOM, and a signed release attestation | S1 |
| T4 | No ARM64 build | No ARM64 target in the tree | Windows-on-ARM users (increasing share) run under emulation or not at all | Add `aarch64-pc-windows-msvc` to the release matrix | S2 |
| T5 | No reproducible-build documentation | Absent | Cannot independently verify binaries | Document toolchain pinning and hash comparison | S3 |

### 4.6 Ecosystem and accessibility

| ID | Gap | Evidence | Impact | Fix | Sev |
|---|---|---|---|---|---|
| X1 | No local API or CLI | Only loopback references are proxy tests (`src/sync/github_sync.rs:308-326`) | No editor/CI/Terraform integration, which 1Password supports via CLI/Connect | `127.0.0.1` scoped-token API + `pv get/run/inject`; per-request approval; no network bind | S2 |
| X2 | No light theme | No theme switch in `ui/appwindow.slint` | Dark-only UI is a usability and accessibility gap | Tokenized palette with light/dark/high-contrast | S3 |
| X3 | No Bengali localization | UI strings are English literals in `src/main.rs` and `ui/appwindow.slint` | The primary user base is Bengali-speaking; this is a product-fit gap | String table + `lang` setting, starting with Bengali and English | S3 |

---

## 5. Shipped in this batch

Two extension items were implemented and tested. No desktop behavior changed.

### 5.1 Proactive idle lock

- `chrome.alarms` permission added to both manifests.
- `IDLE_ALARM` armed at install, at startup, and at service-worker load
  (`background.js:219-240,558-560`).
- Every tick re-evaluates the existing session state; when the deadline has
  passed it writes `pv_locked_at` and broadcasts `PV_GATE_LOCKED` to every tab
  (`background.js:195-217,226-234`).
- Respects `lock_timeout_min: 0` (Never) and leaves unrelated alarms alone.
- Result: "locked" is a fact pushed to the UI, not a verdict the UI must poll
  for.

### 5.2 "Never save for this site"

- `never_save_domains` added to `DEFAULTS` (`content.js:36`) and persisted per
  registrable domain (`content.js:152,2340-2351`).
- Third button in the save banner (`content.js:2374-2378`) that stores the
  domain, dismisses the banner, and shows a confirmation toast.
- The prompt is suppressed on later visits, and the update prompt is suppressed
  too (`content.js:2353,2419`).
- Defense in depth: `PV_SAVE_LOGIN` is refused in the background for a listed
  domain, so a compromised or skewed content script cannot file the login
  anyway (`background.js:383-387,594-611`).
- Corrupted storage values degrade to "empty list" instead of breaking the
  sender.

### 5.3 Test coverage added

`npm test` now reports **118 passing, 0 failing** (was 95 before A3/A4).

New tests:

- Idle alarm is armed once with a 1-minute period.
- Broadcasts `PV_GATE_LOCKED` to all tabs past the timeout, and sets
  `pv_locked_at`.
- Stays silent while the session is fresh.
- Respects `lock_timeout_min: 0`.
- Ignores unrelated alarm names.
- `PV_SAVE_LOGIN` refused for a listed domain, zero native-host spawns.
- `PV_SAVE_LOGIN` still reaches the host for unlisted domains.
- Corrupted `never_save_domains` does not block saves.
- Banner exposes Never, stores the registrable domain, and dismisses.
- Later submits on the same site stay silent.
- A seeded list suppresses the prompt at load.
- Never also silences the password-update prompt.

Harness changes: `chrome.alarms` stub with loud-fail semantics
(`tests/js/harness.mjs`), and a seedable `chrome.storage.local` in the jsdom
harness (`tests/js/content-harness.mjs`).

### 5.4 Extension item editor (A3)

`popup.js` now owns the write path that previously required the desktop app:

- `openItemEditor` builds a modal with title, username, password, URL, folder,
  TOTP secret, and the reprompt toggle. Add, edit, and delete all run from it.
- Moving to a folder is the same update: the folder field is free text with a
  datalist of known folders; the host registers unknown names through
  `Vault::add_folder`.
- New bridge commands: `create_login`, `update_login` (partial), `delete_login`
  (soft delete to Trash). `list` now also returns `folders`.
- Reprompt is enforced in the native host, not just the UI. `verify_master`
  compares the typed password against the Hello-unsealed session passphrase in
  constant time, delays failed attempts, and mints a single-use 120 s token.
  Editing/deleting an armed item (or arming a new one) without that token
  fails with `master reprompt required`.
- The router refuses `PV_ITEM_*` and `PV_REPROMPT` when the sender carries a
  tab, so a page/content script cannot mutate the vault.
- Editing a TOTP item never sends the fetched live code back: a blank TOTP
  field omits the key, so the stored secret survives.

### 5.5 Clipboard auto-clear (A4)

- **Native first.** Every popup copy (password, 2FA code, generator) sends
  `PV_COPY_SECRET` to the host, which calls
  `windows_native::clipboard::copy_sensitive` (`native_host.rs:3017`). That is
  the only path that sets the Windows exclusion formats
  (`CFSTR_EXCLUDE...` / `CanIncludeInClipboardHistory = 0` /
  `CanUploadToCloudClipboard = 0`), so a secret never reaches Win+V or cloud
  clipboard. `text` is capped at 4096 bytes and `ttl_secs` is clamped to
  5-120 s.
- **Linger.** A successful copy stores `now + ttl + 2 s` in `clip_until`; the
  host's shutdown path waits for that deadline before exiting, so closing the
  browser does not leave a secret behind when the port dies.
- **The setting is honoured.** The popup sends its `clipboard_clear_sec` value
  with every copy. The host clamps 5-120 s; `0` ("Never") still sets the
  exclusion formats but drops the deadline, and the host is then free to exit
  immediately instead of lingering.
- **Web fallback.** Firefox, or a host that refuses the copy, falls back to
  `navigator.clipboard` plus the `pv_clip_clear` alarm. The popup states that
  the exclusion formats are unavailable on that path.
- **Hash-guarded clear.** The popup/content script writes a SHA-256 of the
  copied text into `pv_clip_hash` with the alarm deadline. On fire, the
  offscreen document (`offscreen.js:6-25`) or the content script
  (`content.js:3130-3145`) reads the clipboard, hashes it, and blanks only on
  an exact match. Copying something else mid-window therefore survives.
- The service worker mirrors the deadline in `chrome.storage.session`, so a
  worker restart re-arms instead of leaking until reboot. Locking the vault
  (`PV_GATE_LOCKED`) clears immediately through the same guarded path.
- The old content-script timer stays as a fast path with the same match check.

### 5.6 Test coverage added for A3/A4

- Popup source asserts create/update/delete routing, the reprompt-before-
  mutation order, the TOTP-secret guard, and clipboard arming on every copy.
- Router asserts popup-only item mutations, `verify_master` proxying,
  reprompt-token forwarding, timeout clamping, disarm, the offscreen clear,
  the content fallback, and unrelated-alarm silence.
- Hardening pass: native-first copy order, missing/short hash refusal,
  hash-mismatch skip, and `verify_master` backoff growth.

### 5.7 A4 hardening pass (this commit)

Three holes in `08dadd3` closed:

| Hole | Before | Now |
|---|---|---|
| No Win+V exclusion | popup used `navigator.clipboard.writeText`, which cannot set exclusion formats | host `copy_secret` -> `copy_sensitive`, with `ttl+2 s` linger |
| Unconditional clear | alarm blanked the clipboard with no ownership check, destroying a newer user copy | `pv_clip_hash` written at arm time; clear only on SHA-256 match |
| Unbounded `verify_master` | unlimited constant-time comparisons = offline master-password oracle | 5 attempts/minute plus exponential backoff, shared failure counter with the item mutations |
| Auto-clear setting ignored | native path always used the host default 30 s, and "Never" was clamped to 5 s | popup sends `clipboard_clear_sec` on every copy; host maps `0` to `CLIP_TTL_NEVER` (exclusion flags kept, deadline dropped) |

`cargo test` and `npm test` (118) are green after the change.

**Unverified on hardware (2026-10-31):** the seven manual clipboard checks were not run on a real machine. They remain open: (1) Win+V shows nothing after copy, (2) paste is empty after the TTL, (3) copying B survives A's alarm, (4) "Never" keeps the value past 2 minutes, (5) vault lock clears immediately, (6) closing the browser clears after the TTL, (7) closing the popup mid-window still clears on time.

### 5.8 Master password rotation (A5)

`storage::rekey_vault_secret` re-encrypts the whole container under the new
password. It refuses a wrong old password before any write, proves the new
container round-trips to the exact serialized bytes, proves the old password
cannot open the new container, then writes atomically after the normal backup
rotation. The previous container therefore survives as `.bak.1.enc`, sealed
with the **old** password — the one rollback snapshot the action board asked
for.

The Settings card (`ui/appwindow.slint`, "MASTER PASSWORD ROTATION") gates the
input (`rekey_input_error`: ≥8 characters, match, differs from current) and
uses a two-tap confirm. On success the app:

- re-seals `vault_hello.dpapi` with the new master (drops the token if DPAPI
  fails, so Hello fails closed instead of using a stale secret);
- removes the App PIN, because `pin.dpapi` seals the old master with
  `Argon2id(PIN)` and the PIN itself is not recoverable;
- resets `shards_nudged.pref`, so the recovery-shard nudge returns — printed
  shards still recover the old password;
- logs a metadata-only `rekey` event and pushes the new container if sync is
  configured.

Deliberate non-goals: `.pvx` exports, old backups and GitHub history keep the
old password; users are told so in the card and the success toast.

### 5.9 Edit-before-save (A9)

The save prompt used to carry the submitted username and password in a closure
only: the user could save the pair or dismiss it, never correct it. Both login
prompts now share one builder (`content.js` `credentialToast`), so a browser
that autofilled the wrong account or a stale password is fixable in place.

- The username (`type=text`) and password (`type=password`) inputs are
  pre-filled from the submit, `autocomplete=off`, `spellcheck=false`,
  `autocapitalize=off`, and carry no `name`, so the page's own form logic
  cannot claim them.
- The fields and buttons live in a **closed** shadow root. `host.shadowRoot` is
  `null` and `host.querySelector("input")` finds nothing, so a page script
  cannot read a corrected secret out of the DOM. The title/subtitle stay in
  light DOM (non-secret, and the page already knows the site).
- This is a DOM boundary, not a keyboard boundary: a hostile page can still
  observe key events that bubble out of the shadow tree, exactly as it observes
  the original typing. The doc claims nothing stronger.
- Save reads the edited values: username is trimmed, password is not (the
  native `save_login` path does not trim either). An empty either-way pair
  shows an inline error and never reaches the host.
- Before the host round-trip the corrected pair is re-classified with
  `existingSync(pageBase())` + `classifySubmitted`. A pair equal to a cached
  entry stops with "This login is already saved." and no `PV_SAVE_LOGIN`.
- Timer: 30 s as before, but typing/re-focusing re-arms it, and the timer
  refuses to close the prompt while one of the two fields has focus — an edit
  in progress is never eaten. Dismissing clears both input values.
- Escape inside a field means "keep editing"; Escape anywhere else dismisses.
  The old capture handler could not tell the difference.

`npm test` is **124/124** (6 new A9 tests). The harness gains `shadowOf()`, an
`attachShadow` spy that lives only in `tests/js/content-harness.mjs` — the
extension itself never publishes the root.

### 5.10 Trust documentation (A7)

Three root files, written from the code rather than from marketing:

- **`README.md`** — what it is, honest differentiators, container/KEM summary,
  build and test commands, repository map, doc index, and a "Known gaps and honest
  limits" section that lists the unsigned installer, the missing external audit,
  Windows-only scope, the PQ-is-not-a-second-factor caveat, the closed-shadow
  keyboard limit, old-password backups after a rekey, same-origin favicons, and
  the open P2P LAN default.
- **`LICENSE`** — MIT (Copyright (c) 2026 Zahidul Islam), matching the new
  `Cargo.toml` `license = "MIT"` field.
- **`SECURITY.md`** — GitHub private advisory as the only channel (no invented
  email or PGP key), supported-version table, 7/14-day response targets, 90-day
  coordinated disclosure, explicit in-scope and out-of-scope lists, the 0.4.1
  known limitations, and a safe-harbor statement.

Acceptance: `Test-Path README.md, LICENSE, SECURITY.md` is true for all three;
`Cargo.toml` declares the license; the advisory URL resolves for a repository
maintainer. No code changed in this batch.

### 5.11 Independent backup passphrase (A6)

`.pvx` exports used to be sealed with the vault master password, so a stolen
backup was only as strong as the password the user also types every day. New
exports are now sealed with a **separate backup passphrase**:

- A new export is `b"PVBK1"` (`exporter.rs:384`) followed by the unchanged
  portable envelope (`Argon2id` + ML-KEM + XChaCha20-Poly1305). `crypto.rs` is
  untouched — only the key input differs, and every export still draws a fresh
  salt (asserted by `a6_backup_export_uses_a_fresh_salt_every_time`).
- The export gate (`backup_pass_error`, `main.rs:881`) requires ≥12 characters,
  a matching confirmation, and a value that **differs from the master
  password**. Reusing the master is refused rather than warned about, because a
  backup that opens with the master would silently restore the old behaviour.
  The master reprompt stays: it proves the user is present before a file leaves
  the machine.
- The importer (`mod.rs:211`) checks the `PVBK1` tag first
  (`sniffer.rs:117`). A tagged file is decrypted **only** with the backup field —
  the master password is never tried — and a missing or wrong passphrase fails
  with a message that says so. Untagged files take the explicit legacy path and
  still open with the master password, so pre-A6 backups keep importing.
- UI: the reprompt modal grows two password fields for encrypted export
  (`ui/appwindow.slint:2331`); the Import screen has an optional "Backup
  passphrase — only for .pvx backups" field (`ui/appwindow.slint:1543`) that is
  cleared once staging succeeds. Both export fields are cleared on the event
  loop the moment Rust owns the secret.

Tests: `a6_backup_opens_with_passphrase_but_never_with_the_master`,
`a6_backup_export_uses_a_fresh_salt_every_time`,
`a6_new_backup_refuses_the_master_and_legacy_keeps_it`, and the gate test
`a6_backup_pass_gate_rejects_empty_short_mismatch_and_master`. Baselines:
`cargo test` **485 passed / 1 ignored**; `npm test` **124/124**.

Honest limits: the passphrase is only as good as what the user types, there is
no recovery if it is lost, and a backup file still carries its own salt and
container — losing the file loses the data regardless of the passphrase.

### 5.12 Certificate-free release pipeline (A8a)

The trust gap was not "no CI" but "the verification half existed with nothing
producing its inputs": `updater.rs` has always refused assets without a valid
`<asset>.sig` and a checksum, while every published release shipped neither.
v0.4.0's assets prove the point — setup exe + two zips, no `.sig`, no sums — so
the in-app updater fails closed today.

A8a closes the loop without an Authenticode certificate:

- **Workflow** `.github/workflows/release.yml` runs on `v*` tags (or a manual
  dispatch that refuses an existing release). It verifies the tag equals the
  `Cargo.toml` version, refuses to run without `PV_SIGNING_KEY`, then calls one
  packaging implementation so CI and local builds cannot drift.
- **Packaging** `scripts/package_release.ps1` runs `cargo test` + `npm test`,
  builds the release binary, compiles `installer.iss`, zips both extension
  builds, and writes a CycloneDX SBOM from cargo metadata. It hashes every
  distributable as `<asset>.sha256` (bare hash, the updater's preferred form)
  and `SHA256SUMS.txt` (GNU format, humans and the release page).
- **Signing** `tools/pv-sign/src/main.rs` (its own small crate) writes a raw
  64-byte Ed25519 signature per
  `.exe`/`.zip`. It refuses any key whose public half differs from
  `src/release_pubkey.rs`, so a wrong secret fails before upload. The pinned
  key moved to `src/release_pubkey.rs` so the signer and verifier share one
  source of truth.
- **Updater asset split.** The updater swaps a portable binary over the live
  exe, so a release ships both `PhantomVault-Setup-<ver>.exe` (humans) and
  `PhantomVault-<ver>-windows-x64.exe` (updater). `pick_asset` now skips
  `setup`/`installer` names and refuses an installer-only release instead of
  replacing the app with the installer — the old behaviour would have bricked
  the next launch.
- **Provenance** `actions/attest-build-provenance` attests the exe and zips;
  users verify with `gh attestation verify <file> --repo zjhasan13/phantom_vault`.
- **No UPX.** The old "sub-8MB" target came from the v0.2.0 6.7 MB build; at
  0.4.0 the exe was 19.55 MB and the installer 8.54 MB (`docs/HANDOFF.md`);
  the published 0.4.1 exe is 19.77 MB and the installer 8.98 MB. Compressing
  an unsigned binary raises AV false positives, so the checklist records the
  real size instead of asserting an unmet target.

Key custody: the 2026-10-31 rotation generated a new key because the original
pinned key had no available private half. The seed lives only in the Actions
secret `PV_SIGNING_KEY` and an offline backup under the maintainer's profile;
it is never printed by `pv_sign keygen`. Consequence, stated in the README and
`SECURITY.md`: installs built before that date cannot verify new signatures and
need one manual reinstall.

Tests: `pv-sign` covers sign/verify round-trip, tamper and wrong-key rejection,
hex/raw key parsing, and the pinned array/hex agreement; the updater test
`asset_pick_skips_installer_and_prefers_update_exe` pins the installer-refusal
rule. Baselines after A8a:
`cargo test` **485 passed / 1 ignored + 4 pv_sign tests**; `npm test` **124/124**.

Honest limits: Authenticode is still missing (A8b), so SmartScreen still warns;
the provenance attestation covers the uploaded bytes, not a reproducible build;
and losing the offline key means another rotation plus one manual reinstall.

### 5.13 Encrypted offline extension cache (A11)

Until now the bridge was deliberately closed-app-blind: the heartbeat stops and
the Hello token is deleted on exit (`main.rs:56-83`), so a leftover token could
never serve (`native_host.rs` P1 gate). A11 adds a **separate, opt-in,
read-only** path rather than weakening that gate for the live vault:

- **Opt-in toggle** (Settings > Security) builds a **logins-only** snapshot at
  unlock. Trash and non-login kinds never enter it. It is capped at 1000 rows.
- **At rest:** the snapshot is XChaCha20-Poly1305 (`PVOC1` + nonce + tag) under
  a fresh 32-byte key; the key is DPAPI-sealed for the current Windows user.
  No master password is stored.
- **Read:** the extension asks `cache_get`; the native host prompts **Windows
  Hello** before unsealing the key and returns the snapshot. The host answers
  this one command while the desktop app is closed; every other command still
  requires a live heartbeat.
- **In the browser:** decrypted entries live only in the service-worker's
  memory, never `chrome.storage`. A 15-minute TTL bounds the session; a lock
  verdict (`PV_GATE_LOCKED`) clears it immediately; a service-worker restart
  loses it and the next popup prompts Hello again.
- **Read-only by construction:** mutations still go to the host, which is not
  reachable when the app is closed; the popup renders a visible offline banner;
  reprompt-armed items are refused in both the popup and content-script fill
  paths because master presence cannot be proven offline.
- **Hygiene:** a decoy unlock **erases** the cache (a coerced session must not
  leave the real snapshot readable), a rekey refreshes it, and disabling the
  toggle deletes both files.

Tests: four Rust tests cover Trash exclusion, the full-field round-trip,
AEAD tamper/wrong-key rejection and the DPAPI on-disk refresh/clear cycle; four
JS tests cover the closed-app fallback, TTL reuse (one Hello prompt), lock
clearing and the empty-query guard. Baselines after A11: `cargo test`
**489 passed / 1 ignored + 4 pv_sign tests**; `npm test` **128/128**.

Honest limits: Windows Hello here is a **presence prompt**, not a key factor —
a same-user process can call DPAPI and decrypt the cache without it. That is
the price of reading with the app closed; the feature is opt-in, read-only and
logins-only. The snapshot is refreshed at unlock, so edits made later are
visible offline only after the next unlock.

### 5.14 Argon2id extension PIN (A14)

The old extension PIN was a bare SHA-256 of a 4–8 digit PIN, and the hash was
served over the bridge so the popup could compare it (`ext_pin.rs`). Both were
wrong: 10k candidates are reversible in seconds, and serving the verifier hands
the attacker the comparison target.

A14 replaces the record with `PVPIN2|salt|m|t|p|hash`:

- 16-byte random salt, Argon2id (32 MiB, t=3, p=4), 32-byte output, all
  DPAPI-sealed. Parameters live in the record so a future cost bump can still
  verify old PINs.
- **Verification moved into the host** (`ext_pin_verify`); `ext_pin_status`
  returns only `set: true/false`. The extension never sees the verifier.
- **Lockout** is file-backed (`ext_pin_backoff`) and survives host/app
  restarts: failures 0–4 are free, 5 → 30 s, 6 → 60 s, 7 → 120 s, 8+ → 300 s.
  `set`/success resets the counter; `clear` removes both files.
- **Migration:** a legacy 64-hex SHA-256 record is refused with
  "re-set the PIN in Settings" — it can never silently gate anything again.
- Popup quick-PIN sends the PIN to the host and displays the retry delay on a
  lockout; no local SHA-256 code remains.

Tests: set/verify/clear, digit/length validation, legacy-record refusal,
lockout persistence across calls, and corrupt-record fail-closed. Baselines:
`cargo test` **491 passed / 1 ignored + 4 pv_sign tests**; `npm test`
**128/128**.

Honest limit: a 4-digit PIN is still only 10k candidates. Argon2id makes an
offline sweep expensive and the lockout stops online guessing, but a same-user
process can read the DPAPI record and grind it at local CPU cost. Treat the PIN
as shoulder-surfing protection, not vault-grade authentication — and prefer
6–8 digits.

### 5.15 Dual-gate offline cache: Hello or PIN (A11b)

The cache now has **two independent gates over the same DPAPI-sealed key** — no
second key slot, no duplicated ciphertext:

- `cache_status` is prompt-free: `{enabled, pin_set, pin_allowed}` so the popup
  can offer the right methods without flashing a Hello dialog.
- `cache_get {method:"hello"}` is the original Windows Hello path.
- `cache_get {method:"pin", pin}` verifies through the A14 Argon2id record and
  the same persistent 30 s→5 min lockout. It is refused unless the user has set
  **and** explicitly allowed the PIN fallback (`offline_cache_pin.pref`).
- The popup's offline screen offers **Use Windows Hello** plus a PIN field only
  when the fallback is allowed. Background `PV_QUERY` never prompts on its own —
  it serves a warm 15-minute snapshot and otherwise returns "offline cache is
  locked"; a service-worker restart re-asks.
- Setting/replacing/removing the extension PIN revokes the PIN fallback
  (re-consent required); disabling the cache erases the consent marker with the
  rest of the files; decoy unlock still erases everything.

Tests: the Rust PIN-gate test proves the same snapshot opens with the PIN,
wrong PINs fail, the consent marker is required, and removing the PIN closes the
path. Five JS tests cover prompt-free status, PIN unlock, warm-cache queries,
lock clearing and the empty-query guard. Baselines: `cargo test` **492 passed /
1 ignored + 4 pv_sign tests**; `npm test` **129/129**.

Honest limit: the cache is now only as strong as **the weaker gate**. A 4-digit
PIN is 10k candidates; enabling it is a deliberate convenience trade-off, shown
as such in Settings. Leave it OFF unless the offline convenience is worth more
than the PIN's entropy.

### 5.16 Same-origin favicons (A17)

The favicon prefetch used to ask `icons.duckduckgo.com`, then Google, for every
domain in the vault. That leaked the user's site set to two third parties — a
direct contradiction of "no cloud, no tracking" (P1).

A17 deletes both paths. `favicon.rs` now builds exactly one URL:

```
https://{domain}/favicon.ico
```

- The extension's existing harvest path (`PV_FAVICON_HARVEST`, page-declared
  `<link rel="icon">` with host permissions) still wins when a page provides a
  better icon; those bytes are validated and written to the same disk cache.
- Disk cache → custom user icon → same-origin fetch → letter circle. Repeat
  views never touch the network.
- The toggle, offline kill-switch and per-call `can_net` closure are unchanged;
  with the network off, no request is attempted.

Test: `icon_url_is_same_origin_only` pins the URL to the site's own host and
asserts the third-party names cannot reappear. Baselines: `cargo test` **493
passed / 1 ignored + 4 pv_sign tests**; `npm test` **129/129**.

Honest limits: the site itself sees a request for its own icon (unavoidable if
you want its icon), and a site may redirect `/favicon.ico` to a CDN it controls.
There is still no bundled icon set; the letter circle is the offline fallback.

---

## 6. Roadmap

Ordered by risk reduction per unit of work. Each phase has an exit test.

### Phase 1 — Trust (1 week)

1. **DONE (A7)** — `README.md`, `LICENSE` (MIT), `SECURITY.md` with the GitHub
   private advisory channel and a 90-day disclosure window.
2. Authenticode signing in `installer.iss` + CI (**A8b** — needs a certificate).
3. **DONE (A8a)** — release workflow: checksums, Ed25519 updater signatures,
   SBOM, provenance attestation, one packaging implementation for CI + local.
4. Exit test: a fresh clone can verify a downloaded installer's hash and
   signature against the release page. Hash + Ed25519 + attestation: **yes**
   after A8a; Authenticode: **still pending** (A8b).

### Phase 2 — Account lifecycle (2-3 weeks)

1. **DONE (A5)** — master-password change/rekey with atomic swap and a
   one-step rollback snapshot (C1).
2. **DONE (A6)** — separate backup passphrase for `.pvx` (C2): `PVBK1` tag,
   independent passphrase, legacy master-password path preserved.
3. Header version bump carrying `rev` + `prev_hash` (C3).
4. Exit test: rotate the password, unlock with the new one, verify the old one
   fails, and verify an older `.pvx` still imports.

### Phase 3 — Sync integrity and pairing (2-3 weeks)

1. P2P pairing mandatory, PAKE-based, ephemeral beacon IDs (S1, S2).
2. Refuse a lower `rev` on restore; warn instead of silently adopting (S3).
3. Exit test: an unpaired LAN client gets 403 and cannot pull bytes; a replayed
   older blob is refused with a visible warning.

### Phase 4 — Privacy defaults (1 week)

1. **DONE (A17)** — same-origin favicon fetch; the DDG/Google paths are deleted.
   A bundled icon set can come later without changing the privacy posture.
2. Indistinguishable decoy provisioning (P2).
3. Canary alert over P2P plus an optional dead-drop (P3).
4. Exit test: with the network disabled, no favicon request leaves the machine;
   a decoy-provisioned profile is not distinguishable by file listing.

### Phase 5 — Extension completion (1-2 weeks)

1. **DONE (A9)** — edit-before-save in the toast (E3).
2. Settings UI for the never-save list (E5).
3. **DONE (A14)** — Argon2id extension PIN with host-side verification and a
   persistent 30s→5min lockout (P4).
4. **DONE (A11)** — opt-in, Hello-gated **read-only** offline cache (E9).
   The roadmap's "separate PIN" idea was replaced by Windows Hello presence +
   DPAPI, because a second PIN would be one more secret to lose.
5. Exit test: save a login with an edited username from the toast; remove a
   never-save domain from settings and see the prompt return.

### Phase 6 — PQ-paranoid profile (2-3 weeks)

1. Opt-in device-bound decapsulation key (DPAPI/TPM) in addition to the
   password (C4).
2. Keep the portable profile for sync; label both honestly in the UI.
3. Exit test: with the device key removed, the paranoid container cannot be
   opened even with the correct password.

### Phase 7 — Ecosystem (3-4 weeks)

1. Loopback API with scoped tokens and per-request approval (X1).
2. `pv` CLI: `get`, `run`, `inject`, `status`.
3. Exit test: a script retrieves a secret only after an explicit approval
   prompt, and the token cannot be replayed after expiry.

### Phase 8 — Polish (ongoing)

1. Light/high-contrast theme (X2).
2. Bengali localization (X3).
3. ARM64 build (T4).
4. Reproducible-build documentation (T5).

---

## 7. Scorecard

Scores are relative to the best of Bitwarden and 1Password. "Parity" means the
user cannot tell the difference in normal use; "lead" means a capability the
competitors do not ship.

| Axis | PhantomVault | Bitwarden | 1Password | Verdict |
|---|---|---|---|---|
| Server-side vault exposure | None by default | Hosted blob | Hosted blob | **Lead** |
| Client crypto transparency | Source + in-code threat notes | Source | Closed | **Lead** |
| Post-quantum story | Hybrid hedge, documented limit | None public | None public | Lead on mechanism, parity on honesty |
| Sync integrity | SHA CAS + mtime/tombstones, no signed epoch | Server-side versioning | Server-side versioning | Behind |
| P2P / offline sync | Yes, open by default | No | No | **Lead**, but needs pairing |
| Duress / coercion | Decoy vault | None | Travel Mode (partial) | **Lead**, needs deniability |
| Canary credential | Yes, local-only | None | None | **Lead**, needs remote alert |
| Master-password rotation | Shipped (A5: old-password proof, atomic swap, `.bak.1.enc`) | Yes | Yes | Parity |
| Backup passphrase | Yes (A6: `PVBK1`, independent of the master) | N/A (server) | Yes (Emergency Kit) | Parity |
| Extension idle lock | Proactive (this batch) | Proactive | Proactive | Parity |
| Never-save for site | Yes (this batch) | Yes | Yes | Parity |
| Edit-before-save | Yes (A9, closed shadow fields) | Yes | Yes | Parity |
| Offline extension cache | Yes (A11/A11b: opt-in read-only, Hello or PIN, 15 min) | Yes | Yes | Parity |
| Local API / CLI | Missing | CLI (open source) | CLI + Connect | Behind |
| Installer signing / provenance | Provenance shipped (A8a); Authenticode still missing (A8b) | Signed | Signed | Behind on Authenticode, parity on provenance |
| Audit / disclosure docs | Shipped (A7: README, MIT LICENSE, SECURITY.md) | Yes | Yes | Parity |
| Light theme / Bengali | Missing | Theme yes, Bengali partial | Theme yes, Bengali no | Behind on fit |

Net: strong differentiation on privacy architecture, behind on lifecycle,
distribution trust, and ecosystem. The fastest route to "better in every
respect that matters" is Phase 1 + Phase 2, not more crypto features.

---

## 8. Out of scope

- SOC 2 / ISO 27001 certification.
- SSO, SCIM, team vaults, admin console, audit export for enterprises.
- Hosted service, billing, or account recovery.
- Mobile clients.

These require a company and an operations team. Claiming them without the
paperwork would repeat the "PQ second factor" mistake at a larger scale.

---

## 9. How to verify this document

```powershell
# Extension test suite (124 tests)
npm test

# Idle-lock and never-save code
Select-String -Path browser_extension\background.js -Pattern 'IDLE_ALARM|neverSaveHit|never save for this site'
Select-String -Path browser_extension\content.js -Pattern 'never_save_domains|Never'

# A3 item editor + host reprompt gate
Select-String -Path browser_extension\popup.js -Pattern 'openItemEditor|PV_ITEM_CREATE|PV_REPROMPT'
Select-String -Path src\windows_native\native_host.rs -Pattern 'create_login|update_login|delete_login|verify_master|reprompt_ok'

# A4 clipboard auto-clear (native copy, hash-guarded clear, host linger)
Select-String -Path src\windows_native\native_host.rs -Pattern 'copy_secret|clip_until|VERIFY_MASTER_PER_MIN'
Select-String -Path browser_extension\background.js -Pattern 'pv_clip_hash|PV_COPY_SECRET|pv_clip_clear'
Select-String -Path browser_extension\offscreen.js -Pattern 'sha256Hex|skipped'

# A5 master-password rekey
Select-String -Path src\storage.rs -Pattern 'rekey_vault_secret'
Select-String -Path src\main.rs -Pattern 'change_master_password|rekey_input_error'
cargo test rekey

# A8a release pipeline (checksums, Ed25519 signatures, SBOM, provenance)
Test-Path .github\workflows\release.yml, scripts\package_release.ps1, tools\pv-sign\src\main.rs
Select-String -Path src\release_pubkey.rs -Pattern 'UPDATER_PUBLIC_KEY'
Select-String -Path src\sync\updater.rs -Pattern 'check_signature|release_pubkey'
Select-String -Path .github\workflows\release.yml -Pattern 'attest-build-provenance|package_release'
cargo test --manifest-path tools\pv-sign\Cargo.toml
cargo run --manifest-path tools\pv-sign\Cargo.toml -- verify installer-output\PhantomVault-Setup-0.4.1.exe

# A11 offline extension cache (opt-in, Hello-gated, read-only)
Select-String -Path src\security\offline_cache.rs -Pattern 'CACHE_MAGIC|handle_cache_get|SESSION_TTL_SECS'
Select-String -Path src\windows_native\native_host.rs -Pattern 'cache_get|cache_status'
Select-String -Path browser_extension\background.js -Pattern 'queryWithCache|PV_CACHE_STATUS|PV_CACHE_PIN|OFFLINE_TTL_SECS'
Select-String -Path browser_extension\popup.js -Pattern 'offline_banner|PV_CACHE_PIN|offline_unlock'
cargo test offline_cache
node --test tests/js/background.test.mjs

# A14 Argon2id extension PIN + lockout (host-side verify)
Select-String -Path src\security\ext_pin.rs -Pattern 'PVPIN2|Argon2id|delay_for_failures'
Select-String -Path src\windows_native\native_host.rs -Pattern 'ext_pin_verify|ext_pin_status'
Select-String -Path browser_extension\popup.js -Pattern 'PV_EXT_PIN_VERIFY|quick_pin_wait'
cargo test ext_pin

# A9 edit-before-save (closed shadow fields, re-classify, empty guard)
Select-String -Path browser_extension\content.js -Pattern 'credentialToast|attachShadow\(\{ mode: "closed" \}\)|already saved'
node --test tests/js/content.test.mjs

# A6 separate backup passphrase (PVBK1 tag, gate, legacy path)
Select-String -Path src\importer\exporter.rs -Pattern 'BACKUP_V2_MAGIC|export_native_encrypted'
Select-String -Path src\importer\sniffer.rs -Pattern 'PhantomBackupV2'
Select-String -Path src\importer\mod.rs -Pattern 'fn parse_import_any|PhantomBackupV2'
Select-String -Path src\main.rs -Pattern 'fn backup_pass_error|on_reprompt_confirm'
Select-String -Path ui\appwindow.slint -Pattern 'rp_backup_pass|import_backup_pass'
cargo test a6

# Container layout and the honest PQ note
Select-String -Path src\crypto.rs -Pattern 'V2_PORTABLE_MAGIC|H5 NOTE' -Context 0,6

# P2P open-LAN default and beacon fields
Select-String -Path src\sync\p2p_local.rs -Pattern 'when none exists|head_sha|pin_required' -Context 0,3

# Favicons are same-origin only (no DDG/Google; the letter fallback stays)
Select-String -Path src\core\favicon.rs -Pattern 'fn icon_url|favicon\.ico|unwrap_or\(true\)'
Select-String -Path src\core\favicon.rs -Pattern 'DDG_ICON|GOOGLE_S2'   # must be empty
cargo test icon_url_is_same_origin_only

# Trust docs (A7) — all three must exist at root
Test-Path README.md, LICENSE, SECURITY.md
Select-String -Path SECURITY.md -Pattern 'security/advisories/new|90-day'
Select-String -Path Cargo.toml -Pattern '^license'
Select-String -Path installer.iss -Pattern 'SignTool'
```

---

## 10. Addendum 2026-10-30 � second pass, app + extension

A deeper pass over the desktop and extension surfaces found gaps that the first
pass missed, and corrected three assumptions.

### 10.1 Corrections

| Earlier assumption | Reality | Evidence |
|---|---|---|
| Passkeys are metadata-only | Wrong. Full WebAuthn relay exists: page hook, background relay, native attest/assert | `browser_extension/hook.js:132-187`, `content.js:2888-2923`, `native_host.rs:660-830` |
| Import coverage is thin | Wrong. 12 sniffed formats, including Bitwarden, 1Password, KeePass, Proton, Chrome, Safari, LastPass, generic CSV | `src/importer/sniffer.rs:6-37` |
| Updates are unsigned | Partly wrong. The updater requires a detached Ed25519 signature plus SHA-256 before staging; only the installer itself lacks Authenticode | `src/sync/updater.rs:9-38,144-160` (signer + CI added in A8a) |

### 10.2 New gaps

| ID | Gap | Evidence | Impact | Fix | Sev |
|---|---|---|---|---|---|
| E6 | Extension cannot add, edit, or delete items | ~~No write command in `browser_extension/popup.js`~~ — shipped in 5.4 (`openItemEditor`, `create_login`/`update_login`/`delete_login`) | Every change used to require the desktop app; Bitwarden's popup is a full editor | Add item editor + `update_item`/`delete_item` bridge commands with origin and reprompt checks | S1 |
| E7 | Extension copy never clears the clipboard | ~~`popup.js:1504-1507` writes and stops~~ - shipped: native `copy_secret` + `pv_clip_hash` guard (5.5, 5.7) | A copied password used to stay in the OS clipboard indefinitely, and reached Win+V | Reuse the desktop clear timer via the bridge, or a popup-side 30 s timer with best-effort clear | **Shipped** |
| E8 | No shadow-DOM autofill | `content.js:450` is the extension's own UI shadow root; no traversal of page shadow roots | Web-component login forms (increasing share of modern sites) never get badges or fill | Traverse open shadow roots in field scan and observer; skip closed roots | S2 |
| E9 | No offline extension cache — **shipped (A11)** | `background.js` needs a live native port; popup shows Retry (`popup.js:57`) | Extension is dead when the desktop app is closed | Encrypted read-only cache, unlocked by Hello-backed token, short TTL | S2 |
| E10 | No KDBX (binary) import or export | KeePass support is XML/CSV only (`src/importer/keepass.rs:1-5`); exporters are CSV/Bitwarden JSON/native (`exporter.rs:83-412`) | Users cannot move to or from KeePass's real container; lock-in both ways | Read/write KDBX 4 with Argon2 + AES-KDF; keep XML path | S2 |
| E11 | Attachments are 5 MB and inline in the vault blob | `src/models.rs:82`; attachments live on items (`models.rs:73-79,265`) | Any file save re-encrypts the whole vault and bloats sync; Bitwarden allows large separate attachments | Store attachments as separately encrypted chunks with their own keys and a size budget | S2 |
| E12 | No hardware security key unlock | Only Windows Hello + TOTP gate exist; no FIDO2/HMAC-secret path | Bitwarden supports FIDO2 2FA; KeePassXC supports hardware-key unlock. A local vault with a hardware factor would be a differentiator | FIDO2 hmac-secret or CTAP2 key wrapping the vault key; fallback to password | S2 |
| E13 | No secure sharing / expiring link | No share/send model or route in `src/models.rs` or `src/main.rs` | Bitwarden Send is a core workflow; users fall back to chat apps | Serverless Send: encrypted blob + key in URL fragment, GitHub/P2P relay, TTL and one-view | S2 |
| E14 | Desktop is Windows-only | `#![windows_subsystem]` (`src/main.rs:3`), 13 Windows-gated sites, DPAPI/WinRT dependencies | No macOS/Linux, and no mobile at all; Bitwarden ships all of them | Split platform layer behind a trait: DPAPI/Hello on Windows, Keychain/Secure Enclave on macOS, libsecret on Linux | S1 |
| E15 | Desktop has no light theme | Palette is hard-coded dark (`ui/appwindow.slint:110-124`) | Accessibility and daylight use; extension already supports `prefers-color-scheme` (`popup.html:6-17`) | Theme tokens with light/high-contrast variants | S3 |
| E16 | Desktop is English-only | No i18n layer in `src/main.rs`; only the extension has BN/EN (`popup.js:2,19,92-210`) | Bengali users get a localized popup and an English desktop | String table + `lang` setting; reuse the extension glossary | S2 |
| E17 | No Safari extension | Only Chromium and Firefox manifests exist | Safari users cannot use the product | Safari Web Extension wrapper around the same JS | S3 |
| E18 | Vault health covers passwords only | `security/breach_check.rs` checks password hashes via HIBP ranges; no email-breach lookup | Bitwarden/1Password watchtower also flags breached accounts and weak 2FA coverage | Optional email-breach check with k-anonymity and explicit consent | S3 |

### 10.3 What is genuinely ahead (keep and market)

- Full passkey create/get relay, not just storage.
- 12-format importer with fuzzy CSV fallback.
- Ed25519-signed update assets plus SHA-256.
- Shamir recovery shares and GitHub-relay emergency access.
- Built-in Addy/SimpleLogin alias creation with a DPAPI-sealed token.
- Breach check, reuse/weak/stale audit, and bulk rotation.
- Bengali diceware wordlist and a BN/EN extension UI.

### 10.4 Revised priority for "beat both"

1. **E6 + E7** � extension write access and clipboard auto-clear. Without these
   the extension is a viewer, not a manager. 1-2 weeks.
2. **E14** � platform layer. Windows-only caps the addressable market and is the
   single largest structural gap. 6-10 weeks for macOS/Linux; mobile after.
3. **C1 + C2** — rekey and separate backup passphrase (**both done as A5 + A6**).
4. **E8 + E9 + E10** � shadow DOM, offline cache, KDBX. 3 weeks.
5. **T1-T3** - README/LICENSE/SECURITY (**T1 done as A7**), Authenticode (**T2, A8b — needs a certificate**), release provenance (**T3 done as A8a**).
6. **E13 + E12 + C4** � serverless Send, hardware-key unlock, PQ-paranoid
   profile. These are the features that make "better than Bitwarden" true rather
   than argued. 4-6 weeks.