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

1. **Trust surface** — no README, no LICENSE, no SECURITY.md, an unsigned
   installer, and no release provenance. A security product that cannot be
   audited or verified is not competitive, regardless of crypto.
2. **Account lifecycle** — no master-password change, no separate backup
   passphrase, no signed container revision.
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

### P0 — parity blockers (do first)

| ID | Task | Gap | Effort | Done when |
|---|---|---|---|---|
| A5 | Master password change / rekey | C1 | 1-2 wk | Old password fails, new password unlocks, one rollback snapshot exists |
| A6 | Separate backup passphrase for `.pvx` | C2 | 1 wk | Export opens only with the backup passphrase, never with the vault password |
| A7 | README, LICENSE, SECURITY.md | T1 | 2 days | Disclosure address + PGP key published; license present at root |
| A8 | Authenticode signing + release provenance | T2, T3 | 1 wk | A downloaded installer verifies against the release checksum and signature |
| A9 | Edit-before-save in the save toast | E3 | 3 days | Username and password can be corrected before the item is stored |

### P1 — close the structural gaps

| ID | Task | Gap | Effort | Done when |
|---|---|---|---|---|
| A10 | Platform layer: macOS and Linux desktop | E14 | 6-10 wk | Vault unlock, autofill bridge, and sync build and pass tests on both |
| A11 | Encrypted offline extension cache | E9 | 2 wk | Popup lists items and fills them with the desktop app closed, after a Hello-backed unlock |
| A12 | Shadow-DOM field scan and observer | E8 | 1 wk | A web-component login form gets a badge and fills |
| A13 | KDBX 4 import and export | E10 | 2-3 wk | A real `.kdbx` file round-trips without data loss |
| A14 | Argon2id extension PIN + attempt backoff | P4 | 1 wk | 10 wrong PINs trigger exponential delay; the stored verifier is not a bare SHA-256 |
| A15 | Mandatory P2P pairing (PAKE/QR) | S1, S2 | 2 wk | An unpaired LAN client gets 403 and cannot pull bytes; beacons carry only an ephemeral ID |
| A16 | Signed container revision (`rev` + `prev_hash`) | C3 | 1 wk | A replayed older blob is refused with a visible warning |
| A17 | Same-origin favicon fetch | P1 | 1 day | With the network off, no favicon request leaves the machine |
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
| C1 | No master-password change/rekey | No rotate/change callback exists in `src/main.rs`; all saves re-seal with the in-memory password (`src/main.rs:3508`) | A leaked master password cannot be rotated without exporting and rebuilding the vault; `.pvx` backups stay sealed with the old password | Rekey flow: decrypt with old, re-encrypt with new salt + fresh KDF, atomic swap, keep one rollback snapshot, zeroize both | S1 |
| C2 | Backup `.pvx` shares the master password | Export uses the same secret path (`src/storage.rs:139-160`) | A backup stolen with a known/weak master password exposes the vault; no separate "backup passphrase" | Optional separate export passphrase, Argon2id with its own salt, explicit "cannot be opened with the vault password" warning | S1 |
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
| P1 | Favicon prefetch sends every domain to DuckDuckGo, then Google | `src/core/favicon.rs:21-22,346-351`; enabled by default (`:86-89`) | The set of sites in the vault leaks to two third parties; contradicts "no cloud, no tracking" | Fetch `/favicon.ico` same-origin from the site itself, or ship a bundled icon set; delete the DDG/Google paths | S2 |
| P2 | Decoy vault is detectable by file presence | `src/security/decoy.rs:17,21-22` | `decoy_vault.enc` existing tells a coercer that duress mode is provisioned; file size/mtime differ | Always provision both containers, pad to a bucket, align mtimes; or hide the decoy inside the real container | S2 |
| P3 | Canary alert is local-only | `src/security/canary.rs:7,13,58-69` | An attacker with disk access deletes `canary_alert.log`; the owner never learns the vault was opened | Send a signed alert to a paired device over P2P and/or an optional dead-drop (private repo, email) | S2 |
| P4 | Extension PIN is a bare SHA-256 of a 4-8 digit PIN | `src/security/ext_pin.rs:9-11,21-24`; hash is served to the extension (`browser_extension/background.js:319-320`) | 10^4-10^8 offline candidates; a local attacker with the DPAPI blob on the same account can brute-force the UI gate | Argon2id/scrypt with a per-device salt, attempt counter with exponential backoff, Windows Hello fallback | S2 |
| P5 | Plaintext password crosses to the extension per query | `src/windows_native/native_host.rs:397`; capped at 25 (`:409-410`) | Same model as Bitwarden, so not a parity gap, but the blast radius is larger than necessary | Per-fill one-time token, single-item scope, 10 s TTL; keep `query` for the popup only | S3 |

### 4.4 Extension

| ID | Gap | Evidence | Impact | Fix | Status |
|---|---|---|---|---|---|
| E1 | Idle lock was lazy, evaluated only on the next message | `browser_extension/background.js:176-190` before this batch; popup polled every 15 s (`popup.js:941`) | Up to 15 s of the UI claiming "unlocked" after the deadline; background tabs kept a warm gate cache for 30 s | `chrome.alarms` tick + push `PV_GATE_LOCKED` to all tabs | **Shipped** |
| E2 | No "Never save for this site" | `content.js:2371-2378` had only Save / Not Now | Users who never want a login stored for a site were re-prompted forever | Third button, persisted registrable-domain list, background refusal | **Shipped** |
| E3 | No edit-before-save | `content.js:2352-2412` stores the page's username/password verbatim | A typo or a masked field is saved as-is; users must open the desktop app to fix it | Inline edit fields in the toast before Save | S2 |
| E4 | No offline cache in the extension | `background.js:140-168` requires a live native port; popup shows Retry when the desktop is closed (`popup.js:57`) | Extension is useless when the desktop app is not running, unlike Bitwarden's local cache | Encrypted read-only cache with a short TTL, unlocked by a separate extension PIN | S2 |
| E5 | No settings UI for never-save list | This batch writes `never_save_domains` (`content.js:36,2344-2351`) but no popup surface exists | Users cannot review or undo a "Never" decision | Settings list with per-domain remove | S3 |

### 4.5 Trust and distribution

| ID | Gap | Evidence | Impact | Fix | Sev |
|---|---|---|---|---|---|
| T1 | No README, LICENSE, or SECURITY.md | Files absent at repo root | Cannot audit, cannot legally reuse, no disclosure channel; a security product with no disclosure policy is a red flag | Add all three; SECURITY.md with a PGP key and a 90-day disclosure window | S1 |
| T2 | Installer is unsigned | `installer.iss` has no `SignTool`/`SignedUninstaller` directive | SmartScreen warns; enterprise deployment blocked; tampering is undetectable | Authenticode sign the installer and the binary in CI | S1 |
| T3 | No release/provenance workflow | Only `.github/workflows/security.yml` exists | Users cannot verify that a release matches the source | Add a build workflow with checksums, SBOM, and a signed release attestation | S1 |
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

`cargo test` and `npm test` (118) are green after the change.

---

## 6. Roadmap

Ordered by risk reduction per unit of work. Each phase has an exit test.

### Phase 1 — Trust (1 week)

1. `README.md`, `LICENSE`, `SECURITY.md` with a disclosure address and PGP key.
2. Authenticode signing in `installer.iss` + CI.
3. Release workflow: checksums, SBOM, signed attestation.
4. Exit test: a fresh clone can verify a downloaded installer's hash and
   signature against the release page.

### Phase 2 — Account lifecycle (2-3 weeks)

1. Master-password change/rekey with atomic swap and a one-step rollback
   snapshot (C1).
2. Optional separate backup passphrase for `.pvx` (C2).
3. Header version bump carrying `rev` + `prev_hash` (C3).
4. Exit test: rotate the password, unlock with the new one, verify the old one
   fails, and verify an older `.pvx` still imports.

### Phase 3 — Sync integrity and pairing (2-3 weeks)

1. P2P pairing mandatory, PAKE-based, ephemeral beacon IDs (S1, S2).
2. Refuse a lower `rev` on restore; warn instead of silently adopting (S3).
3. Exit test: an unpaired LAN client gets 403 and cannot pull bytes; a replayed
   older blob is refused with a visible warning.

### Phase 4 — Privacy defaults (1 week)

1. Same-origin favicon fetch or a bundled icon set; delete DDG/Google paths
   (P1).
2. Indistinguishable decoy provisioning (P2).
3. Canary alert over P2P plus an optional dead-drop (P3).
4. Exit test: with the network disabled, no favicon request leaves the machine;
   a decoy-provisioned profile is not distinguishable by file listing.

### Phase 5 — Extension completion (1-2 weeks)

1. Edit-before-save in the toast (E3).
2. Settings UI for the never-save list (E5).
3. Argon2id extension PIN with backoff (P4).
4. Optional encrypted offline cache with a separate PIN (E4).
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
| Master-password rotation | Missing | Yes | Yes | Behind |
| Backup passphrase | Missing | N/A (server) | Yes (Emergency Kit) | Behind |
| Extension idle lock | Proactive (this batch) | Proactive | Proactive | Parity |
| Never-save for site | Yes (this batch) | Yes | Yes | Parity |
| Edit-before-save | Missing | Yes | Yes | Behind |
| Offline extension cache | Missing | Yes | Yes | Behind |
| Local API / CLI | Missing | CLI (open source) | CLI + Connect | Behind |
| Installer signing / provenance | Missing | Signed | Signed | Behind |
| Audit / disclosure docs | Missing | Yes | Yes | Behind |
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
# Extension test suite (111 tests)
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

# Container layout and the honest PQ note
Select-String -Path src\crypto.rs -Pattern 'V2_PORTABLE_MAGIC|H5 NOTE' -Context 0,6

# P2P open-LAN default and beacon fields
Select-String -Path src\sync\p2p_local.rs -Pattern 'when none exists|head_sha|pin_required' -Context 0,3

# Favicon third-party hosts and default
Select-String -Path src\core\favicon.rs -Pattern 'DDG_ICON|GOOGLE_S2|unwrap_or\(true\)'

# Missing trust files
Test-Path README.md, LICENSE, SECURITY.md
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
| Updates are unsigned | Partly wrong. The updater requires a detached Ed25519 signature plus SHA-256 before staging; only the installer itself lacks Authenticode | `src/sync/updater.rs:9-38,144-160` |

### 10.2 New gaps

| ID | Gap | Evidence | Impact | Fix | Sev |
|---|---|---|---|---|---|
| E6 | Extension cannot add, edit, or delete items | ~~No write command in `browser_extension/popup.js`~~ — shipped in 5.4 (`openItemEditor`, `create_login`/`update_login`/`delete_login`) | Every change used to require the desktop app; Bitwarden's popup is a full editor | Add item editor + `update_item`/`delete_item` bridge commands with origin and reprompt checks | S1 |
| E7 | Extension copy never clears the clipboard | ~~`popup.js:1504-1507` writes and stops~~ - shipped: native `copy_secret` + `pv_clip_hash` guard (5.5, 5.7) | A copied password used to stay in the OS clipboard indefinitely, and reached Win+V | Reuse the desktop clear timer via the bridge, or a popup-side 30 s timer with best-effort clear | **Shipped** |
| E8 | No shadow-DOM autofill | `content.js:450` is the extension's own UI shadow root; no traversal of page shadow roots | Web-component login forms (increasing share of modern sites) never get badges or fill | Traverse open shadow roots in field scan and observer; skip closed roots | S2 |
| E9 | No offline extension cache | `background.js` needs a live native port; popup shows Retry (`popup.js:57`) | Extension is dead when the desktop app is closed | Encrypted read-only cache, unlocked by Hello-backed token, short TTL | S2 |
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
3. **C1 + C2** � rekey and separate backup passphrase. 2-3 weeks.
4. **E8 + E9 + E10** � shadow DOM, offline cache, KDBX. 3 weeks.
5. **T1-T3** � README/LICENSE/SECURITY, Authenticode, release provenance. 1 week.
6. **E13 + E12 + C4** � serverless Send, hardware-key unlock, PQ-paranoid
   profile. These are the features that make "better than Bitwarden" true rather
   than argued. 4-6 weeks.