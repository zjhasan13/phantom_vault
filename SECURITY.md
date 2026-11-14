# Security Policy

PhantomVault stores the keys to everything else, so we treat security reports as
the highest-priority work in the repository.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | ✅ Security fixes |
| 0.3.x and earlier | ❌ Upgrade first; fixes land only on the latest release |

The container format and the bridge protocol are pre-1.0 and may change between
minor versions. `docs/RELEASE.md` records the current peer-compatibility matrix.

## Reporting a vulnerability

**Do not open a public issue, discussion, or pull request for a security bug.**

Use GitHub's private vulnerability reporting:

1. Go to <https://github.com/zjhasan13/phantom_vault/security/advisories/new>
2. Describe the issue there. The thread is private until an advisory is published.

There is no dedicated security email or PGP key at this time. If you need an
encrypted channel, use the advisory — it is private and stored by GitHub.

Please include:

- PhantomVault version (`0.4.2`), Windows build, and architecture (x64/ARM64)
- Whether the extension, the desktop app, the native host, or the sync path is affected
- Minimal reproduction steps or a proof of concept
- Impact: what an attacker gains, and what preconditions they need
- Any suggested fix, if you have one

Please do **not** include real vault files, master passwords, DPAPI blobs, sync
tokens, or third-party credentials. A synthetic vault is always enough.

### What to expect

These are targets, not contractual SLAs:

- Acknowledgement within **7 days**
- Initial triage and severity assessment within **14 days**
- A fix or a mitigation plan for confirmed high/critical issues as fast as the
  release process allows; you will be credited in the advisory unless you ask not to be

We do not run a paid bug bounty. We do publish a GitHub Security Advisory, credit
the reporter, and ship a patch release.

### Coordinated disclosure

We follow a **90-day** disclosure window from the first acknowledged report. If a
fix ships earlier, the advisory is published then. If you plan to publish research,
tell us the date in the report so the advisory can land first.

## Scope

**In scope**

- Container cryptography: Argon2id parameters, XChaCha20-Poly1305, ML-KEM/X25519
  hybrid, the `PV3` PQ-paranoid key chain (Argon2id + device decapsulation key),
  salt/keypair reuse, nonce handling, version detection and migration
- KeePass KDBX import (A13): declared-KDF caps, wrong-password handling, the
  `keepass` dependency boundary
- Local API (A23): loopback-only binding, DPAPI token storage, per-request
  approval, rate limits and the `pv` CLI surface
- Share bundles (A20): `PVSH1` format, URL-fragment key custody, expiry and the
  transport's one-view enforcement
- Key handling: zeroization, page locking, DPAPI seals, Hello token, App PIN,
  extension PIN (Argon2id, host-side verification, attempt lockout), master-password rekey, rollback snapshot
- Native-messaging bridge: origin pinning, frame MAC, request caps, `verify_master`
  limiter, command surface reachable from a compromised page or extension
- Extension: credential capture, autofill origin checks, save prompt (including the
  closed shadow root), clipboard clear ownership, idle lock, never-save list
- Sync: GitHub ciphertext push/pull, mandatory P2P pairing (device keys, signed
  requests, one-time code), replay/rollback of an older blob (A16 `rev` +
  `prev_hash`), audit-log chain and head anchor
- Release integrity: the pinned Ed25519 release key, `<asset>.sig` verification,
  checksum sidecars, and the SBOM/provenance publish path
- Offline read-only cache: the Hello gate, the DPAPI-sealed cache key, the
  15-minute extension TTL, decoy erasure and the read-only boundary
- Local attack surface: decoy vault (backup-like name, 1 MiB padding, no
  verifier file), canary (local log + signed paired-device alert), shredder,
  installer, update path
- Dependency vulnerabilities that are actually reachable from this code

**Out of scope** (report these as ordinary bugs, not vulnerabilities)

- An attacker who already has your Windows account, administrator/root, a kernel
  driver, or physical access to an unlocked session
- Malware, keyloggers, screen capture, or a compromised browser/OS
- The page observing key events typed into the save prompt — a DOM boundary, not a
  keyboard boundary (documented in the README and `docs/COMPETITIVE_GAP_ANALYSIS.md` §5.9)
- Denial of service against your own machine, or deleting your own vault/backups
- Social engineering, phishing pages that merely look like a login form
- Missing features that are already on the public roadmap (mobile, KDBX, hardware
  keys, signing, reproducible builds, PQ-paranoid profile)
- Third-party services you explicitly configure (your GitHub account, your LAN)

## Known limitations at 0.4.2

These are documented rather than secret; please do not report them as new findings.

- Binaries are **not Authenticode-signed**; SmartScreen warns on first run.
  Releases do ship detached Ed25519 `<asset>.sig` files for the updater, and a
  GitHub build-provenance attestation; verification steps are in `docs/RELEASE.md`.
- Installs built before the 2026-10-31 signing-key rotation pin the old public key
  and need **one manual reinstall** before in-app updates verify again.
- A16 adds a rev-2 container envelope. Older builds cannot open it — upgrade all
  devices before syncing. A fresh device's first pull is TOFU (no local revision);
  later stale pulls are refused.
- Decoy provisioning hides its filename/size class (A18), but mtimes are not
  aligned and large-attachment vaults can still differ in size class.
- 0.4.2 stops loading the content script in subframes: autofill/capture inside
  an embedded cross-origin login widget is gone by design.
- 0.4.2 drops `clipboardRead`. The extension can no longer verify-and-clear a
  copy it made itself; the native host still clears its own copies (Win+V
  exclusion + TTL flush).
- Canary alerts reach paired devices only while P2P is reachable; otherwise
  they queue locally for the next P2P enable/launch. There is no dead-drop yet.
- P2P requests/responses are signed by paired device keys (A15a/c), pushes carry
  a revision anchor, beacons carry only an ephemeral ID, and a peer that changes
  LAN address is re-bound only after its signed response verifies (A15d).
- The opt-in offline cache is **read-only and logins-only**, refreshed at unlock.
  Windows Hello gates the host read, but a same-user process can unseal the
  DPAPI-protected key without that prompt. If the PIN fallback is enabled, the
  cache is only as strong as the 4–8 digit PIN; both are deliberate convenience
  downgrades. Mutations and reprompt-armed items require the app.
- The extension PIN is 4–8 digits. Argon2id + a file-backed lockout make online
  guessing expensive, but a same-user process can read the DPAPI record and
  grind it offline at local CPU cost. Prefer 6–8 digits.
- The post-quantum layer is a **hedge, not a second factor** in the **portable**
  profile: a correct master password still opens it. The opt-in `PV3`
  PQ-paranoid profile additionally requires the device key for this Windows
  profile (Settings → PQ-paranoid): TPM 2.0-backed when available, DPAPI
  software fallback with a visible label, and an explicit proof-first move to
  TPM. Sync/P2P are refused. TPM/DPAPI are not user-presence gates: same-user
  malware can still unseal the key. Losing the sidecar, the TPM key or the
  Windows profile means data loss; enabling is gated behind a password-openable
  `.pvx` export.
- Favicon lookup is **same-origin only** (`/favicon.ico`); no third-party service
  is contacted. The site itself naturally sees its own icon request.
- P2P sync serves **ciphertext without pairing** if no PIN is configured.
- Backups, `.pvx` exports and printed recovery shards keep the **old** password
  after a rekey.
- KDBX import runs an untrusted file through a third-party parser. The
  plaintext KDF parameters are capped before any Argon2/AES-KDF work (see
  `docs/A13_KDBX.md`), but the parser and its dependencies remain part of the
  attack surface; attachments and entry history are not imported. KDBX export
  is sealed with a separate user-chosen password (never the vault master) and
  covers logins only.
- The local API (`pv`) is read-only and loopback-only. Its bearer token is
  DPAPI-sealed for the current user, so same-user malware can steal it; every
  read still requires an explicit in-app Allow prompt and is audit-logged. The
  API does not auto-start after a restart and has no TLS/process attestation.
- A20 shares put the key in the URL fragment; anyone who obtains the full link
  can open the share until expiry (and a recipient can copy what they read).
  One-view/TTL are enforced by the **sender's** store/relay, not by the bundle;
  the LAN endpoint is unauthenticated by design (128-bit random id, ciphertext
  only, key never in the request). File transport enforces expiry on the opener's
  clock and cannot enforce one-view.
- The extension requests broad permissions because autofill needs them:
  `<all_urls>` (content script + host permission) so the filler can run on
  whatever page holds a login form, plus `tabs` (fill target), `scripting`
  (frame routing), `clipboardWrite` (copy without a page gesture) and
  `nativeMessaging` (host bridge). The cost is blast radius: a compromised
  service worker could read page content on every site, and `hook.js` stays
  web-accessible on all `http(s)` pages for the MAIN-world tripwire, which is
  fingerprintable. No narrower set keeps autofill working, so this is accepted
  and documented rather than reduced.
- The native host does **not** yet require a pairing secret. A same-user process
  that knows the registered extension origin/id can launch the bridge and speak
  the native-messaging protocol. Today's mitigations are the local-only pipe,
  the per-request UI gates (reprompt, PIN) and the audit log; a pairing secret
  is designed but not shipped.
- There is no external security audit yet; `docs/AUDIT.md` is internal.

## Safe harbor

We will not pursue or support legal action against researchers who:

- test only against their own installation and their own test accounts,
- avoid privacy violations, data destruction, and service disruption,
- give us reasonable time to fix the issue before public disclosure, and
- do not exfiltrate data beyond the minimum needed to demonstrate the issue.

Good-faith research that follows this policy is welcome, not litigated.
