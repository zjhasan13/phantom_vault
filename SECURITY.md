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

- PhantomVault version (`0.4.0`), Windows build, and architecture (x64/ARM64)
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
  hybrid, salt/keypair reuse, nonce handling, version detection and migration
- Key handling: zeroization, page locking, DPAPI seals, Hello token, App PIN,
  extension PIN, master-password rekey, rollback snapshot
- Native-messaging bridge: origin pinning, frame MAC, request caps, `verify_master`
  limiter, command surface reachable from a compromised page or extension
- Extension: credential capture, autofill origin checks, save prompt (including the
  closed shadow root), clipboard clear ownership, idle lock, never-save list
- Sync: GitHub ciphertext push/pull, P2P LAN authentication, replay/rollback of an
  older blob, audit-log chain and head anchor
- Release integrity: the pinned Ed25519 release key, `<asset>.sig` verification,
  checksum sidecars, and the SBOM/provenance publish path
- Local attack surface: decoy vault, canary, shredder, installer, update path
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

## Known limitations at 0.4.0

These are documented rather than secret; please do not report them as new findings.

- Binaries are **not Authenticode-signed**; SmartScreen warns on first run.
  Releases do ship detached Ed25519 `<asset>.sig` files for the updater, and a
  GitHub build-provenance attestation; verification steps are in `docs/RELEASE.md`.
- Installs built before the 2026-10-31 signing-key rotation pin the old public key
  and need **one manual reinstall** before in-app updates verify again.
- The post-quantum layer is a **hedge, not a second factor**: a correct master
  password still opens the portable container.
- Favicon lookup currently contacts DuckDuckGo and then Google.
- P2P sync serves **ciphertext without pairing** if no PIN is configured.
- Backups, `.pvx` exports and printed recovery shards keep the **old** password
  after a rekey.
- There is no external security audit yet; `docs/AUDIT.md` is internal.

## Safe harbor

We will not pursue or support legal action against researchers who:

- test only against their own installation and their own test accounts,
- avoid privacy violations, data destruction, and service disruption,
- give us reasonable time to fix the issue before public disclosure, and
- do not exfiltrate data beyond the minimum needed to demonstrate the issue.

Good-faith research that follows this policy is welcome, not litigated.
