# FEATURE_LEDGER — what exists, what is partial, what is intentionally absent

Status legend: **✅ shipped** · **◐ partial** · **⛔ absent by design**

This ledger is the quick answer to "does feature X exist, and where?". It is not
marketing: every row points at the file or gate that can prove it. Update a row
when a user-visible capability is added, changed, or deliberately removed.

> Last updated: 2026-11-05 · `171eb92`

## 1. Desktop UI (Slint — `ui/appwindow.slint`)

| Area | Status | Notes / where |
|---|---|---|
| Unlock / lock screen | ✅ | master password, EN/BN toggle, Hello/PIN states, recovery entry |
| Onboarding | ✅ | 3 steps; recovery-shards checkbox kept inside the card (`a1ac396`) |
| Vault list + filter strip | ✅ | All / Favorites / Recent / Login / Card / Note / SSH / Identity / License; centered (`1aa3a70`), two-row grid below 1100 logical px (`a4c2bfc`) |
| Item detail (all kinds) | ✅ | login, card, note, identity, license, SSH; history, attachments, TOTP |
| Add / edit editor | ✅ | per-kind fields, folder, tags, favourite |
| Password generator | ✅ | OS CSPRNG, Complex + Diceware, copy |
| 2FA hub | ✅ | filter chips, sort, per-account params, HOTP next, Add-2FA sheet |
| 2FA import sheet | ✅ | screen/webcam/file QR + manual paste; content-sized (`171eb92`) |
| 2FA export sheet | ✅ | paginated otpauth QR, copy URI, honest empty/error states |
| Vault health report | ✅ | breached / reused / weak / stale, per-row open; content-sized (`171eb92`) |
| Master reprompt | ✅ | guard for reveal / autofill / delete / export; content-sized (`171eb92`) |
| Recovery kit + shards | ✅ | print sheet, shard drill |
| Audit & duress | ✅ | duress password, honeytokens, factory reset (3-pass) |
| Secure Send | ✅ | expiring one-view notes, TTL, read + burn (`docs/A20_SEND.md`) |
| Local sync & storage | ✅ | GitHub private-repo sync, local Wi-Fi P2P, QR fallback |
| Extension bridge | ✅ | native-messaging host install, allowed origins |
| Import | ✅ | row preview, Skip/Update/Import all, undo, dedupe |
| Settings & Dev Center | ✅ | Security / Sync & Devices / Privacy / Recovery / Backups / Dev & API tabs |
| Offline cache | ✅ | snapshot + DPAPI key + Hello/PIN gate; freshness + sealed timestamp |
| Travel mode | ✅ | local-only switch |
| Localization | ◐ | EN/BN for shell + most dialogs; Rust status strings and some dialogs still English (`docs/A26_BN.md`) |

## 2. Browser extension (`browser_extension/`)

| Area | Status | Notes / where |
|---|---|---|
| Autofill dropdown | ✅ | one ranking for dropdown/hotkey/context menu, per-tab carry |
| Continue-as (identifier step) | ✅ | username-only step carries to password step (`fc1def7`) |
| Save prompt — login | ✅ | closed shadow root, 60 s TTL, per-tab, folder picker, notes, editable title/URL, update-target chips, EN/BN, at-risk hint |
| Save prompt — card / identity | ✅ | Aegis panel, reuse hint pending |
| Badge qualification | ✅ | no badge on newsletter/contact/identity fields (`fbe7881`, `7bca1b6`) |
| Popup list | ✅ | all kinds, folders, search, health badges |
| Popup view + editor | ✅ | read-only view with Edit/Fill/Close (`0b7e0c6`); create/update/delete for login/note/card/identity/SSH/License (`1cf5c6d`) |
| HUD 3.0 hero card | ◐ | hero slice shipped (`25008cc`, `09059bb`); full 640px dual-column not built |
| Generator in popup | ✅ | same honest generator |
| SSH keys + licenses | ✅ | list + view/edit in the popup (`b399b06`, `1cf5c6d`) |
| Attachments + history | ◐ | metadata + open/download (`a133375`); upload from popup not built |
| Offline cache | ✅ | warm cache, freshness gate, tab scope (`55fe343`, `b69f8b6`) |
| At-risk hint | ✅ | host-side HIBP k-anonymity (SHA-1 prefix only) + local reuse count |
| Firefox build | ✅ | `manifest.firefox.json` + `browser_extension/build.ps1` |

## 3. Core / security capabilities (Rust)

| Capability | Status | Where |
|---|---|---|
| Vault encryption | ✅ | `src/crypto.rs`, `src/storage/` — Argon2id + XChaCha20-Poly1305 |
| PQ hybrid envelope | ✅ | ML-KEM layer, portable `PV2` envelope (`rules.md` §3) |
| Recovery shards | ✅ | shard drill callback, recovery kit |
| Import/export | ✅ | `.pvx`, Bitwarden JSON, CSV, KeePass KDBX (`docs/A13_KDBX.md`) |
| Expiring shares | ✅ | `src/share*.rs`, one-view/TTL, fragment key |
| Local API | ✅ | `src/api/`, `docs/A23_LOCAL_API.md` |
| Attachments | ✅ | `src/attachment_store.rs`, `docs/A24_ATTACHMENTS.md` |
| Access log (hash-chained) | ✅ | metadata only, `open_access_log` in `main.rs` |
| Windows Hello / PIN / DPAPI | ✅ | `src/security/`, `src/windows_native/` |
| Zeroize / secrecy | ✅ | required by `rules.md`; enforced in review + clippy |

## 4. Deliberately absent (do not "fix" without asking)

| Not present | Why |
|---|---|
| HUD 3.0 dual-column popup (640px) | Declined by the user (2026-11-07). Keep HUD 2.0's list → separate detail page; the 420px popup gives the item full width and matches Bitwarden's extension. |
| Organizations / collections | Vault model is single-user; there is nothing to pick. Do not add org pickers to save prompts. |
| Cloud sync account / vendor lock-in | Local-first by design; GitHub/P2P/QR are user-owned transports. |
| Fake security chips ("AES-256-GCM", "quantum-immune", "0M leak", "0 ms") | Dishonest. The extension explicitly does not reproduce the mockup's enclave/quantum chips (`popup.js:2336`, `popup.html:207`). |
| WebView / Electron | Hard invariant (`rules.md` §1). |

Honest caveat: the **desktop shell** still shows the label "ENCLAVE MODE"
(`ui/appwindow.slint:1699`) and "LOCAL ENCLAVE SYNCHRONIZED" (`:3284`) from an
earlier pass. They are UI labels, not claims under test; renaming them is a
product-copy decision, not a bug fix.

## 5. Recent additions / changes (newest first)

| Commit | What changed |
|---|---|
| `a486f85` | i18n: main dialogs (import/dup/factory/new-PC/attachment/changelog/access-log/shred/health) follow ui_lang |
| `1cf5c6d` | extension: SSH + License view/edit (bridge kinds 6/7, Add chooser, masked keys) |
| `0b7e0c6` | extension: read-only item view (masked secrets) with Edit/Fill/Close; per-row 👁 |
| `da1de56` | save prompts: card/identity reuse hint ("also in N other item(s)") |
| `774420a` | i18n: auto-type notifications, 2FA countdown + Cancel, capture a11y labels follow ui_lang |
| `a4c2bfc` | filter strip: 68px chips + a 5-column, two-row grid on narrow windows |
| `4a38695` | A33: secrets removed from `CredentialView`; Quick Bar copy/type resolve by (kind, id) |
| `6d3aac5` | Quick Bar A32: app prefilter no longer pre-types the app name into the search box |
| `1c03520` | popups T1-T10: token scale, opaque surfaces, 5.2:1 tab contrast, brand casing, BN strings, accessible roles |
| `b63455c` | auto-type A30/A31/A34: watcher stops on lock, decoy fills stay out of real stats, no focus steal after a fill |
| `2b2f81b`, `be545f0` | popups A23/A24: focus-out auto-hide and a 1:1 cursor-anchored header drag |
| `1a82614` | auto-type A13-A17/A19/A20: STA-safe COM, no placeholder usernames, abort logging, recent-first unbound Quick Bar |
| `d76c34c` | auto-type A8/A11/A12: focused pair selection, control-level focus guard, verified Tab stop |
| `34048fb` | auto-type A25-A28: tone-aware toasts, sticky errors, canary alert preserved, Quick Bar block reasons |
| `1cf999a` | auto-type A5/A10: UIA writes verified with keystroke fallback; cancellable 30 s 2FA watcher with countdown + focus guard |
| `b4ec6d0` | auto-type A9/A21/A22/A29: card CVV rejected as OTP; Quick Bar + Quick Capture focus on open; Quick Bar index and capture mask reset |
| `6b095fc` | auto-type A6–A7: target frozen after the minimize settle; typed username restored on a failed password write |
| `3b1fc92` | auto-type A1–A4: fail-closed context gate, password-focus guard, four-stop card fill, multi-line (note/SSH) refusal |
| `171eb92` | four dialogs content-sized; import/export headers centered and contained |
| `1aa3a70` | filter strip centered; Identity + License chips |
| `a1f53f8`, `0c7ce6c` | vault top bar spacing, collapse controls centered |
| `a1ac396` | onboarding recovery-shards checkbox no longer overflows |
| `2d7a6f4` | save prompts follow the EN/BN setting |
| `b8ff022` | save-prompt notes, reuse hint, card/identity parity, a11y |
| `396b0ac` | at-risk flags (HIBP k-anonymity) in save prompts |
| `c4be27c` | save prompts in closed shadow roots |
| `7462714` | editable title/URL in save prompts |
| `43a876d` | choose which existing login a save updates |
| `41329b8` | folder picker + close button in save prompts |
| `b69f8b6`, `55fe343` | offline cache hardening + freshness |
| `a133375` | password history + attachment metadata in the extension editor |
| `b399b06` | SSH keys + licenses in the popup |
| `25008cc`, `09059bb` | HUD 3.0 hero card |
| `fc1def7` | Continue-as one-click fill |

For full detail: `git log --oneline` and `docs/HANDOFF.md`.

## 6. How to update this file

1. Add/change the row in the feature table (status + file/gate pointer).
2. If something was removed on purpose, add it to §4 with the reason.
3. Add one line to §5 with the commit hash.
4. Keep claims verifiable: a row is only ✅ if a test, a screenshot, or a code
   path proves it.
