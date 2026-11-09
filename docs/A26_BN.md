# A26 — Bengali UI (pilot)

> Status: **pilot shipped.** The lock screen already had an in-place EN/BN
> toggle; A26 adds **persistence** (`lang.pref`), a Settings language control,
> and Bengali for the main navigation + Settings/section headings. The rest of
> the desktop UI is still English. This is an incremental translation, not a
> completed A26.

## What is translated now

| Surface | Strings |
|---|---|
| Lock/unlock screen | password/PIN/shards tabs, master-password placeholder, unlock/Hello/PIN buttons, 2FA step, shard recovery (existing) |
| Sidebar | VAULT, TYPES, FOLDERS, APP, All items, Favorites, 2FA Hub, Settings, Login, Card, Identity, Note, License, SSH Key |
| Importer | “Universal Vault Importer” title |
| Settings | “Settings & Dev Center”, Language row, master rotation, offline cache, PQ-paranoid, 2FA clock, clipboard, auto-lock, updates, paired devices, duress/honeytokens/emergency headings |
| Sync/export | GitHub Sync, Local Wi-Fi P2P title + enable/pairing/scan/empty labels, Export Vault heading |
| Dialogs | Master Reprompt title/action/field/Confirm/Cancel, “demands master-password confirmation”, API approval (Allow/Deny + warning), import dry-run preview (mode buttons, Confirm/Cancel, Undo), duplicate-import choice buttons |
| Rust status strings | “decoy mode is read-only” (all handlers), “vault not unlocked”, import flow (waiting/no-file/preview/staged/merging/restore), unlock status line (empty password, decrypting, wrong password, unlocked, Hello/TOTP prompts), main share/API static statuses |
| Quick Capture | window title row, service/username/password/2FA labels + placeholders, Save/Dismiss (separate `ui_lang` copy) |
| Quick Bar | instant-copy hint, Copy, no-matches, Dismiss (separate `ui_lang` copy) |
| Generator | Complex/Diceware, LENGTH/WORDS/ENTROPY/NO AMBIGUOUS, Regenerate/Use This, entropy unit, empty-set warning |
| Item actions | Delete/Sure?, Permanently Shred/Sure? Shred, Restore Item, Empty Trash & Shred All dialog |
| Add/edit form | item-kind placeholders for login/card/identity/license/SSH/note (username, cardholder, card number, CVV, expiry, NID/passport, public/private key, address/company/city/state/ZIP/country, alias) |
| P2P results | already-in-sync, adopted/pushed, conflict (Rust `i18n`) |
| Import summary | headline + counts, updated-in-place, bad rows (Rust `i18n`) |
| Sync results | offline-skip, ciphertext-pushed, vault-synced status lines |
| Sections | LOCAL API (pv CLI), EXPIRING SHARES (SEND), PQ-paranoid labels (partial) |
| Item detail | LOGIN CREDENTIALS, USERNAME, PASSWORD, NOTES, AUTO-FILL OPTIONS, BACKUP / RECOVERY CODES, CUSTOM FIELDS, ATTACHMENTS, ITEM HISTORY, Autofill/Type, Copy All Codes, attach buttons, empty-attachment text |
| Add/edit form | ITEM DETAILS, LOGIN CREDENTIALS, EXTRA FIELDS, AUTHENTICATOR KEY (TOTP), BACKUP / RECOVERY CODES, AUTOFILL OPTIONS, USERNAME, PASSWORD, NOTES |

Everything else — many dialogs, notifications, remaining sync/import result
strings, import/export details and long security copy — remains English. Quick
Capture, Quick Bar and the generator now mirror `ui_lang`.

## How the switch works

- The Slint property `ui_lang` (`"en"` / `"bn"`) drives inline ternaries:
  `text: root.ui_lang == "bn" ? "বাংলা" : "English"`.
- Rust-generated status strings use `tr("English", "বাংলা")`, backed by a
  process-wide `UI_LANG_BN` flag set by the same toggle/startup path.
- The lock-screen toggle and the Settings → Language row both call the Rust
  `set_language(string)` callback, which writes `lang.pref`, sets `ui_lang` and
  the `tr()` flag.
- Startup reads `lang.pref` before the UI is used. No gettext/`.po` bundle is
  involved; nothing changes if the pref is missing (English).
- `normalize_lang()` only accepts `bn` (case/space tolerant); everything else
  falls back to English.

## Honest limits

- **Partial translation.** A Bengali user still sees English in most dialogs.
- Rust-generated status strings (errors, notifications, sync results) are not
  translated; only static Slint labels are.
- Layout QA (clipping/overflow with longer Bengali strings) is manual; only the
  translated surfaces were checked by reasoning, not by a full visual pass.
- No `@tr()`/translation-catalogue yet. Inline ternaries are simple and
  dependency-free but will get unwieldy past a few hundred strings; a later
  slice can migrate to Slint bundled translations (`@tr` + `.po`) without
  changing the user-facing setting.
- `lang.pref` is local UI state (gitignored), not synced.

## How to extend (next slices)

1. Pick a surface (item detail, add/edit form, import preview).
2. Replace `text: "English"` with
   `text: root.ui_lang == "bn" ? "বাংলা" : "English"`.
3. Keep placeholders/`Accessible` labels in sync.
4. Add the pair to this table, then do a visual pass at 100% and 125% scaling.
5. Prefer translating **actions and errors** next (highest user value), then
   long help text.

## Status (pilot wrap-up)

- Slint: ~110 `ui_lang` ternary lines across lock screen, sidebar, detail/form,
  settings, sync/export cards, generator, dialogs and the Quick Bar/Capture
  windows.
- Rust: ~150 `tr()` call sites (unlock statuses, decoy/vault guards, import
  flow, share/API statics, P2P results, import summary).
- Long help paragraphs translated: offline cache, PQ-paranoid card, Local API,
  Expiring shares, family-sync blurb.
- Static width audit: the longest Bengali labels got wider fixed buttons
  (Confirm Import, reprompt/TOTP confirm, import mode row, shred-all).
- Still English: remaining sync/import result details, some modal help copy,
  identity/card detail rows rendered by Rust, and many error strings.

## Layout QA checklist (manual, before calling A26 complete)

1. Settings at 100% and 125% scaling: security cards, language row, share card.
2. Lock screen: tabs, PIN pad, TOTP step, shard recovery.
3. Item detail: username/password rows, attachment buttons, delete/shred/restore.
4. Add/edit form for every kind (login/card/identity/license/note/SSH).
5. Import dry-run preview and duplicate-choice dialog.
6. Generator panel, Quick Bar, Quick Capture.
7. Confirm no Bengali label is clipped/ellipsized unexpectedly; widen or wrap.

## Migration plan (`@tr` + `.po`)

The inline-ternary + `tr()` approach is dependency-free and fine for this
pilot, but it does not scale to full A26. When finishing the translation:

1. Wrap strings with `@tr("…")` (no context) and move pairs into
   `lang/bn/LC_MESSAGES/phantom_vault.po` (+ an `en` catalogue).
2. `build.rs`: `CompilerConfiguration::new()
   .with_bundled_translations("lang")
   .with_default_translation_context(DefaultTranslationContext::None)`.
3. Startup: `slint::select_bundled_translation("bn")` after reading
   `lang.pref`; keep `set_language` writing the pref. Bundled translations
   re-evaluate on selection, so no `update_all_translations` is needed.
4. Replace `i18n::tr` calls with catalogue lookups for the remaining Rust
   strings (or keep the tiny flag for non-Slint-only strings).
5. Remove the inline ternaries as each surface migrates; keep the coverage
   table and the layout checklist as the acceptance gate.

## Coverage update (2026-11-07, dialog batch)

B1 localized the main dialogs: import merge preview, duplicate-import choice,
factory reset, new-PC/Hello re-enrol, attachment preview, changelog, access log,
plaintext-source shred, and the vault health report. Mode/undo/confirm buttons in
the import preview were already BN.

Still English: Rust status/error strings, the `VaultError` text inside
`Auto-Type: {e}`, and some Settings/onboarding paragraphs. The BN layout pass
(100%/125%) is still pending.

## Coverage update (2026-11-08, status batch)

B2 localized the Rust-side status/notification strings we author (export,
import, sync, scanner, PIN, health, janitor, travel mode) and added
`VaultError::localized()` — every variant has a Bengali wrapper, and the
Auto-Type payload strings (focus moved, no foreground window, Tab miss, nothing
to type) are mapped explicitly. Unknown technical payloads fall through in
English rather than a fabricated translation.

Still English: dynamic `format!` statuses outside Auto-Type (their payloads are
OS/serde text), some Settings/onboarding paragraphs, and the BN layout pass.

## Coverage update (2026-11-09, layout pass B3)

B3 closed the remaining Bengali gaps on the main screen and did the visual pass
the earlier batches only reasoned about.

Translated in this batch: sidebar `Cards`, `Identities`, `Licenses`,
`Recovery Kit`, `Audit & Duress`, `Secure Send` and the Trash label
(`ট্র্যাশ`, `ট্র্যাশ (n)`); the `Identity`/`License` filter chips in both the
single-row and the 2-row grid; the list counters (`দেখানো হচ্ছে X / Y`,
`X / Y আইটেম`); the empty detail pane; the recovery-sheet nudge; the health
"all good" line; and the sidebar travel toggle (`✈ ট্রাভেল: চালু/বন্ধ`).

Mono brand chips (`ZERO-KNOWLEDGE`, `RAM-SAFE`, `READY`, `ENCLAVE MODE`,
`PORTABLE`, `LOCAL-FIRST`) stay English on purpose — they are brand/mono
labels, not prose. The Settings page and the item-detail diagnostic tiles are
still mostly English (separate batch).

### Layout QA

This machine runs at **125% display scaling** (DPI 120), so every capture below
is a 125% capture. Slint reports logical px; UIA reports physical px (divide by
1.25 before comparing).

| Capture | Result |
|---|---|
| 1500x940 physical = 1185x752 logical, single-row chips | chips and sidebar fit; with an item open the detail pane overflowed (see fix) |
| 1200x1000 physical = 960x800 logical, the declared `min-width` | 2-row filter grid; sidebar, list, empty detail pane and footer all inside the window |
| 1000x900 physical = 800 logical — **below** `min-width: 960px` | shell overflows; `+ নতুন` and the empty-state text run past the window edge |

Fix found by the pass: the detail "proof strip" (`XChaCha20-Poly1305 VERIFIED`,
`ARGON2ID 64 MiB`, `DPAPI DEVICE BOUND`, `STRENGTH n%`) is one non-wrapping row
whose minimum width (~600 logical px) exceeded the pane and pushed it past the
window edge, cutting the last chip. The middle two chips are now hidden below
1300 logical px (they are duplicated in Settings).

Not covered yet: the **filled** item-detail pane at 960 logical px. It was
verified at 1185 logical (screenshot `pv-bn-detail5.png`); at the minimum width
only the empty pane was captured. The automatic row-click in the harness keeps
landing on the row's action icons, so this needs a manual look.

The 1000-px row above is expected behaviour **below** the documented minimum
(`min-width: 960px`), not a Bengali regression. `SetWindowPos` can bypass that
minimum; whether a user drag is also allowed below it was not verified.

### Traps

- `SLINT_SCALE_FACTOR=1.25` does **not** scale rendered text in Slint 1.18
  (`winitwindowadapter.rs` only uses it to adjust window attributes), so it
  cannot simulate 125% in a screenshot. Use the real display scaling.
- UIA returns physical pixels; divide by the DPI scale before comparing with
  Slint's logical widths.
- `Unlock` in `scripts/dev/pv-ui-auto.ps1` used to print `UNLOCKED`
  unconditionally; it now verifies (`VAULT SEALED` gone) and retries once.
- Resizing the window from a *separate* harness invocation can leave the app
  window hidden from UIA. Resize inside the same run (`bnscreens`, `bnmeasure`).

## Coverage update (2026-11-09, Settings batch B4)

The Settings page now follows `ui_lang`: 196 literals across all six tabs.

- Header + tab bar: `সেটিংস ও ডেভ সেন্টার`, `সিকিউরিটি`, `সিঙ্ক ও ডিভাইস`,
  `প্রাইভেসি`, `রিকভারি`, `ব্যাকআপ`, `ডেভ ও API`. Tab widths were re-tuned so
  the row still fits at the 960 logical px minimum window (verified on screen).
- Security: screen/blackout, favicons, custom logos + help line, travel mode,
  App PIN setup, master rotation copy, offline cache, container profile,
  PQ-paranoid, Local API, shares (create/open/revoke rows), extension PIN,
  two-factor unlock, hands-free 2FA, TOTP drift, clipboard + auto-lock chips,
  offline kill-switch, access log, tray hint, updates.
- Sync/Privacy/Recovery/Backups/Dev: GitHub sync fields, merge preview, per-item
  sharing, Secure Send, business roster/OIDC, pairing, browser bridge, export
  formats + warning, scheduled backups, paranoia/recovery, shard grants,
  DANGER ZONE, email aliases, anti-photography, health/dev tools, scoreboard.
- Toggle chips use a new `tog(on)` helper: `চালু` / `বন্ধ` instead of ON/OFF.
- Rust-side: `Missing credentials…` and `Not available on this device.` go
  through `tr()`.

Kept English on purpose: mono chips (`LOCAL VAULT`, `DPAPI BOUND`), vendor and
protocol names (`Windows Hello`, `TPM`, `OIDC`, `PAT`, `PowerShell`, `Bash`,
`Nushell`, `Addy.io`, `SimpleLogin`, `base64`, `hex`), and the language toggle.

Still English: the long tail of Rust status lines (`set_sync_status`,
`set_notification_text`, `set_*_status(format!…)` — ~250 literals), the item
detail diagnostic tiles, and a few Slint property defaults (`ssh_status`,
`health_headline`) that are set by Rust.

Known layout limit at the 960 logical px minimum: some Settings rows (Windows
Hello status, App PIN chip) still run ~20 logical px past the right edge.
`pv-bn-set-960.png` shows it; the tab row itself fits. Stacking those rows on
narrow windows is the next layout task.

## Verification

- `cargo test` includes `ui_language_normalizes_to_en_or_bn`.
- Manual: toggle BN on the lock screen and in Settings → restart → the choice
  persists; switch back to English.
- No new dependency, no network.

## Coverage update (2026-11-07, auto-type batch)

- Auto-type notifications now localize: multi-line refusal, no-context block,
  spoof warning (formatted), app-mismatch (formatted), "item no longer
  available", master re-prompt, stale-password warning, hands-free 2FA success
  and the 30 s "no OTP screen" message.
- The 2FA countdown pill and its Cancel button, plus the Quick Capture field
  accessibility labels, follow `ui_lang`.
- Still English by design: `VaultError` text inside `Auto-Type: {e}` (the
  underlying error enum is not translated), and the remaining dialogs listed
  above.
