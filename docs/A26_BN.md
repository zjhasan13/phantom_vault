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
| Item actions | Delete/Sure?, Permanently Shred/Sure? Shred, Restore Item |
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

## Verification

- `cargo test` includes `ui_language_normalizes_to_en_or_bn`.
- Manual: toggle BN on the lock screen and in Settings → restart → the choice
  persists; switch back to English.
- No new dependency, no network.
