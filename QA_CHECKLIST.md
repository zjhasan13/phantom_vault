# PhantomVault Release Certification — Physical QA Checklist

> All 12 tests must pass on a clean Windows 10/11 64-bit machine before any
> release is tagged. Check each box only after PHYSICAL verification.
> Baseline: `cargo check` zero-warning + `cargo test` 279 passed / 0 failed.

## 1. Master Password & Memory Hygiene
- [ ] Fresh unlock with master password opens the vault.
- [ ] Wrong password bumps the backoff delay (no lockout of the owner).
- [ ] Auto-lock fires at the configured timeout (default 5m); unlock needs the password again.
- [ ] `Win+L` / session lock wipes RAM immediately (no secrets in a dump).
- [ ] No secret material in `stdout`/`stderr`/`crash.log` during the above.

## 2. Omni-Importer & Post-Import Shredding
- [ ] Import Bitwarden JSON: logins, TOTP, custom fields, folders, passwordHistory land intact.
- [ ] Backup/recovery codes auto-sort into the Backup Codes box (notes keep their copy).
- [ ] 1Password CSV + Proton JSON + KeePass XML import without row aborts.
- [ ] Post-import prompt shreds the source plaintext (DoD 3-pass, file gone).

## 3. 2FA Live Ticker (Proton Ring, Next Code, Steam Guard 5-Char)
- [ ] 2FA Hub shows the 3-column compact card grid (equal pixel widths, no zigzag, short rows left-align).
- [ ] Countdown rings tick every second with violet → orange → red shift.
- [ ] `Next:` preview matches the following code; Copy works.
- [ ] HOTP cards show the HOTP badge and `Next Code` advances the counter.
- [ ] Steam accounts render 5-character codes.
- [ ] Hub search filters ONLY 2FA cards (vault list untouched).
- [ ] ⭐-starred accounts sort first, rest A→Z; starring GitHub moves it top-left.

## 4. Zero-Knowledge GitHub Sync (`zjhasan33/phantom-backup`)
- [ ] Connect with PAT, Sync Now pushes ciphertext; repo shows no plaintext.
- [ ] Second machine pulls and decrypts with the same master password.
- [ ] Conflicting edits keep both sides safe (SHA guard, loud report, no silent merge).

## 5. Desktop Auto-Type (`Ctrl+Alt+A`) and Smart-Grab (`Alt+S`)
- [ ] `Alt+Space` QuickBar finds, copies (auto-clear), and types a login.
- [ ] `Ctrl+Alt+A` types `user{TAB}pass{Enter}` into Notepad.
- [ ] Card types number → TAB → MM → TAB → YY → TAB → CVV; identity types 4 fields.
- [ ] OTP screen auto-fills the live TOTP within 30s (hands-free chain).
- [ ] `Alt+S` on a login window opens capture with app + username prefilled.
- [ ] Typing into `chr0me.exe` (typosquat) is REFUSED with the spoof toast.

## 6. Shamir 3-of-5 Disaster Recovery (EFF Word Shards)
- [ ] Generate recovery sheet → 5 shards print/export.
- [ ] Any 3 shards reconstruct; any 2 fail.
- [ ] Lock-screen "Recover via Shards" restores vault access.
- [ ] Tampered shard reconstructs WRONG (loud failure, never silent).

## 7. Anti-Screen Capture (`WDA_MONITOR` vs `0` Live Toggle)
- [ ] Blackout ON: Snipping Tool / OBS / Discord preview shows pitch black.
- [ ] Blackout OFF (default): screenshots work normally.
- [ ] Toggle applies instantly without moving the window.
- [ ] Integrity banner appears after a rebuild; deleting `exe_integrity.dpapi` re-seals it.

## 8. App PIN Quick-Unlock (DPAPI-Bound, 5-Strike Wipe)
- [ ] Settings → set 4–8 digit PIN; lock screen gains the PIN button.
- [ ] Correct PIN unlocks (same pipeline: backoff, migration, gates apply).
- [ ] 4 wrong PINs show countdown errors; the 5th wipes `pin.dpapi` (PIN button vanishes, master still opens).
- [ ] Wrong PIN on a foreign machine fails (DPAPI machine-bound); AND-mode refuses PIN-first.
- [ ] Factory reset shreds `pin.dpapi` + `pin_attempts.dpapi`.

## 9. Factory Reset (Triple-Gate) & Onboarding
- [ ] Settings Danger Zone + lock-screen link both open the modal; decoy refuses everywhere.
- [ ] Wrong password / missing DELETE blocks arming; 5s countdown runs; Cancel aborts cleanly.
- [ ] Confirm shreds vault + generations + decoy + DPAPI seals; UI lands on clean onboarding; staged imports are purged.
- [ ] Fresh run: 3-step carousel (shard checkbox gates step 3); first unlock shows the one-shot recovery-sheet banner once.

## 10. List, Bulk Ops & Favicons
- [ ] 120+ item vault: first 50 render, `Load 50 More` grows the window, counter reads `Showing X of Y`; new search resets to 50.
- [ ] ☑️ Select mode: Favorite All / Move / Trash in one toast; selection clears on lock; kind-8 Trash deletes permanently (no trash generation).
- [ ] Favicons appear after unlock (disk-cached thereafter; airplane mode still shows them); toggle OFF restores letter icons; 🖼️ override replaces a logo, 🧹 Clear restores fetched.
- [ ] Column 3 shows grouped cards only (no floating modal); empty state reads `🛡️ Select an item…`; `↑↓` cycles, `/` focuses search, `Esc` deselects.

## 11. Browser Extension End-to-End
- [ ] YouTube/Google search bars never get badges or dropdowns.
- [ ] React signup (fetch POST, no form submit) still raises the save prompt; `__pv_pending` stays `null` in page JS.
- [ ] Right-click → Generate fills + confirms; OTP inject shows the `✅ 2FA filled` toast.
- [ ] Locked desktop → popup shows 🔒 instantly (no 10s hang); per-site never-suggest silences one domain only.
- [ ] Popup: recent-use order, 2FA pills, `👤 User` copy, empty-state inline save form.

## 12. Import Dry-Run, QuickBar TOTP & Changelog
- [ ] Picking an export shows counts/dupes in Preview; Cancel merges nothing; Confirm merges + offers source shred.
- [ ] QuickBar ⏱️ copies a fresh live code (standalone + embedded); reprompt-gated logins detour to the modal.
- [ ] Update available → `📋 What's New` shows release notes → Download & Stage → Restart swaps.

---

**Sign-off:** tester __________ date __________ commit __________ (all boxes checked)
