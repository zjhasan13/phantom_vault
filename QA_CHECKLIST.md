# PhantomVault Release Certification — Physical QA Checklist

> All 7 tests must pass on a clean Windows 10/11 64-bit machine before any
> release is tagged. Check each box only after PHYSICAL verification.
> Baseline: `cargo check` zero-warning + `cargo test` 233 passed / 0 failed.

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
- [ ] 2FA Hub shows the 2-column card grid (no stretched single card, no black void).
- [ ] Countdown rings tick every second with violet → orange → red shift.
- [ ] `Next:` preview matches the following code; Copy works.
- [ ] HOTP cards show the HOTP badge and `Next Code` advances the counter.
- [ ] Steam accounts render 5-character codes.
- [ ] Hub search filters ONLY 2FA cards (vault list untouched).

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

---

**Sign-off:** tester __________ date __________ commit __________ (all boxes checked)
