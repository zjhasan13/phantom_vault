# PhantomVault Release Certification — Physical QA Checklist

> All 12 tests must pass on a clean Windows 10/11 64-bit machine before any
> release is tagged. Check each box only after PHYSICAL verification.
> Baseline: `cargo check` zero-warning + `cargo test` 409 passed / 1 ignored (2026-10-13).

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
- [ ] Tampered shard → combine errors loudly, unlock blocked (never a wrong secret).

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
- [ ] Factory reset shreds `pin.dpapi` + `pin_attempts.dpapi` + `ext_pin.dpapi` (Extension PIN).

## 8b. Extension PIN (Desktop-Owned, Verify-Only)
- [ ] Settings → Extension PIN set/remove flips the status readout; extension never offers PIN setup.
- [ ] Trimmed compare: leading/trailing spaces don't break unlock; re-armed retry after wrong PIN.
- [ ] Decoy mode refuses set/remove; lock-screen PIN pad and extension PIN are independent systems.

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
- [ ] P1 REGRESSION (closed-app serving): quit the desktop app fully (no tray) → popup shows lock with "desktop app closed" (never suggestions); reopen + unlock → Retry reopens data.
- [ ] Quick-unlock PIN: set 4–8 digit PIN in desktop Settings → wait out the inactivity timeout → popup shows PIN card (not desktop card); wrong PIN = red error + button stays alive; correct PIN opens + restarts the idle clock. Remove PIN in desktop → PIN card never appears.
- [ ] Auto-lock timeout: Settings 5m/10m/15m/Never persists across popup reopens; `Never` never shows the inactivity card.
- [ ] Eye reveal: 👁️ shows plaintext, second click re-masks, 15s auto-remask fires; reprompt rows confirm first.
- [ ] Generator: 🎲 panel toggles, length/symbols persist, Copy works; panel close re-masks output.
- [ ] Health icons: audited vault rows show ♻️/🕰️/🟡/🔴 matching the desktop audit kinds; no-login-fields page Fill says so instead of silently closing.
- [ ] Verified badge: 3rd fill on one login flips ✅ (single re-seal); "Mark as working" toggles both ways instantly; decoy refuses the toggle.
- [ ] Favicons: visit an uncached site → desktop list shows its icon on next rebuild (extension harvest → disk cache); offline shows letters; kill-switch stops all fetches.

## 11b. 2FA Auto-Fill: Multi-Box, Ranking & Ambiguity Picker
> Invariants under test: never auto-submit (user clicks submit), never auto-pick
> when ambiguous, never ship a code with <3s left, never send raw secrets to the
> page.

- [ ] Multi-box (6 digit, Google/Stripe shape): visit a 6×`maxlength=1` ceremony → all six boxes fill hands-free with `⚡ 2FA code auto-filled`; the page accepts the code WITHOUT any manual paste.
- [ ] Multi-box order is correct (not rotated/reversed): compare box 1-6 against the desktop hub code for the same account.
- [ ] Multi-box is detected BEFORE single-box: a group whose box 0 carries `autocomplete="one-time-code"` still distributes per-digit (never the whole string in box 0).
- [ ] 4-digit and 8-digit split groups fill correctly; a single `maxlength="6"` / `autocomplete="one-time-code"` box still receives the whole code.
- [ ] False-positive guard: a page with 1-3 one-char inputs (quantity stepper, expiry year) is NOT treated as a split OTP group.
- [ ] Hands-free single match: one 2FA account for the site → fills immediately with NO popup interaction and NO picker.
- [ ] AUTO-SUBMIT REFUSED: after auto-fill the page is still waiting — no `requestSubmit`, no Enter is synthesised; the user must click the site's own Verify button.
- [ ] AMBIGUITY GUARD: two 2FA accounts for the same site → NO auto-fill; only the hint toast, and the page's boxes stay empty.
- [ ] Popup fallback: `🔑 Fill 2FA code` with multiple matches lists the candidates in the popup; clicking one fills that account and closes the popup.
- [ ] Inline picker (explicit `PV_FILL_OTP`): renders below the OTP box, dark theme, Esc and outside-click both dismiss it.
- [ ] Picker badges: `✅ Working` on a verified account, `⚠️ DUP` on a colliding (issuer+account) pair, `Primary` on a clean rank-1 row.
- [ ] DUP forces a choice: two accounts sharing issuer+account ⇒ both flagged, picker shown, nothing auto-filled.
- [ ] Ranking: an exact-issuer account outranks a substring account for the same site even when the substring one is stored FIRST in the vault.
- [ ] Empty issuer on an account never makes it match every site.
- [ ] Freshness guard: fill within the last 3s of the window ⇒ nothing is injected, toast says when to retry (no dead/rejected code sent).
- [ ] HOTP card in the hub shows no countdown and fills (no expiry guard applied to counter-based codes).
- [ ] Non-default accounts: an 8-digit TOTP and a 60s-period TOTP both produce a code their own site accepts (per-account digits/period/algorithm honoured).
- [ ] Verified badge on a 2FA account: 3rd fill seals it (single re-seal), `✅ Working` appears in the picker, manual un-verify sticks.
- [ ] No secret leakage: page/extension devtools + `pv_ext_stats.json` contain codes/counts but no `secret` field anywhere.
- [ ] Regression: login autofill + card + identity + generator + QuickBar all behave exactly as before this change.

## 12. Import Dry-Run, QuickBar TOTP & Changelog
- [ ] Picking an export shows counts/dupes in Preview; Cancel merges nothing; Confirm merges + offers source shred.
- [ ] QuickBar ⏱️ copies a fresh live code (standalone + embedded); reprompt-gated logins detour to the modal.
- [ ] Update available → `📋 What's New` shows release notes → Download & Stage → Restart swaps.

## 13. Zero-Knowledge GitHub Sync (Private Repo)
- [ ] Fresh repo first push: 404 takes the create path (no error); repo gains only `vault.enc` ciphertext + generic `chore: vault sync` message.
- [ ] Conflict: remote changed elsewhere → push refuses with "pull first" (never blind-overwrites); pull → merge → push succeeds.
- [ ] Token: DPAPI-sealed `github_token.dpapi`, never logged; proxy env routes both sync + HIBP (Tor-compatible).
- [ ] Oversize/corrupt remote (>48MB, bad base64) fails loud with guidance, never half-merges.

---

**Sign-off:** tester __________ date __________ commit __________ (all boxes checked)
