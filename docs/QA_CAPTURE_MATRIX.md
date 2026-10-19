# QA Matrix — Extension Capture Engine (Tier 0)

> Manual regression matrix for the Tier 0 credential-capture work. Run against
> the built extension (`browser_extension/build.ps1` → `dist/chrome` or
> `dist/firefox`), with the desktop app unlocked. Record Pass/Fail in §4.
>
> Automated coverage: `npm test` (25 tests: 19 background + 6 content/jsdom).
> These manual cases cover the real-browser behavior jsdom cannot (navigation,
> SPA routing, native bridge round-trips).

## 1. Preconditions

1. `.\browser_extension\build.ps1` succeeds.
2. Load `browser_extension/dist/chrome` unpacked (or Firefox temp add-on).
3. Desktop PhantomVault is running and **unlocked** (bridge reachable).
4. Start from a clean vault state where noted (no existing entry for the site).

## 2. Functional matrix

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| CAP-01 | Baseline login save (no regression) | Site with username+password → fill → submit | "🛡️ Save to PhantomVault?" banner appears; Save stores it |
| CAP-02 | Signup, single new-password (G1) | A signup form with `autocomplete=new-password` only → type email+password → submit | Save banner appears (previously **silent**) |
| CAP-03 | Signup, confirm-password match (G3) | password + confirm, both equal → submit | Save banner appears once; one entry saved |
| CAP-04 | Signup, confirm-password **mismatch** (G3) | password ≠ confirm → submit | **No** banner (typo guard) |
| CAP-05 | Multi-page signup (K1) | Page 1: enter email → Next/Submit. Page 2: enter password → submit | Page 2 save banner uses the page-1 email as the username |
| CAP-06 | Multi-page carry is non-secret (P1-b) | DevTools → Application → Session Storage / `chrome.storage.session` during CAP-05 | `pvCaptureCarry` holds `{base, username, at}` only — **no password field** |
| CAP-07 | SPA login (C2) | React/Google-style login that POSTs via fetch, no `<form>` submit | Banner appears promptly (no 2.5 s dead wait), survives the route change |
| CAP-08 | Full-page POST nav (C1) | Classic form POST that navigates immediately | Banner shown before navigation commits (warm cache) |
| CAP-09 | Known credential silent | Log in again with the exact stored username+password | **No** banner |
| CAP-10 | Update prompt | Same username, new password | "🔄 Update existing?" banner; Update rotates, old kept in history |
| CAP-11 | Change-password form (G3) | current-password + new-password → submit | Update flow uses the **new** password value |
| CAP-12 | Search box immunity | Submit a search/`role=search` form | No banner, no carry written |
| CAP-13 | No duplicate prompts | Submit, then let the SPA retry fire | Exactly one banner |
| CAP-14 | Blocked-domain gate | Add the site to `blocked_domains` → submit login | No banner, no native call |
| CAP-15 | Phishing/guard gate | Craft a blocked/phishing host → submit | No banner |
| CAP-16 | Save invalidates cache | Save a login, then submit the same credentials again in the same tab | Silent (known) — stale "new" prompt must not recur |

## 3. Regression matrix (must stay working)

| ID | Scenario | Expected |
|---|---|---|
| REG-01 | OTP cross-navigation fill | After step-1 fill, the 2FA page still auto-fills / offers the picker |
| REG-02 | Multiple 2FA accounts | Picker opens on OTP field; choosing a row fills it |
| REG-03 | Password fill from badge/dropdown | Still fills username+password |
| REG-04 | Hotkey fill (`Ctrl+Shift+L`) | Still fills |
| REG-05 | Passkey ceremony | Still relays via desktop approval |
| REG-06 | Desktop lock mid-ceremony | Bridge calls fail closed; no stale banner |

Regression rationale: Tier 0 must not touch `pvPending`,
`chainPendingStep`, `sweepOtpOnce`, `otpObserver`, the popup fill path, or the
native host — any failure here is a signal that a capture change leaked into
the OTP engine.

## 4. Result log

| ID | Build/commit | Date | Pass/Fail | Notes |
|---|---|---|---|---|
| CAP-01 | | | | |
| CAP-02 | | | | |
| CAP-03 | | | | |
| CAP-04 | | | | |
| CAP-05 | | | | |
| CAP-06 | | | | |
| CAP-07 | | | | |
| CAP-08 | | | | |
| CAP-09 | | | | |
| CAP-10 | | | | |
| CAP-11 | | | | |
| CAP-12 | | | | |
| CAP-13 | | | | |
| CAP-14 | | | | |
| CAP-15 | | | | |
| CAP-16 | | | | |
| REG-01 | | | | |
| REG-02 | | | | |
| REG-03 | | | | |
| REG-04 | | | | |
| REG-05 | | | | |
| REG-06 | | | | |

## 5. Suggested fixtures

- **Classic login:** any site with `input[name=username]` + `input[type=password]`.
- **Signup:** a site using `autocomplete="new-password"` (e.g. modern account
  creation forms).
- **Multi-page:** FxA-style email-step → password-step.
- **SPA/fetch login:** a React login that never fires `<form>` submit.
- **Change-password:** account settings → change password (current + new).
