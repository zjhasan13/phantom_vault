# A27 — native-host pairing (design, not shipped)

Status: **design only**. Tracked as open item 3 in `docs/baki kaj.md`.
Owner batch: ~2–3 days (Rust + extension + tests + one manual browser pass).

## 1. The gap

Today the native host authenticates the *caller's argv[1] string* against the
registered manifests (`origin_allowed`, `native_host.rs:179`; launch gate
`is_native_host_launch`, `main.rs:139`). Both values are public: the extension id
sits in `native-host-chrome.json` / `native-host-firefox.json` on disk.

So any **same-user process** can run

```
phantom_vault.exe chrome-extension://<registered-id>
```

and speak the native-messaging protocol on stdin/stdout. What still stands
between that process and vault data:

- the Windows Hello token + heartbeat (`vault_hello.dpapi`,
  `vault_heartbeat.json`, 75 s max age) must be fresh,
- reprompt-armed items and the extension PIN (Argon2id + file lockout),
- the 60 s host idle TTL (`HOST_IDLE_TTL_SECS`),
- the audit log.

None of those prove *who* is calling. A process that spawns the host during an
unlocked session gets the same answers as the extension.

## 2. Goal / non-goals

Goal: make "know the extension id" insufficient. Raise the cost from *spawn and
talk* to *must hold a secret that only the paired extension has*.

Non-goals (state these in `SECURITY.md`):

- not a defence against a same-user process that already reads
  `chrome.storage.local` (LevelDB in the Chrome profile) or DPAPI-unseals as the
  same user — that process can steal the pairing secret the same way,
- not a defence against code injected into the browser process,
- not a replacement for the Hello/PIN/reprompt gates; it is a fourth layer.

## 3. Design — three layers

### L1. Spawn provenance (no user step)

At host start, before any frame is read:

1. `GetCurrentProcessId` → Toolhelp32 `TH32CS_SNAPPROCESS` → parent PID.
2. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` →
   `QueryFullProcessImageNameW` → parent image path.
3. `WinVerifyTrust` on that path (the updater already links the same API) and
   match the signer against an allow-list of browser publishers.
4. Optional extra signal for Chromium: argv contains `--parent-window=`.

Accept `chrome.exe`, `msedge.exe`, `brave.exe`, `firefox.exe` **with a valid
Authenticode signature from the expected publisher**. Release builds fail closed
(`origin not allowed` frame, exit 2) when the check fails. Debug builds keep the
existing `native-host` bypass for dev ergonomics.

Limits: PID reuse is possible in theory (read the parent before it exits);
a renamed binary fails the signature check; injection into a real browser is out
of scope. This layer alone stops the naive "spawn it myself" attack.

### L2. Pairing secret (one-time, user-mediated)

Bootstrap is user-mediated because there is no out-of-band channel yet.

1. Desktop app: **Settings → Browser extension → Pair extension** mints 32
   CSPRNG bytes, shows them as 8 groups of 4 Crockford-base32 characters
   (e.g. `K7Q2-9F3M-...`), and stores a DPAPI-sealed copy in
   `<vault dir>\host_pairing.dpapi`. The displayed code expires after 10 min and
   is never logged.
2. Popup: **Pair with desktop** asks for the code, stores the decoded 32 bytes in
   `chrome.storage.local.pv_pair_secret` (base64), then sends `pair_confirm`
   (below). A wrong code fails the MAC and the popup says so.
3. Every later frame carries `seq`, `ts` and `mac`:

```json
{"cmd":"list","seq":7,"ts":1763000000,"mac":"<hex hmac-sha256>"}
mac = HMAC-SHA256(secret, "pv1|" + cmd + "|" + seq + "|" + ts + "|" + sha256(canonical_body))
```

Host rules: constant-time compare; `seq` strictly increasing per session;
`|now - ts| <= 60 s`; reject and audit-log `host mac rejected` on any miss. The
response carries the same MAC shape so the extension can detect a fake host.

`pair_confirm` binds both directions:

```
ext -> host: {"cmd":"pair_confirm","ext":"<id>","nonce":"<hex32>","mac":HMAC(secret,"pair-confirm|"+ext+"|"+nonce)}
host -> ext: {"ok":true,"host_nonce":"<hex32>","mac":HMAC(secret,"pair-ok|"+ext+"|"+host_nonce)}
```

Unpair wipes `host_pairing.dpapi` and `chrome.storage.local.pv_pair_secret`.

### L3. Existing gates stay

Hello token, heartbeat, reprompt, extension PIN, idle TTL and the audit log are
unchanged. L1/L2 are additive.

## 4. Rollout

- **Step 1 (warn-only):** ship L1 + L2 with a Settings banner when unpaired. The
  host still serves unpaired callers and audit-logs `host unpaired`.
- **Step 2 (hard require):** one release later, refuse unpaired frames in release
  builds. This is the step that actually closes the gap; step 1 only prepares it.
- A paired extension keeps working across host updates because the secret lives
  in the vault dir, not in the binary.

## 5. Files and tests

| Area | Where |
|---|---|
| Parent check + MAC verify | `src/windows_native/native_host.rs` (`serve_cli`, `origin_allowed` neighbours) |
| Secret mint/store | `src/main.rs` (Settings callback) + new `src/security/host_pairing.rs` |
| Popup pairing UI | `browser_extension/popup.js` / `.html` |
| Per-frame MAC | `browser_extension/background.js` (`hostRequest`) |
| Rust tests | `host_pairing::tests` — canonical input stability, wrong seq/ts/mac, constant-time compare, DPAPI round-trip, parent allow-list |
| JS tests | `tests/js/background.test.mjs` — MAC added to every frame; missing secret refuses; fixture vector shared with Rust (same pattern as `EQUIV_CLUSTERS`) |
| Docs | `SECURITY.md` limitations, `docs/A23_LOCAL_API.md` neighbour note, `docs/FEATURE_LEDGER.md` |

Manual verification is required in a real Chrome and a real Firefox (spawn with
`--parent-window` vs add-on id) — this cannot be automated on this machine.

## 6. Effort

- L1: ~½ day including tests (process snapshot + signature check + negatives).
- L2: ~1½ days (Rust store + MAC, JS MAC, popup UI, fixtures).
- Docs + manual browser pass: ~½ day.
- Risk: a false negative in L1 breaks the extension completely, so step 1 ships
  warn-only and logs the rejection reason before step 2 enforces.

## 7. Open questions

1. Hard-require pairing in the same release as L1, or the release after?
2. MAC the responses as well, or requests only? (Cost is one HMAC per frame.)
3. Accept Edge/Brave by publisher signature, or Chrome + Firefox only?
4. Is a QR-based pairing (desktop shows a QR with the secret) better UX than a
   typed 32-character code? QR needs a camera path on the extension side.
