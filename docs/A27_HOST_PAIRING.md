# A27 — native-host pairing (shipped, one gap left)

Status: **shipped except one documented non-goal**. L1 is complete:
`src/windows_native/host_provenance.rs` resolves the parent image, matches it
against a browser allow-list, and `src/windows_native/authenticode.rs` verifies
its Authenticode chain and signer (`WinVerifyTrust` +
`CryptQueryObject`/`CertGetNameStringW`). A release build refuses a spawn whose
parent is not a vendor-signed browser; debug builds log only. L2 is shipped end
to end: `src/security/host_pairing.rs` mints/seals the 20-byte secret, prints it
as a Crockford code, and verifies a MAC + seq + ts on every frame; the desktop
shows the code in **Settings → Sync & Devices → Extension pairing**
(`Show pairing code` / `Revoke pairing`); the popup stores the decoded bytes,
answers `pair_confirm`, and **verifies the MAC on every reply**; a release build
refuses unverified frames (`enforce_pairing = !cfg!(debug_assertions)`).
Remaining limit (documented, not a bug): a same-user process that can read
`chrome.storage.local` or DPAPI-unseal the secret still wins, and revocation is
not checked at host start. See §3 L1 "Limits".

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
3. File-name allow-list: `chrome.exe`, `msedge.exe`, `brave.exe`, `firefox.exe`,
   `chromium.exe`, `vivaldi.exe`, `opera.exe`.
4. `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, no UI, cache-only URL
   retrieval, `WTD_REVOKE_NONE`) on that path — the embedded signature must chain
   to a trusted root in the local store.
5. `CryptQueryObject` → `CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)` →
   `CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT)` → `CertGetNameStringW`
   — the signer's simple display name must match the browser's vendor token
   (`chrome.exe` → `google`, `msedge.exe` → `microsoft`, `firefox.exe` →
   `mozilla`, `brave.exe` → `brave`, `chromium.exe` → `google`/`chromium`,
   `vivaldi.exe` → `vivaldi`, `opera.exe` → `opera`). Token, not exact subject:
   certificate names drift, and an unknown vendor is refused with its name in the
   log so the table is one line to extend.

Release builds fail closed — an `err` frame naming the problem and exit 2 — for
*not a browser*, *unsigned*, *untrusted chain*, *wrong publisher* and *probe
failed*. Debug builds log `WARN release build would refuse this spawn: …` so a
dev loop can still spawn the host by hand.

**Escape hatch.** `PV_ALLOW_UNSIGNED_BROWSER=1` in the host's environment lets a
*missing* signature through (LibreWolf, ungoogled Chromium, a self-built browser)
and is audit-logged every time. It does not cover a broken chain or a wrong
publisher. Be honest about what it costs: a same-user process that spawns the
host can set the variable itself, so the hatch is only useful for a user who
deliberately runs an unsigned browser. L2 is what still protects that user.

Limits (state them in `SECURITY.md`):

- **Revocation is not checked.** `WTD_REVOKE_NONE` plus
  `WTD_CACHE_ONLY_URL_RETRIEVAL` keeps host start offline and instant; a
  revoked-but-cached certificate therefore passes.
- A copy of a real `chrome.exe` (same bytes, same signature) in another folder
  passes. L1 stops *spawn and talk*, not a determined attacker.
- PID reuse is possible in theory (read the parent before it exits).
- Injection into a real browser is out of scope.
- Non-Windows builds report `Unsigned`; the check is a Windows-only layer.

### L2. Pairing secret (one-time, user-mediated)

Bootstrap is user-mediated because there is no out-of-band channel yet.

1. Desktop app: **Settings → Browser extension → Pair extension** mints a
   **20-byte (160-bit)** CSPRNG secret, shows it as 8 groups of 4 Crockford-base32
   characters (e.g. `K7Q2-9F3M-...` — 32 characters total), and stores a
   DPAPI-sealed copy in `<vault dir>\host_pairing.dpapi`. The displayed code
   expires after 10 min and is never logged.
   - *Correction (2026-11-14):* the first draft said "32 CSPRNG bytes / 8 groups
     of 4". 8×4 = 32 characters = 160 bits, so the secret is 20 bytes. A 32-byte
     secret would need 52 characters.
2. Popup: **Pair with desktop** asks for the code, stores the decoded 20 bytes in
   `chrome.storage.local.pv_pair_secret` (base64), then sends `pair_confirm`
   (below). A wrong code fails the MAC and the popup says so.
3. Every later frame carries `seq`, `ts` and `mac`:

```json
{"cmd":"list","seq":7,"ts":1763000000,"mac":"<hex hmac-sha256>"}
mac = HMAC-SHA256(secret, "pv1|" + cmd + "|" + seq + "|" + ts + "|" + sha256(canonical_body))
```

Known-answer vector for both sides (secret = bytes `00..13`, cmd `list`, seq `7`,
ts `1763000000`, body `{"cmd":"list"}`):

```
sha256(body) = 85b05f70b28a753f0b412901675f7bae25d1dbe8044980044a083961e76215c2
mac          = bb99f3bb4a9c37e2113e8169f9abe64df76c86482022d9137137aeae1ae6113f
```

**What "canonical body" is, exactly.** Not a re-serialised JSON — that would
depend on key order on both sides. The body is the frame **without the `mac`
field**, byte for byte: the extension builds `{...request, seq, ts}`, stringifies
that once (this is the MAC input), then posts `{...request, seq, ts, mac}`.
`JSON.stringify` keeps insertion order, so the wire bytes are exactly `body`
with `,"mac":"…"` spliced in before the closing brace. The host removes that one
field from the raw line and MACs the remainder. `strip_mac_field` is the Rust
half and is unit-tested against frames with `mac` first, middle and last.

Host rules: constant-time compare; `seq` strictly increasing per session;
`|now - ts| <= 60 s`; reject and audit-log `host mac rejected` on any miss.

**Shipped `pair_confirm` (2026-11-15b) is simpler than the draft above.** It is a
normal MACed frame — `{"cmd":"pair_confirm","seq":N,"ts":T,"mac":…}` — and the
reply is `{"ok":true,"paired":true}` or `{"error":"…"}`. It is answered before the
heartbeat/unlock gate because the reply carries no vault data, only the MAC
verdict, and the popup needs it while the desktop app is locked. The
`ext`/`nonce`/`host_nonce` handshake sketched below is **not implemented**; the
reply MAC that replaced it binds the request identity instead.

Not implemented (superseded):

```
ext -> host: {"cmd":"pair_confirm","ext":"<id>","nonce":"<hex32>","mac":HMAC(secret,"pair-confirm|"+ext+"|"+nonce)}
host -> ext: {"ok":true,"host_nonce":"<hex32>","mac":HMAC(secret,"pair-ok|"+ext+"|"+host_nonce)}
```

**Response MACs are shipped (2026-11-15c).** The host signs every reply as

```
HMAC(secret, "pv1r|" + req_cmd + "|" + req_seq + "|" + req_ts + "|" + sha256(canonical_reply))
```

and appends `"mac":"<64 hex>"` to the reply object. `canonical_reply` is the
reply JSON without `mac`, serialised with recursively sorted keys and integral
numbers printed without a fraction (`1.0` → `1`, which is what
`JSON.stringify` does). Both sides must sort, because Chrome's native-messaging
port hands the extension a **parsed object**, not raw bytes — the byte-exact
trick used for requests cannot work in this direction.

Rust: `host_pairing::canonical_json` + `reply_mac`; the host applies it with a
`SignedOut<W>` stdout wrapper, so the ~20 reply sites in `serve_cli` stay
unchanged — it re-encodes each complete frame once and passes everything through
when there is nothing to sign (no secret, or a request with no `seq`/`ts`).
JS: `canonicalJson` + `verifyReply` in `background.js`; a **signed request
demands a signed reply**, so a missing or wrong MAC rejects the promise and the
popup shows an error instead of the data. Shared known-answer vector
`4a0b4fe89bb5b65197d7c4e01af4bd58e370a247a5e629faabb59549e625ada8` is asserted in
both `host_pairing` and `tests/js/background.test.mjs`.

Why it matters: without reply MACs, a look-alike host could answer the popup with
fabricated items. With them, the popup only renders replies from a process that
holds the same 20 bytes. It does **not** stop a same-user process that can read
`chrome.storage.local` (see non-goals).

Unpair wipes `host_pairing.dpapi` and `chrome.storage.local.pv_pair_secret`.

### L3. Existing gates stay

Hello token, heartbeat, reprompt, extension PIN, idle TTL and the audit log are
unchanged. L1/L2 are additive.

### L4. PIN-gated session (strict mode, 2026-11-16)

The default build seals `vault_hello.dpapi` after a **PIN** unlock too (see
`SECURITY.md` → "PIN unlock and the browser bridge"), so the bridge normally
needs no extra step. Settings → Security → *Browser bridge after PIN unlock*
turns that off. In that mode the desktop writes no plain token, and the host
does not die with "no bridge credential":

- The first frame (typically `stats` or `ping`) is answered with
  `{ok:false, need:"pin"}` and the host **stays alive** on the same native port.
- The popup shows its lock overlay with an app-PIN field and sends
  `{cmd:"unlock_pin", pin}` (popup-only: a content script is refused, so a page
  cannot use the bridge as a PIN oracle).
- The host calls `crate::security::app_pin::verify_and_recover`, i.e. the same
  `pin.dpapi` record, the same Argon2id parameters and the same **5-strike**
  counter as the desktop unlock. A wrong PIN answers
  `{ok:false, need:"pin", remaining:N}`; the fifth shreds the sealed master and
  answers `{ok:false, wiped:true}`.
- No plain master ever touches disk. Liveness in this mode is the desktop
  heartbeat (`desktop_alive()`), because there is no token file to watch; a lock
  therefore stops serving within the heartbeat window instead of instantly.

The unsealed master lives only in the host process and is zeroized on exit, the
same as the Hello-token path.

## 4. Rollout

- **Step 1 (warn-only):** ship L1 + L2 with a Settings banner when unpaired. The
  host still serves unpaired callers and audit-logs `host unpaired`.
- **Step 2 (hard require):** one release later, refuse unpaired frames in release
  builds. This is the step that actually closes the gap; step 1 only prepares it.
  **Implemented (2026-11-15c):** `serve_cli` sets
  `enforce_pairing = !cfg!(debug_assertions)`, so a release build refuses the
  first unverified frame (and every later one) with an actionable message, while
  a debug build stays warn-only so a dev loop does not need a re-pair per build.
  `pair_confirm` is exempt: it is how a user pairs, and its reply carries only
  `{ok,paired}`.
- A paired extension keeps working across host updates because the secret lives
  in the vault dir, not in the binary.
- **L1 step 2 (spawn provenance, enforced):** release builds refuse a host
  spawn whose parent is not a vendor-signed browser (see §3 L1);
  `PV_ALLOW_UNSIGNED_BROWSER=1` is the documented hatch for unsigned browser
  forks and is audit-logged.

Shipped so far (L1 step 2 + step 1 + step 2 + response MACs): `Show pairing code`
/ `Revoke pairing` in **Settings → Sync & Devices → Extension pairing**,
`pair_confirm` answered before the heartbeat gate (the reply carries a MAC
verdict, no vault data), the popup's `Desktop pairing` row, signed replies that
the popup verifies, the Authenticode parent check, and `host mac rejected: <why>`
in the bridge log.

Two traps learned while wiring this:

- **The seal lives where the *host* looks, not where the app happens to run.**
  `pairing_path()` = `resolve_data_dir()` (the `project_dir.txt` marker under
  `%LOCALAPPDATA%\PhantomVault`) + `host_pairing.dpapi`. A stale marker (a dev
  install that recorded the repo root) silently split app and host across two
  different seal files, so the app now rewrites the marker at startup
  (`native_host::record_data_dir`). Portable mode moves the vault dir, and the
  marker follows it.
- **`pair_confirm` must be answered before the unlock gate.** The popup proves a
  typed code while the desktop may be locked; the reply is `{ok,paired}` or an
  error string, never vault content, so the gate stays where it is.
- **Replies cannot be MACed over raw bytes.** Requests can (`JSON.stringify`
  once, host strips `mac`), but Chrome delivers the reply as a parsed object, so
  key order and `1.0` vs `1` are lost. Both sides canonicalise instead
  (`host_pairing::canonical_json` / `canonicalJson`), and the shared vector keeps
  them honest.

## 5. Files and tests

| Area | Where |
|---|---|
| Parent check + MAC verify | `src/windows_native/native_host.rs` (`serve_cli`, `origin_allowed` neighbours) |
| Secret mint/store, request + reply MAC | `src/main.rs` (Settings callback) + `src/security/host_pairing.rs` (`canonical_json`, `reply_mac`) |
| Reply signing wrapper | `src/windows_native/native_host.rs` (`SignedOut`, `emit_err`) |
| Popup pairing UI | `browser_extension/popup.js` / `.html` |
| Per-frame MAC + reply verify | `browser_extension/background.js` (`signFrame`, `verifyReply`) |
| Rust tests | `host_pairing::tests` — canonical input stability, request + reply known-answer vectors, wrong seq/ts/mac, constant-time compare, DPAPI round-trip, parent allow-list |
| JS tests | `tests/js/background.test.mjs` — MAC added to every frame; missing secret refuses; reply accepted when signed, refused when unsigned/tampered/replayed; both vectors shared with Rust (same pattern as `EQUIV_CLUSTERS`) |
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
2. ~~MAC the responses as well, or requests only?~~ **Answered: responses are
   MACed** (2026-11-15c, `pv1r|…` over the canonical reply). Cost is one HMAC per
   frame, and it is what makes a look-alike host useless.
3. Accept Edge/Brave by publisher signature, or Chrome + Firefox only?
4. Is a QR-based pairing (desktop shows a QR with the secret) better UX than a
   typed 32-character code? QR needs a camera path on the extension side.
