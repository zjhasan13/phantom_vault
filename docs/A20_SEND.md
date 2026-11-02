# A20 — serverless expiring share (Send-style)

> Status: **slices 1–5 shipped.** Bundle crypto, on-disk TTL/one-view store,
> LAN/file transport, the `share` CLI, a desktop **Settings → Expiring
> shares** card (create/copy/open/preview/import/revoke), A20a's optional
> **recipient passphrase** (`PVSH2`) and **QR code**, plus A20b's async
> **GitHub secret-gist relay** (recipient needs no token). The pre-existing
> Phase 9 **Secure Send** card (notes via the GitHub relay) remains a separate
> surface; A20 is the item/bundle path.

## GUI (slice 3 + A20a + A20b)

Settings → **EXPIRING SHARES (SEND)**:

- type a login title, TTL (`24h`) and views (`0` = unlimited), choose **LAN**
  or **Async gist** (mutually exclusive), optionally toggle **Passphrase** and
  enter/confirm an 8+ character phrase, press **Create share**;
- the link (`pvshare://…`) appears once with a masked **Copy link** button and a
  **QR code** (the QR encodes the link only, never the bundle);
- **Open** accepts a `pvshare://…` link (LAN, gist, or file) or a `.pvsh` bundle
  file plus an optional passphrase, shows a title/username preview, then **Add
  to my vault** (duplicate-safe, saved with the vault master);
- active shares list with per-share **Revoke** (passphrase rows show `🔒 pass`,
  relay rows show `☁ gist`); revoking a relay share also deletes its gist
  (best-effort, needs the stored token). Revoking the last LAN share stops the
  LAN listener.

With a passphrase the link is `pvshare://<id>#p=1` (or
`pvshare://gist/<owner>/<gist_id>#p=1`) and contains **no key**; the key is wrapped
inside the bundle by Argon2id(passphrase). Without one, the link is the original
`#k=<key>` form.

Async gist uses the token stored by **Settings → GitHub Sync**; a classic PAT
must include the `gist` scope (fine-grained tokens generally cannot create
gists). No token is needed on the recipient side: a secret gist is unlisted but
readable by anyone who knows its id.

The older **Secure Send** card (seal a note → GitHub relay → read + burn) is
unchanged and still notes-only. Use it for async text; use Expiring shares for
logins over LAN/file/gist.

## CLI (slice 2 + A20a + A20b)

```powershell
# sender: creates pvshares/<id>.pvsh, prints a file link
phantom_vault share create "Gmail" --ttl 24h --views 1

# sender: passphrase-protected share; the link has no key
phantom_vault share create "Gmail" --ttl 24h --views 1 --passphrase

# sender: async relay — secret gist, recipient needs no token
phantom_vault share create "Gmail" --ttl 24h --views 1 --relay gist
phantom_vault share create "Gmail" --ttl 24h --views 1 --relay gist --passphrase

# sender: also serve the ciphertext on the LAN, print pvshare://<ip>:<port>/<id>#k=…
phantom_vault share create "Gmail" --ttl 24h --views 1 --serve

# recipient: fetch over the link or read a bundle file
phantom_vault share open "pvshare://192.168.1.5:52123/<id>#k=…"
phantom_vault share open "pvshare://gist/<owner>/<gist_id>#k=…"
phantom_vault share open "pvshare://<id>#p=1" --file pvshares/<id>.pvsh
phantom_vault share open "…" --import          # prompts master, adds the login

phantom_vault share list
phantom_vault share revoke <id>   # also deletes the gist when present
```

`--passphrase` prompts twice (no echo, trimmed) before creating the share. A
`#p=1` link prompts for the passphrase on open; a missing or wrong passphrase
fails closed with a generic "wrong passphrase or corrupt bundle". `--relay gist`
and `--serve` are mutually exclusive.

One-view/TTL are enforced by the **sender's store** (`take()` increments views
before returning bytes; expiry deletes the bundle). The listener has no pairing
auth **by design** — the id is 128-bit random and the key never reaches it; the
bundle is already end-to-end encrypted. This is separate from A15 vault sync.

## Goal

Share one or more vault items with someone who does not have PhantomVault's
vault, using an **expiring** link where the relay never sees the key. LAN is
one-view; file and gist transport are expiry-only/best-effort.

```
pvshare://<share-id>#k=<base64url 256-bit key>     <- key lives in the fragment
<encrypted bundle>                                  <- any transport: P2P/file/GitHub
```

## Slice 1 (shipped): bundle format + crypto

- `PVSH1 | nonce(24) | XChaCha20-Poly1305(ciphertext+tag)`.
- Random 32-byte key per share (no password, no Argon2 — there is no user secret
  to stretch; the key is high-entropy and single-use).
- Plaintext is JSON `{version, created, expires_at, max_views, items}` padded to
  a **4 KiB bucket**, so the bundle size does not reveal field count/length.
- `items`: kind/title/username/password/url/notes/totp/custom fields (slice 1
  shape; attachments and passes are later).
- `create()` refuses empty item lists and `ttl_secs == 0`; `open()` rejects
  wrong keys, tamper, truncation, unknown versions and expired payloads.
- `CreatedShare::link()` returns `pvshare://<id>#k=<key>`; `parse_link()`
  rejects any link without a key fragment.
- Zeroization: bundle plaintext, the decoded key and the derived key are wiped
  after use.
- Tests: roundtrip, key-never-in-blob, wrong key/tamper/truncation, expiry,
  padding stability, link parsing.

## Slice 2 (shipped): store + LAN/file transport

- `src/share_store.rs`: `pvshares/<id>.pvsh` + `<id>.meta.json` (expiry,
  `max_views`, `views`). `take()` checks expiry/views and increments `views`
  **before** returning the bundle, so a crash cannot grant an extra view;
  expiry deletes the files. `revoke()` deletes both; `purge_expired()` sweeps.
- `src/share_serve.rs`: `GET /<id>` returns the ciphertext once (per the store),
  `GET /health` for liveness. Bound to `0.0.0.0:0` for LAN or loopback for
  tests. **No pairing/auth by design**: the id is 128-bit random and unguessable,
  the key never appears in the request, and the bytes are already encrypted.
  This endpoint is separate from the A15 vault-sync surface.
- `src/share_cli.rs`: `share create|serve|open|list|revoke`. `create` prompts the
  vault password, finds one login by title, builds the item, stores it and prints
  the file link; `--serve` starts the LAN listener and prints
  `pvshare://<ip>:<port>/<id>#k=…`. `open` fetches (or reads `--file`), decrypts,
  prints a preview, and `--import` adds the login (skipping title+username
  duplicates) with a password-confirmed save.
- Tests: store one-view/expiry/unlimited/revoke; real loopback serve (first 200,
  second 404, health, revoked 404); link forms (file + LAN); bundle tests above.

## Slice 4 / A20a (shipped): optional recipient passphrase + QR

Two independent gaps closed:

1. **Passphrase** — the sender may protect the share so the link alone is not
   enough. The bundle becomes `PVSH2`:

   ```
   magic "PVSH2" (5) | flags (1) = 0x01 | salt (16)
   | wrap_nonce (24) | wrapped_key (48 = 32-byte key + 16-byte tag)
   | payload_nonce (24) | payload ciphertext+tag
   ```

   - `wrapped_key = XChaCha20-Poly1305(Argon2id(passphrase, salt, 64 MiB, t=3,
     p=4), key)`; the payload is then sealed with the random `key` exactly as
     in `PVSH1`.
   - The link carries only `#p=1`; the passphrase never enters the bundle or
     the link. `open()` derives the KEK, unwraps the key, decrypts the payload,
     and wipes the KEK/key buffers.
   - `PVSH1` is unchanged and still opens with `#k=<key>`; the opener detects
     the magic and only requires a passphrase for `PVSH2`.
   - Passphrases are trimmed at every entry point (CLI, UI, library) so a stray
     space cannot make a share unopenable. The UI enforces 8+ characters and a
     matching confirmation; the library only rejects empty/whitespace.
   - A `#k=` fragment cannot bypass a `PVSH2` bundle: the fragment key is
     ignored for `PVSH2` and only the wrapped key is used.
   - Flags are exact: any value other than `0x01` is rejected (forward-safe).

2. **QR** — the create card renders the link as a QR code using the existing
   `qr_svg` generator (same one as A15 pairing). The bundle is ~4 KiB (padding
   bucket), far above QR capacity, so **only the link is encoded**; the bundle
   still travels over LAN/file. The temporary SVG path is content-tagged so a
   second share does not show the first QR from Slint's image cache.

Honest limits: a weak passphrase is brute-forceable offline (the bundle is a
valid verifier); Argon2id raises the cost but does not fix a bad secret. The
passphrase must reach the recipient over a channel different from the link
(otherwise it adds no protection). QR is a convenience, not a confidentiality
boundary — anyone who photographs it gets the link.

## Slice 5 / A20b (shipped): async relay via GitHub secret gist

The recipient may be offline/behind NAT, so the LAN transport cannot work. The
sender can publish the **already-encrypted** bundle to a **secret (unlisted)
gist**:

- one gist per share; one fixed file `bundle.pvsh.b64` whose content is the
  base64 of `PVSH1`/`PVSH2` (max 64 KiB of ciphertext);
- link: `pvshare://gist/<owner>/<gist_id>#k=<key>` or `#p=1`; the gist id is
  random hex and the key stays in the fragment. The owner login is included
  because it enables a **tokenless raw fetch**
  (`gist.githubusercontent.com/<owner>/<id>/raw`), which keeps working even
  when the GitHub API requires auth to read a secret gist's metadata;
- publish/delete use the token already stored for **GitHub Sync** and require
  the classic `gist` scope; fetching needs **no token** (raw gist host, with
  the API as a no-owner fallback). A secret gist is unlisted, not
  private-by-ACL;
- GitHub only ever sees ciphertext, a generic description (`PhantomVault
  share`), a fixed filename, and the sender's account identity. The link
  itself includes the owner login so the recipient can use the raw host;
- `share revoke` and the GUI **Revoke** delete the gist best-effort; the local
  metadata keeps `relay_gist` so an expired relay share is **not** purged
  locally (the gist does not auto-expire, so the sender must still revoke);
- **honest limit:** TTL/one-view are *not* relay-enforced. Recipients can
  re-fetch until the delete lands, so the view budget is forced to `0`
  (unlimited) on this transport and the UI disables the Views field; the CLI
  warns and does the same. This is labelled "expiring (best-effort)", never
  "one-time".

Testing uses a loopback mock GitHub API (`PV_RELAY_API`) and a test-only token
override; no network or real credentials are needed. The production endpoint is
`https://api.github.com` and honours the same proxy variables as sync.

## Threat model (honest)

| Threat | Mitigation / limit |
|---|---|
| Relay/storage sees the blob | only ciphertext; the key is in the URL fragment (never sent in HTTP requests) |
| Relay sees the key | impossible **iff** clients put it only in the fragment; a user pasting the full link into chat does share the key with that channel |
| Passphrase-protected share (`PVSH2`) | link alone is useless; the key is wrapped with Argon2id(passphrase). Offline guessing is possible — strength depends on the passphrase |
| Passphrase + link sent together | protection collapses to the original link-only model; send them over different channels |
| QR code photographed/shared | same as leaking the link; the QR never contains the bundle, and for `PVSH2` it never contains the key |
| GitHub gist relay | only ciphertext + generic metadata; the key is in the fragment. The gist owner's GitHub identity is visible to GitHub and is included in the link (needed for the tokenless raw fetch); a secret gist is unlisted, not private-by-ACL |
| Gist TTL / one-view | **not enforced by GitHub**. Deletion happens only when the sender revokes; an expired relay share is kept locally so it can still be deleted. A recipient can re-fetch until then |
| GitHub token | publish/delete need a classic PAT with `gist`; the token is DPAPI-sealed and never logged. A missing scope fails with a clear error, not a silent fallback |
| Unauth recipient fetch | raw gist host availability applies; the no-owner API fallback is rate-limited (60/hour per IP). Failures are reported, never replaced with stale data |
| Link leaked before expiry | anyone with the link can open it until TTL/one-view is enforced |
| Recipient copies after opening | unavoidable — "one view" is not DRM |
| Clock manipulation | expiry uses the recipient's local clock; a modified client can ignore it |
| Revocation | delete the blob; already-downloaded copies cannot be revoked |
| Phishing / auto-open | links must never auto-import; show a preview of what will be added |
| Token/URL logs | fragment is not sent to servers, but may land in browser history/clipboard managers |

## Transport options

| Transport | TTL | One view | Async | Notes |
|---|---|---|---|---|
| **LAN relay (shipped)** | sender-enforced | **yes** (store deletes/refuses after the view budget) | no (both online) | `share create --serve` + `share serve`; no pairing/auth by design |
| Local file/manual (shipped) | metadata only | no | yes | `pvshares/<id>.pvsh` + the fragment link; weakest claim |
| **GitHub secret gist (shipped, A20b)** | best-effort (sender deletes the gist on revoke; no relay clock) | no (recipient can re-fetch until deletion) | **yes** | `share create --relay gist`; recipient needs no token; label "expiring", not "one-time" |

LAN is the strongest claim we can make without running infrastructure. Gist is
the only async option that needs no recipient account, but it cannot enforce
TTL/one-view.

## UX (shipped in slice 3 + A20a/A20b)

1. Settings → Expiring shares card (title input; no context-menu selection yet).
2. TTL text (`24h`) + views (`1`, `0` = unlimited) + LAN **or** Async gist
   (mutually exclusive).
3. Show the link **once** with a masked copy button and a QR code; warn that
   without a passphrase the link is the key. With a passphrase, tell the sender
   to send link and passphrase separately. Async gist is labelled best-effort.
4. Recipient pastes the link / picks the `.pvsh` file (+ passphrase when
   required) → app fetches (LAN, gist, or file), decrypts, shows a
   title/username preview → **Add to my vault** (never auto-import).
5. Sender sees active shares and can **Revoke**; gist deletion is attempted,
   and the LAN listener stops when the last LAN share is revoked.

Not yet: item context-menu/bulk selection.

## Exit tests

1. Create → link → fetch → decrypt → preview → import; item fields match.
2. Wrong key / tampered blob / truncated blob fail closed.
3. Expired share is refused (recipient clock).
4. One-view transport: second fetch gets no blob; sender can revoke before fetch.
5. The key never appears in the bundle or in the relay request path/headers.
6. Padded bundles of different field sizes are the same length.
7. `PVSH2`: correct passphrase opens; missing/wrong passphrase fails closed; a
   `#k=` fragment cannot bypass the passphrase; the passphrase is not in the
   bundle; `#p=1` links parse with `key: None`.
8. Store metadata: the passphrase flag survives a reload, and a pre-A20a
   `.meta.json` without the field still loads as "no passphrase".
9. Gist relay: publish → fetch → delete round-trips over a loopback mock API;
   the gist link parses with `is_gist()`; fetch rejects missing/oversized/
   truncated objects; an expired relay share stays local so it can be revoked.

Slices 1–2 cover 2, 5 (bundle half) and 6. Slice 2 covers 3 (store expiry) and 4
(loopback one-view test). Slice 3 wires the GUI; the exact desktop import
click-through is manual QA (no UI automation), while the shared backend is
covered by tests. A20a adds 7–8 (`share::tests::passphrase_*`,
`share_store::tests::passphrase_flag_*`). A20b adds 9
(`share_relay::tests::*`, `share_store::tests::store_enforces_*`). 5 is true for
the LAN transport (the key is only in the fragment; the store never sees it).

## Effort

- Slice 1 (done): 0.5 day.
- Slice 2 (store + LAN/file transport + CLI): 1 day.
- Slice 3 (Slint card, copy, open/preview/import, revoke): 1 day.
- Slice 4 / A20a (optional passphrase + QR): 0.5 day.
- Slice 5 / A20b (async gist relay): 0.75 day.
- Remaining: item context-menu/bulk selection only.

## Non-goals

- No DRM/"self-destruct after reading" guarantee on the recipient side.
- No server-side accounts or link shortener.
- No attachments/folders in slice 1 (they stay in `.pvx` until a later slice).
- No web viewer (recipient needs the app; a browser viewer is a separate surface).
