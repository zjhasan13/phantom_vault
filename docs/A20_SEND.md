# A20 — serverless expiring share (Send-style)

> Status: **slices 1–2 shipped.** Bundle crypto + an on-disk store with TTL/
> one-view accounting + a LAN/file transport and the `share` CLI work today.
> The desktop UI (selection, link display, recipient preview) is slice 3; until
> then sharing is CLI-only.

## CLI (slice 2)

```powershell
# sender: creates pvshares/<id>.pvsh, prints a file link
phantom_vault share create "Gmail" --ttl 24h --views 1

# sender: also serve the ciphertext on the LAN, print pvshare://<ip>:<port>/<id>#k=…
phantom_vault share create "Gmail" --ttl 24h --views 1 --serve

# recipient: fetch over the link or read a bundle file
phantom_vault share open "pvshare://192.168.1.5:52123/<id>#k=…"
phantom_vault share open "pvshare://<id>#k=…" --file pvshares/<id>.pvsh
phantom_vault share open "…" --import          # prompts master, adds the login

phantom_vault share list
phantom_vault share revoke <id>
```

One-view/TTL are enforced by the **sender's store** (`take()` increments views
before returning bytes; expiry deletes the bundle). The listener has no pairing
auth **by design** — the id is 128-bit random and the key never reaches it; the
bundle is already end-to-end encrypted. This is separate from A15 vault sync.

## Goal

Share one or more vault items with someone who does not have PhantomVault's
vault, using an **expiring, one-time** link where the relay never sees the key.

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

## Threat model (honest)

| Threat | Mitigation / limit |
|---|---|
| Relay/storage sees the blob | only ciphertext; the key is in the URL fragment (never sent in HTTP requests) |
| Relay sees the key | impossible **iff** clients put it only in the fragment; a user pasting the full link into chat does share the key with that channel |
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
| GitHub/other relay (next) | best-effort (blob deletion) | no (client cannot enforce) | yes | Must be labelled "expiring", not "one-time" |

No third-party relay is needed for the LAN path, which is the strongest claim we
can make without running infrastructure.

## UX plan (slice 3)

1. Item context menu / bulk select → **Share…**
2. Choose TTL (1h / 24h / 7d) and max views (1 / N / unlimited).
3. Show the link **once** + copy button + QR; warn that the link is the key.
4. Recipient opens `pvshare://…` → app fetches the blob, decrypts, shows a
   preview (titles/fields) → **Add to my vault** (never auto-import).
5. Sender sees active shares and can **Revoke** (delete the blob).

The CLI already covers 1–5 headlessly; the Slint UI is the remaining surface.

## Exit tests

1. Create → link → fetch → decrypt → preview → import; item fields match.
2. Wrong key / tampered blob / truncated blob fail closed.
3. Expired share is refused (recipient clock).
4. One-view transport: second fetch gets no blob; sender can revoke before fetch.
5. The key never appears in the bundle or in the relay request path/headers.
6. Padded bundles of different field sizes are the same length.

Slice 1 covers 2, 5 (bundle half) and 6. Slice 2 covers 3 (store expiry), 4
(loopback one-view test) and the create/fetch/decrypt path; `--import` is
interactive, so its exact UI flow is manual QA until slice 3. 5 is true for the
LAN transport (the key is only in the fragment; the store never sees it).

## Effort

- Slice 1 (done): 0.5 day.
- Slice 2 (store + LAN/file transport + CLI): 1 day.
- Slice 3 (Slint share UI + QR + import preview, optional async relay): 3–5 days.
- Total target: 2–3 weeks including docs/QA.

## Non-goals

- No DRM/"self-destruct after reading" guarantee on the recipient side.
- No server-side accounts or link shortener.
- No attachments/folders in slice 1 (they stay in `.pvx` until a later slice).
- No web viewer (recipient needs the app; a browser viewer is a separate surface).
