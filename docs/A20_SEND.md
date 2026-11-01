# A20 — serverless expiring share (Send-style)

> Status: **slice 1 core shipped** (`src/share.rs`, tests only; not yet wired to
> UI/transport). Transport + UI are slice 2. The feature is **not** user-facing
> until that lands.

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

## Transport options (the decision slice 2 must make)

| Transport | TTL | One view | Async | Notes |
|---|---|---|---|---|
| **P2P relay (LAN)** | sender-enforced | **yes** (delete after first successful fetch) | no (both online) | Recommended first: no third party, matches A15 pairing/signing |
| GitHub/other relay | best-effort (blob deletion) | no (client cannot enforce) | yes | Must be labelled "expiring", not "one-time" |
| Local file/manual | metadata only | no | yes | Useful offline; weakest claim |

Recommendation: implement **P2P first** (enforceable one-view/TTL, reuses
`signed_headers`/pairing conventions), then an honest async fallback where the
UI says "expires, but cannot guarantee a single view".

## UX plan (slice 2)

1. Item context menu / bulk select → **Share…**
2. Choose TTL (1h / 24h / 7d) and max views (1 / N / unlimited).
3. Show the link **once** + copy button + QR; warn that the link is the key.
4. Recipient opens `pvshare://…` → app fetches the blob, decrypts, shows a
   preview (titles/fields) → **Add to my vault** (never auto-import).
5. Sender sees active shares and can **Revoke** (delete the blob).

## Exit tests

1. Create → link → fetch → decrypt → preview → import; item fields match.
2. Wrong key / tampered blob / truncated blob fail closed.
3. Expired share is refused (recipient clock).
4. One-view transport: second fetch gets no blob; sender can revoke before fetch.
5. The key never appears in the bundle or in the relay request path/headers.
6. Padded bundles of different field sizes are the same length.

Slice 1 covers 2, 5 (bundle half) and 6; 1/3 are covered at the format level;
4 needs the transport.

## Effort

- Slice 1 (done): 0.5 day.
- Slice 2 (P2P relay + UI + preview/import): 3–5 days.
- Slice 3 (async relay/GitHub + revocation UI): 3–5 days.
- Total target: 2–3 weeks including docs/QA.

## Non-goals

- No DRM/"self-destruct after reading" guarantee on the recipient side.
- No server-side accounts or link shortener.
- No attachments/folders in slice 1 (they stay in `.pvx` until a later slice).
- No web viewer (recipient needs the app; a browser viewer is a separate surface).
