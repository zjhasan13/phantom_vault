# A23 — local API + `pv` CLI (slice 1: read-only)

> Status: **shipped, read-only.** A script can read one login field after an
> explicit in-app **Allow** prompt. `run`/`inject`, write operations and token
> scopes are later slices.

## What it is

- Opt-in **Settings → Local API (pv CLI)**. Off by default, per session.
- Listener binds **127.0.0.1** only, on a random loopback port; the port is
  written to `pv_api_port`.
- A 32-byte bearer token is generated on enable, **DPAPI-sealed** in
  `pv_api_token.dpapi`, expires after **24 hours**, and is revoked when the API
  is turned off.
- Every secret read creates a pending request; the app shows an **Allow once /
  Deny** prompt (30s). The CLI polls the result. Every decision is written to
  the access log (id + field, never the secret).

## CLI

The binary is `phantom_vault`; alias it to `pv` if you like.

```powershell
phantom_vault pv status
phantom_vault pv get "Gmail"                     # password
phantom_vault pv get "Gmail" --field username
phantom_vault pv get --id <credential-id> --json
```

The app must be running, unlocked, and have the API enabled. Token/port files
are resolved from `PV_API_DIR`, then the current directory, then the
executable's directory.

Exit codes: `0` ok, `1` refused/locked/not running/timed out, `2` usage.

## Endpoints

| Method | Path | Behaviour |
|---|---|---|
| GET | `/v1/status` | `{ok, locked, version}`; token required; no vault data |
| GET | `/v1/get?title=…&field=password\|username` | creates a pending request → `202 {request_id}` |
| GET | `/v1/get?id=…&field=…` | same, by credential id |
| GET | `/v1/result?id=…` | `202` pending, `200 {value}`, `403` denied, `408` expired |

Auth: `Authorization: Bearer <token>`. Rate limit: 30 `/v1/get` requests per
minute (`/v1/status` is exempt). Errors: `401`, `403`, `404`, `405`, `409`
(ambiguous title), `423` (locked), `429`.

## Threading model

The HTTP worker never touches Slint (component handles are thread-affine). It
only enqueues a `PendingRequest` in a process-global queue. The UI thread runs a
200 ms Slint `Timer`, shows the oldest pending prompt, and `Allow`/`Deny` sets
its decision. Pending requests expire after 60 seconds; the CLI waits up to 50.

This keeps the crypto/vault path untouched: the API only reads credentials that
are already in the unlocked in-memory vault.

## Threat model (honest)

- **Same-user malware can steal the token** (DPAPI is user-scoped). Per-request
  approval is the real control: a stolen token alone cannot silently return a
  secret; the user sees the exact title/field and must press Allow.
- The loopback listener is plaintext HTTP. Local processes can observe it; the
  token is the only guard. No TLS, no code-signing/process attestation.
- A compromised app process or an attacker who can automate the UI defeats the
  prompt; this is not a sandbox boundary.
- The token file lives beside the vault; `PV_API_DIR` can point elsewhere.
- The API does **not** auto-start after an app restart; re-enable it. A stale
  port/token file fails closed (connection refused / token expiry).
- Decoy mode: enabling the API is refused. If the app is switched to decoy while
  the API is already on, reads return the decoy vault (the same data the UI
  shows); turn the API off before entering decoy if that matters.
- Read-only fields are `password` and `username`; TOTP is not exposed yet.

## Tests

- `api::token::tests::token_roundtrips_expires_and_revokes` — create/load,
  expiry, revoke.
- `api::local::tests::handler_enforces_token_lock_approval_and_rate` — 401,
  locked 423, 202→allow→200, deny→403, 400/404/409, rate limit.
- `api::local::tests::loopback_get_waits_for_ui_approval_and_returns_the_value`
  — real TCP server + client, simulated UI approval, secret returned.
- `api::cli::tests::get_args_parse_title_id_field_and_json` — CLI parsing.

## Next slices

1. `pv run` / env injection through the API (approval per process).
2. Token scopes (read:username vs read:password, per-folder) + Settings list.
3. TOTP read and `--copy` (clipboard) with the same approval.
4. Auto-start on unlock (opt-in) and a visible "API active" tray indicator.
