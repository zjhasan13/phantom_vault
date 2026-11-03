# PhantomVault UI tokens (single source of truth)

> Status: **P0 shell + cockpit components shipped.** `design/tokens.json` is the
> source; the Slint `PhantomTheme` and the extension `design-tokens.css` mirror
> it. The vault has a full-width command bar, filter/select strip, ~5/7 split,
> entropy bars/badges, three diagnostic tiles and a recent audit trail. Remaining
> P0 polish: tags/last-used/expires model fields, font/icon decision,
> compact-window QA.

## Source

- Design: `expected ui/stitch_phantom_vault_desktop_ui/phantom_vault/DESIGN.md`.
- Palette decision: **frontmatter (screenshots) wins** over the prose palette;
  see `docs/UI_PARITY_MAP.md` §18.
- Machine-readable: `design/tokens.json`.

## Where it is consumed

| Consumer | File | Status |
|---|---|---|
| Slint desktop | `ui/appwindow.slint` → `global PhantomTheme` | canonical tokens + compatibility aliases; common component colors swept, 115 hex literals remain outside the theme block (alpha tints, gradients, one-offs) |
| Extension | `browser_extension/design-tokens.css` (`--pv-*`) | file exists, **not linked** from `popup.html` yet (HUD 2.0 slice) |

The Slint aliases (`void`, `abyss`, `panel`, `card`, `edge`, `aura`, `pulse`,
`ink`, `mist`, `dim`, `good`, `warn`, `bad`) are kept so the 624 raw-hex sweep
can be incremental. They intentionally point at the new semantic values.

## Gate

```powershell
npm run test:tokens
# or
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check_ui_tokens.ps1
```

`npm test` remains the JS test suite; the token check is separate because it is
Windows/PowerShell-specific.

## Typography policy (size-conscious)

- Target families: **Inter** (UI) and **JetBrains Mono** (secrets/OTP/hashes).
- **Not bundled yet.** Bundling WOFF2/TTF adds runtime size; the P0 slice uses
  `Inter, "Segoe UI", sans-serif` and `"JetBrains Mono", "Cascadia Mono",
  Consolas, monospace` fallbacks. The extension loads no remote fonts (MV3 CSP
  + offline).
- If exact font parity is approved later, add OFL files under `assets/fonts/`
  and register them with `slint::register_font_from_path` before
  `MainWindow::new()`. Do not add a CDN dependency.

## Icon policy (deferred)

- Material Symbols **ligatures do not work in Slint**. The current app uses
  emoji; the mockups use outline icons.
- P0 keeps emoji. A later slice can use either a small icon TTF (codepoints
  only) or SVG/`Path` icons. No icon font is bundled yet.
- Extension icons may use local SVGs; no remote CDN.

## Label policy

The mockup labels that are not true for PhantomVault are listed in
`docs/UI_PARITY_MAP.md` §15 and must be rewritten, not faked:

| Mockup | Use instead |
|---|---|
| AES-256-GCM / ChaCha20 | **XChaCha20-Poly1305** |
| TouchID / Secure Enclave / YubiKey / TPM | **Windows Hello + DPAPI** (FIDO2 is A21) |
| SLIP-39 / Reed-Solomon | **GF(2^8) Shamir (3-of-5)** |
| BLAKE3 Merkle | **HMAC-SHA256 chain** |
| Tauri/SQLite/Nostr/Wasm/CRDT | Not shipped; say so |
| 7-pass flash purge | **file-level 3-pass DoD** |

## Next (P0)

1. ~~Sweep the common atoms/shell hex colors~~ (done; 115 hex literals remain outside the theme block).
2. ~~Add the full-width command bar, select strip and ~5/7 split~~ (done).
3. ~~Add row entropy bar/badge and the 3 detail tiles + recent audit trail~~ (done).
4. Remaining: tags/last-used/expires model fields; font/icon decision; compact
   window QA.
5. Then the extension HUD 2.0 links `design-tokens.css` and adopts `--pv-*`.

Acceptance for each slice: `npm run test:tokens`, `cargo test`, `npm test`,
clippy clean; no callback/property renames (see `UI_PARITY_MAP.md` Appendix B).
