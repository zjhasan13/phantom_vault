# PhantomVault UI tokens (Aegis Cyber-Cockpit palette)

> Status: **AegisVault Cyber-Cockpit re-theme (Option B).** `design/tokens.json`
> is the source; the Slint `PhantomTheme` and the extension
> `design-tokens.css` mirror it. Palette: deep navy `#0b1326` + mint `#4edea3`
> + electric cyan `#4cd7f6`. Shipped: vault shell + sidebar rail, All Items
> two-column detail, editable item tags, 2FA hub slices 1-2 (chips/sort/
> per-account params, centered Add/Export sheets), embedded Inter / JetBrains
> Mono / Noto Sans Bengali / Material Symbols subsets. Remaining: Settings/Dev
> Center IA, Generator studio, extension HUD restyle.

## Source

- Design: `expected ui/stitch_phantom_vault_desktop_ui/all_vault_items/code.html`
  (Tailwind config) + the downloaded `screen.png`.
- Palette decision: **AegisVault redesign wins** (user decision, Option B);
  see `docs/UI_PARITY_MAP.md` §18.
- Machine-readable: `design/tokens.json`.

## Where it is consumed

| Consumer | File | Status |
|---|---|---|
| Slint desktop | `ui/appwindow.slint` → `global PhantomTheme` | canonical tokens + compatibility aliases; common component colors swept (160 hex occurrences total incl. the theme block; the rest are alpha tints/one-offs) |
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

## Typography policy (embedded subsets)

- Families: **Inter** (UI) and **JetBrains Mono** (secrets/OTP/hashes), plus
  **Noto Sans Bengali** for the Bangla UI. All three are **OFL**; licenses live
  in `ui/fonts/licenses/`.
- **Embedded as subsets** (Latin + punctuation/symbols; Bengali block for Noto)
  via Slint file imports (`import "fonts/Inter-Regular.ttf";` …), so the compiler
  embeds them in the exe. **No runtime path lookup, no CDN, no extra crate.**
- Weights shipped: Inter Regular/SemiBold/Bold/Black (400/600/700/900);
  JetBrains Mono Regular/Bold. 500/800 map to the nearest embedded weight.
- Measured cost: fonts **~1.07 MB** on disk, including the 69.6 KB Material
  Symbols subset. Subsetting (fonttools, build-time only) is what keeps this
  near 1 MB.
- `MainWindow.default-font-family: "Inter"`; mono surfaces set
  `font-family: "JetBrains Mono"` explicitly. Slint's font fallback resolves
  Bengali to the embedded Noto and emoji to Segoe UI Emoji (verified in the BN
  login screenshot).
- The browser extension still loads no remote fonts (MV3 CSP + offline); its
  CSS keeps the system mono stack until a subset is shared.

## Icon policy (Material Symbols subset)

- Material Symbols **ligatures do not work in Slint**, so the embedded subset is
  addressed by **codepoint** (`Text { text: "\u{e1a1}" }`).
- `ui/fonts/MaterialSymbolsOutlined.ttf` is a 31-codepoint subset (~69.6 KB)
  embedded in the exe; the sidebar rail and several controls use it.
- Content that has no subset codepoint still uses emoji (🔑/⭐/🗑/📋 in cards and
  list rows) — deliberate, not a missing-font bug. A later slice can expand the
  subset and retire the emoji.
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

1. ~~Sweep the common atoms/shell hex colors~~ (done; alpha tints/one-offs remain).
2. ~~Add the full-width command bar, select strip and ~5/7 split~~ (done).
3. ~~Add row entropy bar/badge and the 3 detail tiles + recent audit trail~~ (done).
4. ~~Item tags / last-used / expires model fields~~ (item tags done; expires still
   comes from the existing model where present). ~~Font/icon decision~~ embedded.
5. Remaining: compact-window QA for the new hub/sheets; then the extension HUD
   2.0 links `design-tokens.css` and adopts `--pv-*`.

Acceptance for each slice: `npm run test:tokens`, `cargo test`, `npm test`,
clippy clean; no callback/property renames (see `UI_PARITY_MAP.md` Appendix B).
