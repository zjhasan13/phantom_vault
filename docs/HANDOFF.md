# Session Handoff â€” PhantomVault

> Read this fully in a fresh session BEFORE doing anything. Last updated: Generator Studio slice 1 (full-page, honest OS CSPRNG, Complex + Diceware, copy), Settings & Dev Center slice 1 (Aegis header + 6-tab section filter), Aegis 2FA hub slices 1-2 (filter chips / sort / per-account params), centered Add-2FA + Export sheets with explicit busy / empty / error states, and a collapsed-rail `»` expand button; before that, login-page parity pass 2 (pinned brand header, PQ-aware hero pill, honest 3-tab strip, 5-segment entropy), UI token foundation (design/tokens.json) after A24d/A24c/A24b/A24a/A20c/A20b/A20a/A26/A23/A22/A20/E5/T5/A19/A18/A15c/A16/A12/A17/A11b/A14.
> Companion: `rules.md` (architecture invariants â€” non-negotiable).

## 1. Where we are

- **Web 0.3.2 (latest):** one ranking for every fill path (`rankLogins`:
  carried -> verified -> last_filled -> A->Z) used by the dropdown, hotkey and
  context menu; identity suggestions fixed (raw `getIdentities()` - URL-less
  rows no longer dropped, and `isAddr` beats the checkout-card heuristic);
  per-tab carry (`pvCaptureCarry:<tabId>` via background `PV_TAB_ID`); SPA
  identifier-only step 1 carries the username via a data-free `PV_SPA_IDENT`
  tripwire; popup mirrors the trust rank; carry clears only on a full fill.

- **Import/export 0.4.0:** lossless native
  `.pvx` backup (same master-password hybrid envelope â€” superseded by A6 below,
  which adds the `PVBK1` backup-passphrase tag; passkeys, 2FA hub,
  SSH keys, attachment bytes), row-level preview with Skip / Update existing /
  Import all, URL-aware login dedupe, session-only undo guarded by a vault
  fingerprint, and an all-kinds "Full CSV" export. Importer decrypts `.pvx`
  with the live master and refuses a foreign one. Installer + zips rebuilt at
  0.4.0.
  Tests `npm test` **79/79**, `cargo test` **468 passed / 1 ignored**.
  Installer `installer-output/PhantomVault-Setup-0.4.0.exe` (8.54 MB, sha16
  `675196E7EC550471`, excludes `browser_extension/dist`); exe 19.55 MB
  ProductVersion 0.4.0; zips `dist/phantomvault-{chrome,firefox}-0.4.0.zip`
  (111002 / 111054 bytes). Release upload is user-side (`gh` unauthenticated).

- **A26 pilot — Bengali UI + persistence (this batch):** the lock screen already
  had an EN/BN `ui_lang` toggle; it now persists to `lang.pref` through the Rust
  `set_language` callback, and Settings gains an **English / বাংলা** row. Inline
  `ui_lang` ternaries translate the sidebar (VAULT, All items, Favorites, 2FA
  Hub, Settings), the importer/Settings headings, and the LOCAL API / Expiring
  shares section labels. **Batch 2:** type labels (Login/Card/Identity/Note/
  License/SSH Key), TYPES/FOLDERS/APP, item-detail headings (credentials,
  username/password, notes, auto-fill, backup codes, custom fields, attachments,
  history, autofill/attach actions) and the add/edit form headings. **Batch 3:**
  Settings security headings (rotation, offline cache, PQ, 2FA clock, clipboard,
  auto-lock, updates, paired devices, duress/honeytokens/emergency), GitHub
  Sync + Local Wi-Fi P2P labels, Export Vault heading, and the Master Reprompt
  title/description. **Batch 4:** reprompt action/field/Confirm/Cancel, the API
  approval dialog (Allow/Deny + warning), and the import dry-run preview
  (mode buttons, Confirm/Cancel, Undo). **Batch 5:** a `tr()` + `UI_LANG_BN`
  bridge now localizes the most frequent Rust status strings (decoy read-only
  across all handlers, vault-not-unlocked, import waiting/no-file/preview/
  merging/restore) and the duplicate-import choice buttons. Remaining Rust
  status/error strings, and many dialogs stay English; **Batch 6:** unlock
  status line (empty/wrong password, decrypting, unlocked, Hello/TOTP prompts),
  main share/API static statuses, and the Quick Capture window (its own
  `ui_lang` copy synced by `set_language`). **Batch 7:** the `tr()` flag moved
  to `src/i18n.rs` (shared with the importer); the import summary headline/counts,
  Quick Bar (its own `ui_lang` copy: instant-copy, Copy, no-matches, Dismiss) and
  sync offline/pushed/synced status lines are localized. **Batch 8:** the
  generator panel (its own `ui_lang` passed down), delete/shred/restore item
  buttons, and P2P result lines (already-in-sync, adopted, pushed, conflict) via
  the shared `i18n` flag; the Bengali Confirm-Import button was widened. **Batch
  9:** a `root.tr(en, bn)` helper, add/edit placeholders for card/identity/
  license/SSH/note kinds (cardholder, number, CVV, expiry, NID, keys, address/
  city/state/ZIP/country, alias), and the Empty Trash & Shred All dialog. **Batch
  10:** long help paragraphs (offline cache, PQ-paranoid, Local API, Expiring
  shares, family sync), a static fixed-width audit (Confirm Import, reprompt/
  TOTP confirm, import-mode row, shred-all widened), and a wrap-up section in
  `docs/A26_BN.md` with the layout-QA checklist and the `@tr`/`.po` migration
  plan. A full 100%/125% visual layout pass is still manual and required before
  calling A26 complete. `normalize_lang` only
  accepts `bn` (case/space tolerant); anything else falls back to English.
  Honest: most dialogs and all Rust-generated status strings remain English —
  `docs/A26_BN.md` lists the coverage and how to extend. Tests +1 → `cargo test`
  **540 passed / 2 ignored + 4 pv_sign**; `npm test` **133/133**.

- **A20 slices 1–2 — expiring share (this batch):** `src/share.rs` adds the
  transport-agnostic `PVSH1` bundle (random 256-bit key never in the blob, meant
  for the `pvshare://…#k=` fragment; XChaCha20-Poly1305; JSON padded to 4 KiB;
  TTL/`max_views`; key/tamper/truncation/expiry fail-closed). Slice 2 adds
  `src/share_store.rs` (`pvshares/<id>.pvsh` + meta; `take()` increments views
  before returning), `src/share_serve.rs` (`GET /<id>` one-view/TTL, `health`,
  LAN or loopback; **no pairing/auth by design** — 128-bit id + fragment key),
  and `src/share_cli.rs` (`share create [--serve] / serve / open [--file]
  [--json] [--import] / list / revoke`). **Slice 3 (this batch):** Settings →
  **Expiring shares** card (`login_share_*` — deliberately namespaced away from
  the pre-existing Phase 9 Secure Send card): create by title/TTL/views/LAN,
  masked copy, open link or `.pvsh`, preview, duplicate-safe **Add to my vault**
  (saved with the master), active-share rows with per-share **Revoke**; the LAN
  listener stops when the last share is revoked. Tests +7 → `cargo test`
  **539 passed / 2 ignored + 4 pv_sign**; `npm test` **133/133**. The desktop
  import click-through is manual QA; async relay/QR remain.

- **A20a — optional recipient passphrase + QR (this batch):** `src/share.rs`
  adds `PVSH2` (`magic | flags=0x01 | salt 16 | wrap_nonce 24 | wrapped_key 48 |
  payload_nonce 24 | ct+tag`). The random payload key is wrapped with
  `Argon2id(passphrase, 64 MiB/t=3/p=4)`; the link becomes
  `pvshare://<id>#p=1` (or `host:port/id#p=1`) with **no key**.
  `create_with_passphrase` / `open(bundle, key, passphrase)` keep `PVSH1`
  readable and ignore `#k=` for `PVSH2`; missing/wrong passphrase fails closed,
  flags are exact, and passphrases are trimmed at every entry point.
  `ShareMeta`/`ShareRecord` persist a `passphrase` flag with
  `#[serde(default)]` (old `.meta.json` still loads). CLI gains
  `share create --passphrase` (double prompt) and a passphrase prompt on
  `#p=1` links. Settings card gains Passphrase toggle/confirm, a
  passphrase field on Open, and a QR image of the **link only** (the ~4 KiB
  padded bundle does not fit a QR); the QR temp file is content-tagged so a
  second share cannot show a stale image. Tests +2 (`passphrase_share_*`,
  `passphrase_flag_persists_*`) → `cargo test` **542 passed / 2 ignored**;
  `npm test` **133/133**. UI click-through is still manual QA.

- **A20b — async gist relay (this batch):** `src/share_relay.rs` publishes the
  encrypted `PVSH1`/`PVSH2` bundle as base64 in a **secret GitHub gist**
  (`bundle.pvsh.b64`, 64 KiB cap) and fetches it **without a token** through
  the raw gist host (API fallback for owner-less links); a loopback mock
  (`PV_RELAY_API` + `PV_RELAY_RAW`) covers publish/raw-fetch/API-fetch/delete.
  Links are
  `pvshare://gist/<owner>/<gist_id>#k=…` / `#p=1` (the gist host is reserved in
  `share.rs`; `ShareLink::is_gist`). Publish/delete use the stored GitHub
  token (classic PAT with `gist`; clear error otherwise). `ShareMeta`/
  `ShareRecord` persist `relay_gist`; `share revoke` and GUI Revoke delete the
  gist best-effort; expired relay shares stay local (so the gist can still be
  deleted) instead of being purged. CLI `share create --relay gist`; Settings
  adds an **Async gist** toggle (mutually exclusive with LAN) and a `☁ gist`
  row marker; publish/revoke run off the UI thread. Tests +3 (relay
  roundtrip/mock, id/link strictness, oversize/missing) → `cargo test`
  **545 passed / 2 ignored**; `npm test` **133/133**.
  Honest: gist TTL/one-view are **not** enforced and the gist owner's GitHub
  login is in the link (needed for the tokenless raw fetch); labelled
  best-effort, not one-time.

- **A20c — item Share + bulk staging (this batch):** right-click a vault row
  (`PointerEventKind.down` + `PointerEventButton.right`) or use the hover /
  detail **📤 Share** button to stage that login and jump to Settings →
  Expiring shares; Select mode gains **📤 Share Selected** for the whole
  selection. `share_stage()` is a RAM-only global (cleared on lock, decoy
  unlock, Clear, and after a successful create); `shareable_item` /
  `selected_share_items` keep only active logins (non-logins, trashed rows and
  unknown ids are skipped, sorted by title). The card shows the staged count,
  disables the title field, offers **Clear**, and a 200 ms Timer scrolls the
  Settings view to the card (`share_anchor`). The create path uses the staged
  items when present, otherwise the title lookup. Tests +1
  (`bulk_share_stages_only_active_logins`) → `cargo test` **546 passed / 2
  ignored**; `npm test` **133/133**. All A20 slices are now shipped.

- **A24a–d — attachment sidecars (this batch):** `src/attachment_store.rs`
  adds `PVAB1` (1 MiB AEAD chunks, id/index AAD, wrapped per-file key under the
  vault `attachment_root`). New >5 MiB files stream to
  `<vault_dir>/attachments/<id>.pvab`; the vault save stores metadata only.
  Add/download stream, preview is capped at 8 MiB, delete tombstones remote
  copies, and `.pvx` export re-inlines sidecars. **GitHub sync** pushes
  sidecars before the vault and pulls missing ones before adoption; **P2P**
  gained paired/signed `/p2p/attach/list|/<id>` GET/POST/DELETE and reconciles
  after the vault. Settings shows inline/sidecar counts and a **Move inline to
  encrypted sidecars** migration action (clone → write → save; failure restores
  and removes new files). Tests +9 → `cargo test` **554 passed / 3 ignored**
  (includes an ignored 50 MiB roundtrip); `npm test` **133/133**. No new
  dependencies; app size impact is code-only. Manual QA still: 50 MiB `.pvx`
  export/import, lock mid-migration, disk-full/antivirus, 100%/125% layout.

- **UI token foundation + P0 palette pilot (this batch):**
  `design/tokens.json` is the single source for the frontmatter
  palette/type/radius/spacing; `ui/appwindow.slint` `PhantomTheme` carries the
  canonical tokens + aliases, and `browser_extension/design-tokens.css` mirrors
  them (not linked yet). `scripts/check_ui_tokens.ps1` / `npm run test:tokens`
  fail on drift. The common app colors were swept (~554 literals; 115 hex
  literals remain outside the theme block); the vault now has a full-width command bar (search,
  ZERO-KNOWLEDGE / RAM-SAFE chips, local session, New Item), a filter/select
  strip above a 5/7-ish list/detail split, 76px rows with a real entropy bar and
  health/type badge, three detail diagnostic tiles (pwned/age/encryption) and a
  recent audit-trail card. Honest: `0M LEAK`/`⌘K` are not fabricated; row tags/
  last-used/expires still need model fields; fonts/icons remain system
  fallbacks (size decision); `PWNED` shows "Not scanned" until an audit runs.
  **Desktop visual QA (this batch):** compared against
  `expected ui/.../all_vault_items/code.html` at 1280x800 logical on a
  125%-scaled 1920x1080 display. Restructured to the mockup's real markup:
  search-first command bar (no redundant brand label; pill chips for
  ZERO-KNOWLEDGE / RAM-SAFE / LOCAL; compact `+ New`), a 42px filter strip with
  76px buttons and a right-pinned Select, a real list header (`VAULT ITEMS` +
  `total_matches_count`, `LOCAL INDEX`), and 76px rows with a 36px rounded icon
  tile, title + health/type badge pill on one line, handle line, then the
  strength bar/% — selected row = surface-highest + 3px primary bar, matching
  the design. New `fit_window_to_work_area` clamps the initial 1280x800 window
  to the monitor work area in physical px so a 125% / small panel does not hide
  the right pane. Tooling note: capture the window from a **DPI-aware** process
  (SetProcessDpiAwarenessContext) — a DPI-unaware `PrintWindow` crop made the
  right pane look clipped when it was not.
  See `docs/UI_TOKENS.md` and `docs/UI_PARITY_MAP.md` §30.

- **Login page parity, pass 2 (this batch):** the lock screen is rebuilt as the
  `login page/code.html` cryptographic gateway: 38px technical grid (alpha
  `#ffffff0d`) + two ambient glows, live telemetry strip (vault sealed / real
  Argon2id 64 MiB t=3 p=4 / device binding), engine chips (real `v0.4.1-rs`,
  Windows Hello when available, portable badge), shield crest + gradient
  wordmark, and a 560px glass card (110px violet glow) with Master Pass / PIN /
  Recovery Shards tabs, real vault filename, eye toggle, **live entropy bits**,
  Kerckhoffs-honest cipher row, DPAPI binding + zeroize status rows, gradient
  Unlock (`🔓`, `↵ Enter`), Windows Hello row, and real recovery/shred links.
  Pass-2 fixes: hero pill, wordmark and tagline are pinned **above** the
  `ScrollView`, so password auto-focus can no longer scroll the brand header
  out of view; the pill hugs its content and switches on real PQ state
  (`POST-QUANTUM ENCLAVE · TPM 2.0` / `POST-QUANTUM ENCLAVE ACTIVE` /
  `LOCAL ENCLAVE ACTIVE`, chip `HW KEY` / `ML-KEM-768` / `XChaCha20`); the
  TPM status row is conditional on `pq_backend == "tpm"`; the tab strip always
  renders three tabs (PIN reads `PIN · OFF` when no app PIN exists and explains
  the fix on click); tab glyphs; `LOCAL-ONLY · NO ACCOUNT` right label in the
  identifier row; 5-segment entropy bar bound to the real `lock_bits`; lock
  glyph inside the password field; Windows Hello row always visible with an
  honest fallback ("not enrolled · use the passphrase"); footer
  `v<ver> · MIT · OPEN SOURCE`.
  Honest substitutions for the mockup's invented claims: no TPM PCR[7], no
  FIPS 140-3 certification, no YubiKey assertion, no SLIP-39, no
  "104.2 bits / CPU years", no TrailOfBits audit; those slots show the real
  Argon2id/XChaCha20 params, DPAPI binding, Windows Hello availability, and
  "open source". Fonts are now **Inter + JetBrains Mono + Noto Sans Bengali**,
  embedded as Latin/Bengali subsets in `ui/fonts/` (1.02 MB; debug exe +1.09 MB)
  with OFL licenses; `default-font-family: "Inter"` and mono overrides. The BN
  fallback was verified on the login screen. Login polish: 520px card, `LOC: EN`
  language chip, duress/decoy row only when `decoy_exists()` (real), and the
  tamper banner is suppressed on debug builds only (release still shows it).
  Compact 960×620 QA: the Unlock button stays above the fold; the Hello row and
  links scroll. Deliberately
  **not** implemented: the mockup's one-click duress-wipe button (unsafe),
  frameless chrome (native titlebar kept), and the Passkey/FIDO2 tab (A21 is
  not shipped, so the tab would be a dead control). Honest parity estimate
  **~85%** of the mockup; 100% is unreachable without those three and without
  the false claims. `cargo build` green; visual QA via DPI-aware `PrintWindow`
  capture.

- **AegisVault Cyber-Cockpit re-theme (Option B):** the user
  replaced `all_vault_items/code.html`/`screen.png` with a new design
  (`AegisVault`: deep navy `#0b1326`, mint `#4edea3`, electric cyan `#4cd7f6`)
  and chose a full pivot. Done in this slice: `design/tokens.json`, the Slint
  `PhantomTheme` + aliases, the extension `--pv-*` mirror and the token gate are
  on the Aegis palette; brand strings/window title stay **PhantomVault** (only the Aegis design system/palette is adopted); the login
  gateway and vault shell now render navy/mint; the sidebar is the design
  structure (brand+version, local-vault selector, VAULT STORAGE with real
  per-type counts, Logins/
  Cards/Notes/SSH/Favorites/Trash, UTILITIES, local-engine + local-session +
  lock); rows carry the real last-updated age and the detail header shows
  `ID … · Updated …`. Login polish: explicit 14px heights on the section-label rows + a start-aligned wrapper stop the card from stretching to the ScrollView viewport, so the account/passphrase gaps match the mockup; the password field autofocuses through LineEdit `init` instead of a 0x0 FocusScope. The item detail two-column transformation (Launch & Autofill, username/password cards, TOTP/passkey cards, Authorized Autofill Targets, storage/revision/tags) and the toolbar filter chips have since landed as well.

  **2FA hub slices 1-2 + sheet/rail fixes (this batch):** the hub is now the
  Aegis grid - search toolbar (Show NEXT / Export / Add 2FA), four real KPI
  cards (active keys / RFC 6238 / local clock with no fake NTP claim /
  ephemeral on-demand codes), `All / Starred / TOTP / HOTP / STEAM` chips,
  `Vault / A-Z / Z-A` sort, honest `30s · SHA-1 · 6 digits` params on every
  card, 192px cards and a TOTP-engine footer. Add-2FA (660px) and Export
  (480px) are centered sheets anchored inside the hub pane with a full-pane
  backdrop; both were previously laid out *inside* the hub's VerticalLayout,
  which pushed the Add sheet half off-screen. Export now opens immediately and
  drives a real busy / empty / decoy / error state, so the button can never look
  dead (the global toast is not rendered on the hub). The collapsed 64px rail
  stacks the P mark above a 40x20 `»` expand button (the old 92px header row
  clipped the chevron out of view); expanded mode keeps `«`. `push_hub_width`
  now subtracts the real 256px sidebar instead of 220. Verified by running the
  app: hub chips/sort/params, Add sheet centered, Export renders a scannable
  migration QR with Page 1/1, and `»`/`«` both toggle. Tests **556 / 4
  ignored**.

  Remaining for full parity: Settings slice 2 (2-column card grid + per-section
  polish), Generator studio, extension HUD/prompt restyle, and honest
  substitutions for the AES-256-GCM/Passkey/TPM/IPC claims (never fake them).
  Verified: `cargo check` green, token gate 21 values.

- **Settings & Dev Center slice 1 (this batch):** the Settings screen now opens
  with the Aegis header (`SETTINGS & DEV CENTER`, `LOCAL VAULT` / `DPAPI BOUND`
  chips, version) and a 6-tab filter: **Security / Sync & Devices / Privacy /
  Recovery / Backups / Dev & API**. The 16 existing cards were split at section
  boundaries and each tab renders only its own group; every existing control
  and callback is unchanged. Verified by running the app: Settings opens without
  a crash, tab 0 shows Security, and clicking **Sync & Devices** swaps in the
  GitHub/Sharing/Send/P2P cards while the Security card disappears.
  Important Slint lesson: scrolling to anchors via `settings_scroll.content-y`
  (directly in a click handler, then from a Timer) overflowed the main thread's
  stack on this screen in debug builds. The shipped slice uses conditional
  card rendering instead - do not reintroduce a content-y jump here without a
  crash test. Slice 2 note: a 2-column `FlexboxLayout` (48% cards) does not fit
  at 1280 logical px - the cards' min-content width is ~657px, so only one fits
  per row and the second wraps below. A real 2-column grid needs the wide rows
  inside each card to become responsive first; not attempted in this slice.
  Tests 556/4.

- **Generator Studio slice 1 (this batch):** the sidebar "Password Generator"
  now opens a full page (`active_nav == 4`) instead of the modal; the modal
  stays for the vault's Generator button. Page: honest OS CSPRNG strip
  (`rand_core::OsRng`, no hardware-TRNG claim), masked output with HIDE /
  REGENERATE, entropy bar with the policy estimate (no crack-time/quantum
  claims), Copy / Clear, Complex + Diceware (EN/BN), and an ENTROPY SPEC card
  (RNG / RAM only / no network / cleared on leave). A new `copy_generated`
  callback copies without clearing the page; `changed active_nav` clears the
  RAM-only output when leaving. Verified: nav opens the page, Diceware produced
  `6 words - 78 bits`, Copy put the value on the masked clipboard, no crash.
  Remaining: Pronounceable/PIN modes (no backend), session history.

- **Migration wizard slice 1 (this batch):** the importer now opens with the
  Aegis header, a 4-stage stepper (Choose file / Dry-run preview / Confirm
  merge / Done) driven by the real `show_import_preview` + `import_kind`
  state, a 25/75/100% stage bar, eight provider tiles, and a restyled
  file-password card + dry-run confirm. No fake byte progress: the bar shows
  the UI stage only. Verified by running the app: Import opens, step 1 is
  active, provider tiles render, the app stays alive.

- **Recovery Kit / Forensic & Duress / Secure Send pages (this batch):** three
  new nav routes built from the existing backend, not the mockup promises.
  Recovery Kit (5): 3-of-5 GF(2^8) Shamir, shard grid with an honest
  "not generated this session" empty state, Export Printable PDF, two-shard
  drill. Forensic & Duress (6): the HMAC-chained access log with refresh/export/
  bridge filter, duress arm, honeytokens. Secure Send (7): create note+TTL,
  link-code read+burn, offline packet/key, output card. Verified by running the
  app: all three nav entries open their page, the app stays alive. Tests 556/4.

- **GitHub restore on first run (this batch):** Step 3 of the onboarding
  carousel now has an "OR RESTORE AN EXISTING VAULT FROM GITHUB" block
  (owner / repo / PAT). The handler reuses `github_sync::pull_remote`, refuses
  when a local vault already exists, writes the ciphertext atomically, stores
  the repo + DPAPI-sealed token (PAT zeroized), hides onboarding and asks for
  the OLD master password. It never decrypts or claims success: a device-bound
  remote still needs its `pq_decapsulation.dpapi`. Verified: restore downloads
  the ciphertext into an empty data dir and switches to the unlock screen.

- **Item detail diagnostics (this batch):** the detail now shows three real
  tiles - PWNED VERIFICATION with a per-item **Check** (HIBP k-anonymity),
  PASSWORD REUSE (`Shared with N other item(s)` + **View** filters the vault to
  reused), and CREDENTIAL AGE. The cipher stays in the proof strip. The Check
  handler refuses in decoy/offline mode, zeroizes the password after the
  lookup, and never fabricates a clean result. Verified by creating a fresh
  vault in `%TEMP%\pv-ui-demo` (`Demo-Pass-123!`), opening the seeded login and
  clicking Check: the handler logged `audit / item-breach-check`. That run also
  exposed a label bug - `Ok(None)` (clean password) rendered as "Not scanned",
  so the button looked dead. `breach_check::result_label` now maps
  `Ok(None)`/`Ok(Some(0))` to "No breach found" and is unit-tested.
  Note: the window must be foreground for UIA coordinate clicks - the Slint
  AccessKit tree exposes the Check label at an off-screen rect.

- **"+ Add" chooses the item kind (this batch):** the popup only had an
  "Add login" button even after the editor learned notes/cards/identities. It
  now opens a small kind chooser (Login / Note / Card / Identity) and reuses the
  same editor + `create_item` bridge path. JS-only change; cargo gates were
  skipped on request (low disk) - npm 152/152, dist rebuilt.

- **"Continue as ..." on the password step (this batch):** when the page shows /
  carries exactly one vault account and there is no visible username field, a
  compact chip appears under the password box: site favicon, `CONTINUE AS
  <account>`, one **Fill** button and a dismiss `x`. Fill runs the normal
  `requireExtPin` + `fillLogin` path; dismiss is remembered per site in session
  storage; the chip never appears when a username field exists (the dropdown
  owns that case), when the hint matches zero or multiple accounts, or while the
  dropdown is open. Data shape: page chip / typed value / carried username, the
  same order the dropdown ranks by.

- **Extension item editor covers all four kinds (this batch):** the bridge gained
  generic `create_item` / `update_item` / `delete_item` commands (`kind` is
  explicit, so an identity edit can never become a login write; soft delete;
  card Luhn/month/year/CVV validation; note/card/identity validation). The
  popup editor reuses one form per kind (login keeps its reprompt/TOTP/show
  controls) and card/identity/note rows now carry an edit button. The popup's
  identity fill also fills company/city/state/zip and matches the country
  `<select>` by label. Tests: Rust generic-item lifecycle + Luhn/expiry + locked
  refusal, popup source-shape tests updated for the kind-aware editor.

- **Identity autofill is complete (this batch):** `PV_IDENTITIES` used to filter
  by the domain string (identities are not URL-bound, so real vaults returned
  nothing) and the reply only carried name/email/phone/address. The command now
  takes `all: true` like cards (still requires a non-empty query as the
  anti-dump guard, capped at 25) and returns `company/city/state/zip/country`.
  `fillIdentity` fills all nine fields, with the country `<select>` matched by
  option label (`United States` / `US` / `USA` variants) through
  `setSelectByText`. Capture (`readFormIdentity`) now also keeps the structured
  address parts, accepts an email-only contact (was phone-or-address only), and
  the save prompt forwards them. Verified by filling a full address form in
  jsdom and by the Rust `cards/identities` test (`all` bypass, filtered without
  it, city/zip/country in the reply).

- **Save prompt deeper parity (this batch):** reading Bitwarden's notification
  path further: `shouldAttemptNotification` requires
  `username && (password || newPassword)` for an add, the tab's form data is
  **consumed** by `clearCompletedWebRequest` once the notification fires, and
  `tabs.onRemoved` clears per-tab state. Our restore path now also drops the
  record when `classifySubmitted` says the pair is already known (a save from
  another tab must not pop a stale card); the 60 s TTL is absolute, not reset by
  a re-show.

- **Badge qualification (this batch):** a shield used to attach to any
  `type=email` / `autocomplete=email` box on a matched site (newsletters,
  contact forms, comment boxes). Bitwarden qualifies with
  `InlineMenuFieldQualificationService`: `isFieldForLoginForm` splits into
  password and username paths; `isUsernameFieldForLoginForm` vetoes identity
  emails, requires no new-password field for `autocomplete=username`, vetoes
  `AccountCreationFieldKeywords`, runs `isNonLoginUsernameField`
  (newsletter/mailing-list in the field, form attrs or any sibling), and for a
  lone field falls back to `isAmbiguousFieldNonLogin` - closest headings first,
  login headings win, non-login headings lose; `isExcludedFieldType` /
  `isSearchField` drop the rest, and `FieldIgnoreList` skips captcha/forgot.
  Ours now follows that order: identity autocomplete veto, ignore-list veto,
  account-creation veto (`autocomplete=username` also loses when a visible
  new-password field exists), newsletter context veto (field/form/siblings),
  then closest-heading tie-break before the URL signal. `findFields` also skips
  Bitwarden's excluded input types (hidden/file/button/image/reset/search/
  checkbox/radio). Tests: newsletter box + newsletter heading + signup form get
  no badge; an email-only box under a "Sign in" heading still does; Google
  challenge URL keeps its shield (npm 147/147).

- **Save prompt survives navigation (this batch):** a login POST replaces the
  document, so the old prompt vanished with it. Bitwarden's own answer is a
  per-tab map in the background (`overlay-notifications.background.ts:143-183`),
  a 60 s TTL (`CLEAR_NOTIFICATION_LOGIN_DATA_DURATION`), and a re-trigger from
  `webRequest`/`webNavigation` once the tab finishes loading. We mirror the
  shape rather than the plumbing: the capture lives in `chrome.storage.session`
  under `pvSavePending:tab:<id>` (base-domain key only when the background
  cannot report a tab id), 60 s TTL, 3-show cap, cleared when the tab closes
  (`tabs.onRemoved`). The next document on that tab re-opens the card 1.2 s
  after boot; Save / Not Now / Never / Esc clear it, the 30 s auto-dismiss only
  hides it. Card reskin: site favicon, NATIVE BRIDGE chip, one meta line
  `domain · chars · bits`.
  Tests: pending is written on submit, restored on the next document, and
  cleared by Not Now (npm 141/141). The card and identity save prompts now use
  the same panel (mint primary, quiet secondary, no emoji titles) so every
  save surface matches the app.

- **Multi-page login (verified against Bitwarden):** Bitwarden does carry the
  username into the password step, but only for the save/notification path -
  `storeModifiedLoginFormData` merges `username || existing.username`,
  `password || existing.password`, `newPassword || existing.newPassword` per tab
  (`overlay-notifications.background.ts:152-173`). Our carry is the same idea
  with a longer lease (session storage, base domain, username only - the
  password is never carried) and it also feeds the *fill* ranking
  (`page hint → carry → last filled → verified`), which Bitwarden's inline menu
  does not do (it sorts by `lastUsedDate`, see AUTOFILL_ACCOUNT_RANKING.md).

- **Offline equivalent-domain clusters (this batch):** the Google/Microsoft/
  Meta/Apple/Amazon/Sony/Yahoo/Proton families were hand-copied in two places
  (`browser_extension/domain.js:63` and `native_host.rs:2590`), so one edit
  could silently break the other. `data/equivalent_domains.json` is now the
  canonical list; `tests/js/equiv.test.mjs` compares it to the JS literal and a
  Rust test does the same against the embedded copy (`include_str!`), so drift
  fails `npm test` / `cargo test`. No server lookup: the list ships with the
  build, which is enough because it changes a few times a year.
  Also tightened `PV_QUERY` URL matching: `url_matches_variant` compares hosts
  on label boundaries instead of `url.contains(variant)`, so
  `notgoogle.com` and `google.com.evil.tld` no longer appear in a `google.com`
  query, while real subdomains and the ccTLD clusters (`google.co.*`) still do.
  Title/username matching stays fuzzy on purpose (that is a search box).

- **In-page dropdown skin (this batch):** the login dropdown and the 2FA picker
  now share one Aegis skin - 12px panel on `#0b1326`, search row, `DOMAIN` +
  account-count meta, 30px avatar tiles, icon-only status (shield-check =
  verified here, recycle = reused, warning = weak, clock = old; labels stay in
  tooltips/aria), a hover `Fill` pill, and a footer with only the keys that work
  (`↵` picks the first row when the filter exists, `Esc` closes). Row data and
  ranking are unchanged; the old emoji prefixes ("🔑", "✅", "(unused?)") and
  prose badges are gone. The mockup's AES-256 / enclave / AegisCloud / score
  chips were deliberately not copied - no backend proves them. Verified by
  serialising the real jsdom render and screenshotting it in headless Chromium
  (4 seeded accounts, both surfaces); npm tests 135/135.

  The in-field badge (the shield the extension docks inside a password box) got
  the same treatment: 26px mint chip with a dark shield glyph (cyan + spark on
  new-password fields), hover lighten, no emoji. Verified the same way against
  a mock password field.

- **A23 slice 1 — local API + `pv` CLI (this batch):** opt-in Settings toggle
  starts a **loopback-only** (127.0.0.1, random port) read API. The 32-byte
  token is DPAPI-sealed (`pv_api_token.dpapi`), expires in 24h and is revoked on
  disable. Every `pv get` enqueues a pending request; the UI thread polls with a
  200 ms Slint `Timer` and shows an **Allow once / Deny** modal (the worker never
  touches Slint - component handles are thread-affine). Pending TTL 60s (the CLI
  waits 50s), 30 requests/min, audit log stores credential id + field only.
  CLI: `phantom_vault pv status | pv get <title|--id> [--field password|username]
  [--json]`; the client polls `/v1/result`. Locked vault → 423, wrong/expired
  token → 401. Tests +4 (token, handler, loopback e2e, CLI parse) →
  `cargo test` **532 passed / 2 ignored + 4 pv_sign**; `npm test` **133/133**.
  Read-only slice: `run`/`inject`, scopes and auto-start are next.

- **A13 slice 1 — KeePass KDBX import (this batch):** `.kdbx` (KDBX 3.1/4) is
  sniffed by its binary magic and opened with the per-file password (or
  password + key file at the API level). The MIT `keepass` crate performs the
  container crypto; PhantomVault only caps the declared KDF work
  (`kdbx_kdf_guard`: Argon2 ≤1 GiB/≤200k iterations/≤64 lanes, AES-KDF
  ≤20M rounds) and maps decrypted entries through the existing `RawItem`
  pipeline (folders, TOTP, custom fields; attachments/history not modeled).
  Real KeePassXC fixtures cover Argon2/AES-256, Argon2id/ChaCha20 and
  password+keyfile. **Slice 2 (this batch):** `export_kdbx` writes KDBX4
  (Argon2id/AES-256) from active logins — title/user/password-protected,
  URL/notes, `otp` as an otpauth URI, hidden custom fields protected, nested
  folders, trashed items skipped. UI action 5 uses the reprompt modal's
  separate 12+ character KDBX password (never the master); logins-only is
  documented (cards/notes/passkeys stay in `.pvx`/CSV). Round-trip test:
  vault → KDBX → importer. Tests +9 → `cargo test` **528 passed / 2 ignored +
  4 pv_sign**; `npm test` **133/133**.

- **A15d — automatic P2P re-bind (this batch):** `p2p_pairing::bind_peer_addr`
  plus a key-based `p2p_local::verify_peer_response`: a response is trusted by
  the **signed device key**, not by the source IP. `pull_peer`/`push_peer`
  re-bind a paired peer to its new LAN address only after the head anchor and
  blob integrity checks pass; an unknown host still answers 403 and the user is
  asked for its pairing code. The loopback e2e test now moves the stored
  address, pulls with no code and asserts the re-bind. Tests +2 →
  `cargo test` **519 passed / 2 ignored + 4 pv_sign**; `npm test` **133/133**.

- **A22 Phase A/B — PQ-paranoid profile (this batch):** a new container profile
  that needs the master password **and** this device's ML-KEM decapsulation key.
  Phase A added `security/pq_profile.rs` (generate/seal/load `pq_device.dpapi`
  with DPAPI; missing/corrupt fails closed). Phase B adds `PV3\0`
  (`crypto.rs`) with layout `magic | salt 16 | kem_ct 1088 | nonce 24 | ct+tag`,
  key chain `HKDF-SHA256(salt = ML-KEM shared secret, ikm = Argon2id key,
  info = "phantom_vault_paranoid_v1")`, `ContainerProfile` +
  `save_vault_secret_with_profile` + profile dispatch in `storage.rs`, and a
  sync-merge guard that refuses `PV3` blobs. Missing sidecar is a distinct error
  (`This vault requires this device's PQ key`), never a password error and never
  a portable fallback. Rekey preserves the profile (rev+1, same device key).
  `meta.profile` is validated against the magic; unknown/downgrade fails closed.
  Tests +3 → `cargo test` **509 passed / 1 ignored + 4 pv_sign**; `npm test`
  **133/133**. Phase C (this batch) adds the Settings card + two-tap disable,
  the mandatory in-session encrypted `.pvx` export gate
  (`PARANOID_BACKUP_READY`), `storage::convert_vault_profile` (lock →
  round-trip proof → rotate `.bak.1.enc` → swap), profile-preserving saves
  (no silent downgrade; missing sidecar fails loudly), `current_profile`
  magic read, and sync/P2P/merge/startup-pull refusal for `PV3`. Device key is
  reused on re-enable and kept on disable so older paranoid backups stay
  openable. Tests +2 → `cargo test` **511 passed / 1 ignored + 4 pv_sign**;
  `npm test` **133/133**. Honest limits: DPAPI is user+machine bound (not a
  TPM), the offline cache/`.pvx` stay password-sealed, and paranoid is
  single-device by design. **D1 (this batch):** TPM custody layer shipped —
  `src/security/pq_tpm.rs` (`PVT1`, CNG RSA-2048 OAEP-SHA256 wrap + XChaCha20
  DK seal, platform **and** software KSP), backend-aware `pq_profile`
  (`generate_and_seal_with`, `active_backend`), strict TPM→DPAPI load order
  with **no hidden fallback**, atomic sidecars, software-KSP tests, and a
  real-TPM manual roundtrip on this machine. **D2 (this batch):** the enable
  flow prefers TPM and falls back to DPAPI with a visible backend label;
  Settings shows `Device key: TPM 2.0 (hardware-bound)` / `DPAPI (software
  fallback)` and offers a proof-first **Move device key to TPM** (reseal →
  in-memory unseal → live vault load → delete DPAPI; failure rolls back).
  `.tpm` joins the factory-reset sweep. Migration is explicit only — never on
  unlock. **D3 (this batch):** no-TPM fallback covered by a test-only hook,
  measured TPM timings (unseal ~316–352 ms), and a **public**
  encapsulation-key cache keyed by sidecar bytes (0 ms per save; the DK is
  never cached), plus release notes. Tests +6 → `cargo test` **517 passed /
  2 ignored + 4 pv_sign**; `npm test` **133/133**.

- **A5 — master password rekey (this batch):** `storage::rekey_vault_secret`
  proves the old password against the live container, encrypts under the new
  one (fresh Argon2id salt + fresh ML-KEM keypair, KDF params untouched),
  round-trip-verifies, proves the old password no longer opens it, rotates the
  previous container to `.bak.1.enc` (still old-password) and writes
  atomically. Settings > Security gains the three-field card + two-tap
  confirm (`change_master_password`). On success: RAM master replaced, Hello
  token re-sealed, App PIN removed (PIN is unrecoverable), shard nudge reset,
  metadata-only `rekey` access-log event, sync push. Deliberate: `.pvx`, old
  backups and GitHub history stay on the old password. Tests: +6 â†’
  `cargo test` **481 passed / 1 ignored**, `npm test` **118/118**. A4 hardware
  clipboard QA still unverified (gap doc Â§5.7).

- **A9 â€” edit-before-save (this batch):** `content.js` now has one
  `credentialToast` builder behind `saverToast`/`updateToast`. The prompt shows
  the submitted username and password in real inputs (password masked) inside a
  **closed** shadow root, so the pair can be corrected before anything is
  stored and a page script cannot read it back out of the DOM. Save reads the
  edited values, trims the username only, blocks an empty pair with an inline
  error, and re-classifies against `existingSync` so a pair equal to a stored
  entry stops with "already saved" instead of a host round-trip. The 30 s timer
  re-arms on typing and refuses to close while a field is focused; Escape
  inside a field keeps the edit, elsewhere it dismisses. Tests: +6 â†’
  `npm test` **124/124**, `cargo test` 481 unchanged. Honest limit: a closed
  shadow root is a DOM boundary, not a keyboard boundary â€” the page can still
  see key events, as it can for the original typing.

- **A6 â€” independent backup passphrase (this batch):** new `.pvx` exports are
  `b"PVBK1"` + the unchanged portable envelope, sealed with a **backup
  passphrase** instead of the vault master (`exporter::export_native_encrypted`,
  `BACKUP_V2_MAGIC`). Export gate (`backup_pass_error`): â‰¥12 characters, confirm
  must match, and the value must **differ from the master** â€” reusing the master
  is refused outright. The master reprompt stays as proof of presence. Import
  checks the tag first (`Format::PhantomBackupV2`) and decrypts a tagged file
  **only** with the backup field; a missing/wrong passphrase fails with an
  explicit message and leaves the vault untouched. Untagged files take the
  legacy path (master password) so pre-A6 backups still import. UI: two modal
  fields for encrypted export + an optional "Backup passphrase" field on the
  Import screen, both cleared once Rust owns the secret. `crypto.rs` unchanged;
  fresh salt per export (asserted). Tests +4 â†’ `cargo test` **485 passed / 1
  ignored**, `npm test` **124/124**.

- **A8a â€” certificate-free release pipeline (this batch):**
  `.github/workflows/release.yml` runs on `v*` tags: verifies tag == Cargo
  version, refuses without `PV_SIGNING_KEY`, then calls
  `scripts/package_release.ps1` (the same script used locally) to run
  `cargo test` + `npm test`, build the release exe, compile `installer.iss`,
  zip both extensions, write a CycloneDX SBOM, hash every asset
  (`<asset>.sha256` + `SHA256SUMS.txt`) and sign every `.exe`/`.zip`.
  `tools/pv-sign/src/main.rs` (its own crate, no app dependency graph)
  produces raw 64-byte Ed25519 `<asset>.sig` and refuses a
  key that does not match the pinned key; `src/release_pubkey.rs` is now the
  single source of truth (updater re-exports it). Releases ship both the Inno
  installer and `PhantomVault-<ver>-windows-x64.exe`; `pick_asset` now skips
  `setup`/`installer` names and refuses an installer-only release, so the
  updater can never swap the installer over the live app. The workflow
  publishes the release and a GitHub build-provenance attestation. **No UPX** â€”
  the old sub-8MB target came from v0.2.0 (6.7 MB); the published 0.4.1 exe is
  19.77 MB (0.4.0 was 19.55 MB) and the installer 8.98 MB, so
  `docs/RELEASE.md` records the real size instead.
  **Key rotation:** the old pinned key had no available private half, so a new
  key was generated. Seed: `%USERPROFILE%\.phantomvault\release_signing.key`
  (user-only ACL, never printed by keygen). The GitHub secret `PV_SIGNING_KEY`
  is set and verified via `gh secret list` (the maintainer's stored OAuth token
  was used; the seed was piped through stdin, never echoed). Clients built
  before this change must reinstall once manually.
  **First live run (2026-10-31):** tag `v0.4.1` published automatically by
  `release.yml`. Assets: setup exe 8,979,423 B, portable exe 20,727,808 B,
  both zips, `.sig` + `.sha256` for each, CycloneDX SBOM (583 components) and
  `SHA256SUMS.txt`. Verified after download: both exes' `.sig` against the
  pinned key, hashes equal the API digests and `SHA256SUMS.txt`, and
  `gh attestation verify â€¦ --repo zjhasan13/phantom_vault` exited 0.
  `security.yml` is green on the tag commit too.
  Tests +4 â†’ `cargo test` **485 passed / 1 ignored + 4 pv_sign tests**; `npm test` **124/124**.
  Authenticode (A8b) remains open â€” no certificate.

- **A11 â€” offline read-only extension cache (this batch):** Settings > Security
  gains an opt-in toggle. On enable (and at every unlock while enabled) the app
  writes a **logins-only** snapshot (`vault_cache.enc`, `PVOC1` +
  XChaCha20-Poly1305) under a fresh 32-byte key sealed with DPAPI
  (`vault_cache_key.dpapi`). The native host answers exactly one command,
  `cache_get`, while the desktop is closed: it prompts **Windows Hello**, then
  unseals and returns the snapshot. Every other command still requires the P1
  heartbeat. The extension keeps the decrypted entries only in service-worker
  memory for 15 minutes (`OFFLINE_TTL_SECS`), clears them on `PV_GATE_LOCKED`,
  and serves `PV_QUERY` from the cache with `cached: true` + a visible banner.
  Read-only: mutations hit the closed host and fail; reprompt-armed items are
  refused offline in both popup and content paths. Decoy unlock **deletes** the
  cache; rekey refreshes it; disabling deletes both files.
  Tests +4 Rust (Trash exclusion, AEAD tamper/wrong key, DPAPI disk round-trip,
  clear) and +4 JS (fallback, TTL reuse, lock clearing, empty-query guard) â†’
  `cargo test` **489 passed / 1 ignored + 4 pv_sign tests**; `npm test`
  **128/128**. Honest limit: Hello is a presence prompt, not a key factor â€” a
  same-user process can unseal DPAPI without it, and the snapshot refreshes
  only at unlock.

- **A15a â€” mandatory P2P pairing (this batch):** new `sync/p2p_pairing.rs`:
  per-device Ed25519 key (DPAPI), one-time 64-bit code (5 min, single-use, never
  sent over the wire), HMAC pair proof, DPAPI-sealed paired-device list, and
  Ed25519-signed `pull`/`sync` requests (timestamp Â±120 s). `p2p_local.rs`
  now answers only `/p2p/pair` unauthenticated; every other request without a
  paired signature gets 403. The shown P2P "PIN" is now the pairing code; a
  paired device syncs without re-entering it (address-based lookup). Legacy PIN
  code is retained only for old route tests/migration. Tests +3 â†’
  `cargo test` **499 passed / 1 ignored + 4 pv_sign**; `npm test` 132/132.
  **A15b:** beacons now carry only an ephemeral per-process ID (no head
  SHA/mtime; legacy parse fallback only), and Settings lists paired devices with
  a Forget action (`list_pairs/forget`). Remaining: response signing, QR, and
  wiring A16's fresh-device anchor to the paired head.

- **A15b â€” ephemeral beacons + paired-device UI (this batch):** `Peer` no longer
  carries `head_sha`/`pin_required`; `beacon_json` emits `{app,name,version,port,id,ts}`
  with a random per-process `id`, and `parse_beacon` accepts legacy `head_sha`
  only for discovery. Settings gains a paired-device list (name, key prefix,
  address) with **Forget**, which removes the key from `p2p_paired.dpapi` so the
  next request is 403. Tests +1 â†’ `cargo test` **500 passed / 1 ignored + 4
  pv_sign**; `npm test` 132/132.

- **E5 â€” never-save Settings UI (this batch):** popup Settings lists
  `never_save_domains` (sorted) with a per-domain **Remove**; removal rewrites
  `chrome.storage.local` and `content.js`/`background.js` pick it up live via
  `storage.onChanged`/the background lookup. Test +1 JS â†’ `npm test` **133/133**,
  `cargo test` 505/1 unchanged.

- **T5 â€” reproducible-build documentation (this batch):** added
  `docs/REPRODUCIBLE_BUILDS.md` (pinned inputs, clean rebuild, hash + Ed25519 +
  attestation verification, honest non-bit-reproducible list, T5b target).
  Docs-only; `cargo test` 505/1 and `npm test` 133/133 unchanged.

- **A19 â€” remote canary alert (this batch):** `record_trip` still writes the
  local log, then sends `{id,time,title_hash,via,device}` to paired peers via
  `POST /p2p/canary` (signed by A15 keys; no title/secret leaves). Unreachable
  alerts queue in `canary_pending.jsonl` and retry on P2P enable; the receiver
  appends a `CANARY-TRIPPED-REMOTE` line and a startup flag that `main` turns
  into a notification. Tests +1 â†’ `cargo test` **505 passed / 1 ignored + 4
  pv_sign**; `npm test` 132/132. Honest limit: P2P reachability required for
  live delivery; no dead-drop yet.

- **A18 â€” indistinguishable decoy provisioning (this batch):** decoy moved from
  `decoy_vault.enc` to `my_secure_vault.enc.bak.0.enc` (looks like an extra
  backup; rotation only touches 1â€“5) and is written with
  `save_vault_secret_flat` (no nested backups). The `duress.dpapi` verifier is
  gone â€” the decoy AEAD tag is the password proof. `storage.rs` pads every JSON
  payload to a 1 MiB bucket, so a typical vault and decoy share the same
  container size. Legacy files migrate on first use and are in the factory-reset
  list. Tests +2 â†’ `cargo test` **504 passed / 1 ignored + 4 pv_sign**;
  `npm test` 132/132. Honest limits: mtimes are not aligned, >1 MiB attachments
  can change the size class, and the decoy is still a separate container.

- **A15c â€” response signing, QR, A16 anchor (this batch):** every framed P2P
  response is signed with the host device key (`sign_response/verify_response`,
  `X-PV-Key/Time/Sig`); clients verify before parsing. The one-time code renders
  as a self-contained SVG QR (`qr_svg`, Settings image) alongside the text.
  Pairing pins the host `rev`/`hash`, pull responses carry it, and `head_ok`
  refuses a lower revision / same-rev different hash; a successful pull updates
  the pin. Tests +2 â†’ `cargo test` **502 passed / 1 ignored + 4 pv_sign**.
  Push-side anchor now sends the client head and the server refuses a lower
  revision (409) before adopting. Remaining: re-pair on address change.

- **A16 â€” signed container revision (this batch):** the AEAD payload is now a
  rev-2 envelope `{meta:{format,version,rev,prev_hash}, vault}`. Save increments
  `rev` and sets `prev_hash = SHA-256(previous container)`; a per-path
  in-process head also refuses a save when the file changed underneath
  ("unlock again"). `check_incoming` refuses a lower rev, equal-rev/different
  hash, or a newer rev that does not chain to the local hash; the GitHub merge
  path calls it before merging. Legacy plain-Vault payloads load as rev 0 and
  migrate to rev 1 on the next save; rekey writes rev N+1 chained to the old
  container. Tests +3 â†’ `cargo test` **496 passed / 1 ignored + 4 pv_sign**;
  `npm test` **132/132**. Honest limits: fresh-device first pull is TOFU (no
  local anchor), P2P still uses the mtime/SHA guard (A15), and **older builds
  cannot open rev-2 vaults** â€” upgrade every device before syncing.

- **A12 â€” shadow-DOM scan/observer (this batch):** `content.js` gains
  `deepRoots`/`deepQuery`/`deepActiveElement` (open roots only, 200-root/20k-node
  caps, skips `__pv_*`). `findFields`, card/address queries, `passwordNear`, the
  OTP split-group anchor and `scanForms` use the deep query; `badgeGroup` treats
  a shadow tree as its own scope; `deepActiveElement` covers generate/auto-submit
  focus. Every discovered open root gets the same debounced `pvScheduleScan`
  observer, and `watchSubmit` attaches to deep `<form>` elements (submit does not
  cross a shadow boundary). Closed roots remain untouched. Tests +3 JS â†’ `npm
  test` **132/132**; `cargo test` 493/1 + 4 pv_sign unchanged. Honest limit:
  closed components are invisible; traversal caps may skip pathological pages.

- **A17 â€” same-origin favicons (this batch):** deleted the DuckDuckGo and Google
  fallbacks in `src/core/favicon.rs`. The only fetch is now
  `https://{domain}/favicon.ico`; the extension's page-declared icon harvest is
  unchanged and still preferred. Toggle/kill-switch/`can_net` gates untouched.
  Test `icon_url_is_same_origin_only` pins the host and forbids the third-party
  names from reappearing. `cargo test` **493 passed / 1 ignored + 4 pv_sign
  tests**; `npm test` **129/129**. Honest limit: the site sees its own icon
  request and may redirect to its CDN; no bundled icon set yet.

- **A11b â€” dual-gate offline cache (this batch):** the same DPAPI cache key can
  now be opened by **Windows Hello** (`cache_get method:"hello"`) or the
  **extension PIN** (`method:"pin"`), verified through A14's Argon2id record and
  the same persistent lockout. `cache_status` is prompt-free
  (`{enabled,pin_set,pin_allowed}`), so the popup's offline screen offers Hello
  plus a PIN field only when the user separately enabled the PIN fallback
  (`offline_cache_pin.pref`, default OFF). Background queries never prompt on
  their own: they serve a warm 15-minute snapshot or return "locked". Replacing
  or removing the PIN revokes the fallback (re-consent), and cache disable/decoy
  erase the marker with the snapshot. Tests +1 Rust (PIN gate, consent required,
  wrong PIN) and JS now 129. Honest limit: strength = min(Hello, PIN); a 4-digit
  PIN is 10k candidates, so the fallback stays opt-in and is labelled weaker.

- **A14 â€” Argon2id extension PIN (this batch):** `ext_pin.dpapi` no longer
  stores/serves a bare SHA-256. The record is `PVPIN2|salt|m|t|p|hash` with a
  16-byte salt and Argon2id (32 MiB, t=3, p=4), sealed with DPAPI. The host
  verifies (`ext_pin_verify`) and the bridge returns only `set: true/false`
  (`ext_pin_status`); the popup no longer hashes or compares anything. A
  file-backed attempt counter (`ext_pin_backoff`) survives restarts: 5 failures
  â†’ 30 s, then 60/120/300 s; success/set resets it. A legacy SHA-256 record is
  refused with "re-set the PIN in Settings", never silently honoured.
  Tests +2 â†’ `cargo test` **491 passed / 1 ignored + 4 pv_sign tests**;
  `npm test` **128/128**. Honest limit: 4-digit PIN entropy is 10k; Argon2id +
  lockout raise the cost but same-user malware can grind the DPAPI record
  offline.

- **A7 â€” trust documentation (this batch):** three files at the repo root, written
  from the code, not from marketing. `README.md` (features, container/KEM summary,
  build/test commands, repo map, doc index, and a "Known gaps and honest limits"
  section that names the unsigned installer, the missing external audit, Windows-only
  scope, PQ-is-not-a-factor, the closed-shadow keyboard limit, old-password backups
  after a rekey, the favicon third parties and the open P2P LAN default). `LICENSE`
  is MIT (Copyright (c) 2026 Zahidul Islam) and `Cargo.toml` now declares
  `license = "MIT"` plus repository/description/readme. `SECURITY.md` uses GitHub
  private advisories as the only channel (no invented email or PGP key), with
  supported versions, 7/14-day response targets, a 90-day coordinated window,
  explicit in/out-of-scope lists, the 0.4.1 limitations and a safe-harbor statement.
  No code changed; `cargo check` and `npm test` (124) stay green.

- Branch `main`. Tier 0 + audit Phases 1â€“6 committed (`117e38b`, `96b9330`,
  `b850ce7`, `05c0a36`, `e06d841`, `fc36e65`, `e6eadf5`).
- **Deep audit (`docs/AUDIT.md`)** â€” 5-agent read-only sweep + inline
  verification. Verified: "Lock" sidebar item exits the process
  (`slint:1349`â†’`main.rs:11665`; **FIXED in Phase 4**); legacy passkey `uv` boolean
  trust (`native_host.rs:507`, low reach â€” relay uses `assert_full`/`uv_token`);
  `crypto.rs:131-136` skipped `zeroize()` on the decrypt-error branch
  (FIXED in Phase 1 below).
  Two agent claims marked FALSE POSITIVE (do not re-chase): `fill_counts`
  serde panic (`native_host.rs:1670` â€” same pattern tested at `:2467`);
  `backup_scheduler` "wrong file" (relative `VAULT_FILE` is a project-wide
  convention, `main.rs:44`).
- **Tier 0 â€” extension capture engine** (`browser_extension/` ONLY, no Rust/exe
  rebuild; `node --test tests/js/background.test.mjs` **19/19**, `build.ps1`
  chrome+firefox OK): fixes registration / multi-page credential capture
  "gives up".
  - G1/G2/G3: `readFormCreds` replaces the inline submit reader â€” `new-password`
    fallback so a pure-signup form (no non-new password input) is no longer
    skipped; `maybeOfferSpaSave` now consumes `findFields.newPass`; signup vs
    login classified by field shape; a confirm-password mismatch refuses to
    offer (typo guard).
  - C1/C2: `getExisting` is a 60 s in-flight-deduped credential-list cache.
    The submit verdict is computed **synchronously** off a warm cache (no
    `await` before the banner â†’ survives a full-page POST nav); invalidated on
    save. SPA ping reads the DOM immediately + one 400 ms retry (was a flat
    2500 ms wait). Badge probe (`probePageMatch`) shares the same cache.
  - K1/K2: non-secret username carry across pages in `chrome.storage.session`
    (`pvCaptureCarry`, username only â€” P1-b intact; password never persisted) +
    one-time `setAccessLevel(TRUSTED_AND_UNTRUSTED_CONTEXTS)` at SW start.
  - Tests: `npm test` â†’ **25/25** (19 background + 6 jsdom content). Added
    `package.json` + `jsdom` devDependency (dev-only, `node_modules` ignored);
    `tests/js/content.test.mjs` loads the REAL `content.js` in jsdom and covers
    login / signup-new-password / confirm-mismatch / multi-page carry /
    known-silent / search-immunity. Background-side: K2 accessLevel,
    `PV_SAVE_LOGIN` proxy, cross-site sender refusal. Manual matrix:
    `docs/QA_CAPTURE_MATRIX.md` (CAP-01..16 + REG-01..06).
  - **Untouched by design:** `pvPending`, `chainPendingStep`, `sweepOtpOnce`,
    `otpObserver`, popup fill path, native host.
- **Phase 1 â€” Rust data integrity (DONE `96b9330`):**
  - D5 (>1 MB sync data loss): `sync/github_sync.rs` gains `decode_remote_blob()`
    â€” refuses an empty/whitespace body (GitHub Contents API returns `content:""`
    for files >1 MB) and bad base64. `main.rs` adopt path independently refuses a
    zero-byte remote (defense in depth). Was: `""` â†’ empty vault â†’ fresh device
    wrote 0 bytes.
  - D6: `crypto.rs` `decrypt_vault_secret` zeroizes the derived key on the error
    branch too (`?` used to skip it).
  - Unicode panics: `importer/mod.rs` `parse_bw_datetime` uses `str::get` for the
    `Â±hh:mm` suffix (no `split_at`/byte indexing); `developer/secret_scanner.rs`
    `scan_line` uses `to_ascii_lowercase` + `get` (byte-length-preserving
    offsets). Multi-byte input can no longer panic.
  - Atomic backups: `storage/backup_scheduler.rs` writes `.vault_backup_*.tmp`
    then renames (crash/full-disk can't leave a truncated `.enc`).
  - Tests: +5 cases (github empty/garbage decode, datetime offsets+unicode,
    scanner unicode, atomic backup). `cargo test` â†’ **451 passed / 1 ignored**.
- **Phase 2 â€” security (DONE `b850ce7`):**
  - D3 access log fail-closed: `security/access_log.rs` â€” an unreadable chain
    key now REFUSES the append with a loud stderr line instead of falling back
    to unkeyed SHA-256 (`log_event_gated`). `verify_at_detailed` reads the key
    read-only (no mint) and can't create one as a side effect.
  - D4: `security/emergency.rs` zeroizes the plaintext shard `Vec` on both the
    seal and open paths (was only the HKDF key).
  - E3: new shared `browser_extension/domain.js` (`pageBase`/`isBlockedHost`/
    `isPunycodeHost`), loaded by `popup.html` + packaged by `build.ps1`. The
    popup's direct-inject fill (`fillGuards`, now async) and suggestion list
    refuse blocked domains and punycode hosts, matching `content.js`.
  - D2 passkey legacy `uv` boolean: confirmed unreachable from the extension
    (only `assert_full`/`attest` + `uv_token` are sent); legacy parity kept, no
    code change.
  - Tests: `tests/js/domain.test.mjs` added â†’ `npm test` **28/28**.
- **Phase 3 â€” shared domain logic (DONE `05c0a36`):**
  - E1: `domain.js` `registrable()` now keeps multi-label public suffixes
    (`foo.co.uk` â†’ `foo.co.uk`; `shop.foo.co.uk` â†’ `foo.co.uk`,
    `www.google.co.uk` â†’ `google.co.uk`) using a pragmatic PSL subset.
  - E2: `EQUIV_CLUSTERS`/`memberHit`/`domainCands`/`domainsEquiv` exist only in
    `domain.js`; `content.js`, `background.js`, `popup.js` are thin wrappers.
  - Wiring: both manifests `"js": ["domain.js", "content.js"]` (order matters);
    `background.js` starts with `importScripts("domain.js")` (classic MV3 SW);
    `popup.html` loads it before `popup.js`; `build.ps1` already packages it.
  - Harnesses: background sandbox stubs `importScripts`; the jsdom content
    harness evaluates `domain.js` before `content.js`.
  - Tests: +4`domain.test.mjs` cases (registrable ccTLD, pageBase, clusters,
    ccTLD blocked gate) â†’ `npm test` **32/32**; `cargo test` 452 unchanged.
- **Phase 4 â€” real lock + iframe capture (DONE `e06d841`):**
  - D1: sidebar Lock (`slint:1350` â†’ `main.rs:11677`) and tray Lock
    (`main.rs:3355`) now call the shared `lock_vault_now` pipeline â€” RAM scrub,
    clipboard flush, access log, lock screen â€” instead of `process::exit(0)`.
    New sidebar **Exit** (`slint:1351`, `on_exit_app`) + tray **Exit** are the
    only quit paths (clipboard flushed first, log event `exit`). Unlock already
    existed in the Slint lock screen, so no new screen was added.
  - E4: both manifests `all_frames:true`; the original same-origin guard (removed in P6) returned before any
    setup unless the frame is top-level or SAME-ORIGIN (reads `top.location`,
    throws on cross-origin â‡’ inert). No `match_about_blank` (hostless origin â‡’
    refused). Prevents a third-party iframe from raising a save prompt for its
    own host. (P6 later superseded this with frame-local-origin matching.)
  - Tests: `tests/js/content.test.mjs` +1 manifest/guard regression â†’
    `npm test` **33/33**; `cargo test` **452 passed / 1 ignored**.
- **Phase 5 (audit) â€” E5 desktop-gate cache (DONE `fc36e65`):**
  - `content.js` `extDeskOkPage` is no longer page-lifetime: success is cached
    for at most `EXT_DESK_OK_TTL_MS = 30 s`, and the cache is dropped on
    `window.focus`, tab-visibility return, and bfcache `pageshow`; a
    `PV_SESSION_STATE` locked reply clears it immediately. Worst-case staleness
    is 30 s, and every secret still rides the native bridge gate (UX-only fix).
  - Test: `E5: desktop gate is bounded by TTL and dropped on focus` stubs
    `Date.now` â†’ one probe warm, re-probe after 31 s, re-probe after `focus`.
    `npm test` **34/34** (19 background + 8 content + 7 domain). Extension-only;
    no Rust rebuild.
- **Phase 6 (audit) â€” E6 observer + lock broadcast (DONE `e6eadf5`):**
  - E6: the two synchronous `documentElement` subtree observers became ONE
    120 ms-debounced observer (`pvScheduleScan`) running `scan()` +
    `scanForms()`; cold-page boot scans stay immediate.
  - E5 follow-up: `background.js` `broadcastGateLocked()` pushes
    `PV_GATE_LOCKED` to every tab when a `PV_SESSION_STATE` reply is locked or
    a `PV_PING` fails / reports `unlocked:false`; content drops its gate cache
    on receipt. Lock/timeout now invalidates all tabs immediately.
  - Tests: +3 (background broadcast fan-out, content broadcast invalidation,
    E6 static guard) â†’ `npm test` **37/37** (20 background + 10 content +
    7 domain). Extension-only; no Rust rebuild.
- Extension OTP UX shipped (`ec789db`): multiple-2FA sites now open the
  account picker on OTP-field focus/sight (login-dropdown parity, gated by
  `show_suggestions`); picker rows carry â™»ï¸/ðŸŸ¡/ðŸ•°ï¸ health icons joined
  client-side from `PV_QUERY`. Working-badge + recency already native
  (3rd-fill auto-verify `models.rs:601`) â€” untouched. Extension-only: rebuild
  via `browser_extension/build.ps1`, NO exe rebuild. QA physical: 1-account
  auto-fill, 2-account pickerâ†’choose, submitâ†’âœ… upore, health icons.
- **P0 (fill strength) â€” URL-less web fill hole (DONE `6a4b0c6`):**
  - Finding: desktop items carry no URL (`urls: []`), but `content.js` and
    `popup.js` treated an empty URL list as allow (`entryAllowed`), and native
    `query` is substring-based â†’ lookalike domains could autofill desktop
    items. Fixed both gates to refuse URL-less entries; content skips them
    silently (phishing toast only for stored-URL mismatches), popup shows
    "No site URL saved â€” edit this item and add one."
  - Tests: +4 (url-less hotkey refusal + bound control in jsdom, popup
    gate/source assertions) â†’ `npm test` **41/41**; extension-only.
- **P1 (fill strength) â€” capture URL/title quality (DONE `620bf68`):**
  - `captureUrl()` stores origin+path only (query/hash stripped, trailing
    slashes normalized); `captureTitle()` prefers `og:site_name` /
    `application-name` / `apple-mobile-web-app-title`, else strips title
    suffixes and skips generic segments ("Sign in", "Login", â€¦), else host.
  - Native `canonical_login_url()` mirrors the normalization in `save_login`
    (older clients can't inject query/fragment into the vault).
  - Tests: +2 jsdom save-payload + 1 Rust canonicalization â†’
    `npm test` **43/43**, `cargo test` **453 passed / 1 ignored**.
- **P2 (fill strength) â€” desktop app binding (DONE `ce43147`):**
  - `Credential.apps: Vec<String>` (`#[serde(default)]`, additive/export-safe).
    Smart-Grab stores lowercased exe + pretty name via hidden `cap_app`.
  - QuickBar (`Ctrl+Alt+A`) prefers items bound to the focused app; Auto-Type
    refuses bound items in any other app (`autotype-blocked-app` log). Unbound
    web items are unaffected.
  - Tests: +2 (serde default, binding helper) â†’ `cargo test` **455 passed /
    1 ignored**; `npm test` 43/43 unchanged.
- **P3 (fill strength) â€” popup fill parity (DONE `dbd721a`):**
  - Popup fill/fill-submit now delegates to content.js `PV_FILL_ENTRY {id}`;
    content re-queries by domain, re-checks `entryAllowed`, fills through
    `fillLogin()` (React setters, multi-step, TOTP pending) and returns the
    field count. Direct inject is fallback only; refusals keep their reason.
  - Tests: +2 jsdom + 1 popup source â†’ `npm test` **46/46** (20 background +
    16 content + 7 domain + 3 popup).
- **P4 (fill strength) â€” UIA `SetValue` desktop fill (DONE `6e31196`):**
  - `desktop_autofill::set_focused_value()` writes the focused enabled,
    writable Edit via `ValuePattern.SetValue` (no keystrokes/IME/clipboard).
    Both `type_sequence` and `type_fields` try it per field and fall back to
    the verified Unicode SendInput path; read-only password boxes therefore
    keep working. Input still sanitized; focus token re-checked before every
    fill / Tab / Enter.
  - Test: +1 policy gate â†’ `cargo test` **456 passed / 1 ignored**.
- **P5 (fill strength) â€” UIA login field-pairing (DONE `9f7c298`):**
  - App-bound desktop logins try `fill_login_pair()`: locate the password Edit
    (focused if password, else first) + nearest username Edit above it in the
    foreground window; verify both writable before writing; revert partial
    writes; refuse when focus is an Edit outside the pair (chat/search box).
    Success = SetValue both, `autotype/uia-pair` log, Enter â€” no Tab dependency.
  - Fallback chain stays: per-field UIA SetValue (P4) -> guarded Unicode typing.
  - Test: +1 `pick_login_pair` matrix -> `cargo test` **457 passed / 1 ignored**.
- **P6 (web fill strength) - cross-origin iframe fill (DONE `7e6da61`):**
  - `content.js` boots in cross-origin frames instead of self-disabling; badges,
    autofill, save prompts and TOTP use the FRAME's own origin for every match
    (top location is never read). A credential can therefore only land in the
    origin it was saved for.
  - Background `PV_SAVE_LOGIN` validates `sender.url` (frame) before
    `sender.tab.url`, so an embedded login is stored under the iframe domain -
    never under the embedding page's domain.
  - `PVDomain.pickActionFrame()` probes all frames (visible password/text field,
    focus, top flag) and picks the form frame; hotkey uses it, context menu uses
    `info.frameId`, both send with an explicit `{frameId}` (fallback 0, never a
    broadcast). Popup gathers frame hosts, merges iframe-domain suggestions
    (max 5 extra origins), applies blocked/punycode/mismatch gates to them, and
    targets `PV_FILL_ENTRY` + direct inject + submit at the same frame. Top-only
    ceremony/OTP popup messages now pass `{frameId:0}`.
  - Tests: +4 background, +1 domain, +2 popup -> `npm test` **53/53**;
    `browser_extension/build.ps1` builds chrome+firefox.
- **Badge noise + card capture (DONE `e8a282f`):**
  - One action-aware icon per context, reconciled every scan: login = shield
    on the password (username folds in), signup = dice only, password-change =
    that shield's menu (fill login OR generate new+confirm), card = its own
    shield. Mode changes/removals drop the old button, so SPA transitions can
    never leave two icons or a stale one. Checkout billing emails are never
    badged. The form-less fallback no longer badges every text input on a page
    that has a password (same form / tight ancestor / 320px only), and
    standalone email badges need a credential-step signal.
  - Card save: `readFormCard()` (Luhn, MM/YY, CVV shape) + masked Save/Update
    banner + `PV_SPA_CARD` tripwire; background `PV_SAVE_CARD` reuses the
    sender-frame check; native `save_card` validates, dedupes by PAN and updates
    expiry/holder/CVV in place (cards stay global, never URL-bound).
  - Card fill repair: `filterEntries()` used to drop card rows (no `urls`);
    `queryCards()` now requests `all:true`, and `fillCard()` handles split
    month/year selects as well as `cc-exp`. `resolveRows()` sticks to the
    anchor's kind (disabled card/identity toggles no longer leak login rows),
    and the generator only writes new/confirm siblings, never the current
    password on a change form.
  - Tests: +12 content, +3 background, +1 Rust -> `npm test` **71/71**,
    `cargo test` **460 passed / 1 ignored**.
- Baselines: `cargo test` 556 passed / 4 ignored, `npm test` 133/133 (four JS harnesses), `cargo check --all-targets` zero
  warnings, `cargo clippy --all-targets -- -D warnings` clean.
- v0.2.1 bumped (Cargo + installer + both extension manifests); v0.2.0 stays
  the rollback anchor until v0.2.1 is tagged (needs QA physical pass first).
- SecretString migration (Phases 1â€“5) DONE: crypto/storage `_secret` variants live,
  all prod call sites (main unlock/save Ã—30+, bridge, CLI, decoy, app_pin) ride
  `SecretString`/`Zeroizing`; legacy `&str` wrappers `#[deprecated]` (compat tests
  only, under `#[allow(deprecated)]`). Models fields stay `String` (disk format
  frozen â€” deliberate). Remaining `&str` edges: decoy-verify, app_pin-enroll,
  Hello-compare (OS/DPAPI boundaries, documented).
- Release v0.2.0 tagged + pushed (`cargo build --release` + UPX 6.7 MB exe,
  chrome+firefox zips, SHA256SUMS in `Desktop/pv-release-0.2.0/`).
- `cargo audit`: HIGHs gone (quick-xml 0.41, webpki 0.103, rxing 0.9, rqrr 0.11).
  Residual (justified): `rsa` (ignored), `bincode` (contained+documented),
  `paste`/`ttf-parser`/`yoke-derive` (transitive).
- Git history purged of vault containers (C1) + force-pushed. **Everyone works
  from fresh clones â€” never push from a stale pre-purge clone.**
- Build env: `CARGO_TARGET_DIR=C:\Users\FAHAD\pv-target` (persisted via setx,
  2026-10-31). D: is only 9.7 GB and filled up twice; C: has ~23 GB free.
  `scripts/package_release.ps1` and `installer.iss` honour the variable
  (`/DMySourceExe`), so a custom target dir does not break packaging.
- Epic roadmap 6â†’7â†’2â†’4â†’1 SHIPPED (per-phase commit + push, no existing
  signatures/behavior broken):
  - #6 breach full-loop checklist (`fe30f10`): vault-side rotation progress
    per health row (`rotation_status` + `health_rows_with_rotation`);
    score/flags/order untouched; site auto-change stays manual by design.
  - #7 limited direct import (`ed10d48`): `importer/browser_direct.rs`
    read-only profile discovery (Chrome/Brave/Edge/Opera/Firefox) +
    guided CSV import; direct store decrypt OFF (needs SQLite+AES-GCM /
    NSS key â€” refused loud, documented in module header).
  - #2 emergency timed grant (`402e1df`): `security/emergency.rs`
    (requestâ†’approveâ†’waitâ†’envelope, PQ+XChaCha, maturity enforced in
    `seal_envelope`) + `emergency/<id>.<kind>.json` relay via existing
    private repo (fixed generic commit msg) + copy-paste transport;
    takeover = existing shard recovery. Shamir/PDF untouched.
  - #4 CRDT merge (`d3c3235`): `sync/crdt_merge.rs` explicit preview â†’
    apply only; login LWW on `last_changed`, ties/delete-vs-edit keep
    local + conflict; device unlock factor never merges; grants union
    (revoke wins). Whole-blob adopt paths untouched.
  - #1 per-item sharing (`38ea9cd`): `security/sharing.rs` login-only MVP
    (other kinds refuse loud); `Vault.shared_grants` additive
    (`#[serde(default)]`, pre-sharing JSON loads); revoke = mark +
    mandatory password rotation (issued copies can't be un-issued).
- Epic roadmap 9â†’3â†’5 SHIPPED (mobile/iOS excluded, per-phase commit + push):
  - #9 secure-send (`ab909db`): `security/secure_send.rs` â€” expiring
    XChaCha notes, link-code = key (id = sha256(key)), relay
    `send/<id>.json`, read â†’ expiry-check â†’ decrypt â†’ DELETE (burn);
    delete-fail after good read LOUD; copy-paste offline path included.
    `delete_file` verified in octocrab 0.41.2 vendored source first.
  - #3 passkey ceremony relay (`a8750ad` + test-fix `08dd887`):
    `core/passkey.rs` assertion + fmt-none attestation packaging;
    `native_host` `assert_full`/`attest` (uv-token OR legacy uv) +
    `request_uv` (Hello system prompt â†’ single-use rp-bound 120s token);
    hook 90s hold + timeout fallback; popup approve button; background
    sender-check + Hello-before-sign. Legacy `PV_ASSERT` fail-closed
    test untouched. Caught by tests: UV consume was remove-then-check
    (burned on wrong-rp) â†’ check-then-remove.
  - #5 business admin (`1343968`): `security/admin.rs` â€” member CSV
    roster (machine-local `org_members.json`, factory-reset shredded),
    deprovision auto-revokes key-bound grants, OIDC userinfo email-verify
    (no JWT dep), chain-verified audit JSON export. Explicitly NOT:
    IdP-gated unlock, server SCIM, SAML.
  - Dropped without new cause: #8 mobile/Safari/iOS app (user-excluded),
    plus standing drops below.

## 2. How to resume (new PC / new OpenCode session, any model incl. Muse Spark)

1. `git clone https://github.com/zjhasan13/phantom_vault.git` (fresh â€” no old clones).
2. Read `rules.md`, then this file, then ask the user which pending item to start.
3. Workflow (mandatory): **plan mode first** (spec + file:line touch list, no edits)
   â†’ user approves ("green signal") â†’ **build mode** (implement + `cargo check` +
   `cargo test` + `npm test`) â†’ commit
   (`type(scope): subject (test counts)`) â†’ push `main`.
4. Communication: short, direct, Bengali-mix OK. Every finding cites `file:line`
   + exact code quote. Verify with tools, don't speculate. Never use `bash` to
   communicate; never use comments for chain-of-thought.
5. Quality bar that produced this history: no fix without a regression test,
   no refactor without `cargo check` clean, no push with red tests, honest
   "I don't know yet â€” here is how we find out" instead of guessing.

## 3. Pending queue (ordered)

**Extension gaps (recorded 2026-11-04, still open):**

- **Notes / Cards / Identities editors are desktop-only.** Shipped: the popup
  editor covers all four kinds through the generic `create_item` /
  `update_item` / `delete_item` bridge commands, and "+ Add" opens a kind
  chooser (Login / Note / Card / Identity). What is still desktop-only is
  attachments and password-history browsing.
- **The extension cannot run without the desktop app (by design).** The vault
  key never leaves the app; the native host's `unlocked` gate refuses everything
  else. `offline_cache.rs` exists but is not enabled, so with the app closed the
  popup says "Vault is Locked" - there is no read-only mode yet.
- **No "Continue as ..." shortcut on the password step.** Shipped in this batch
  (`#__pv_continue` chip); remaining polish is only visual tuning against the
  mockup.
- **Installed app 0.4.0 vs extension 0.4.1 (bridge version mismatch).** The
  native host refuses the newer extension until the app is upgraded: run
  `installer-output\PhantomVault-Setup-0.4.1.exe` (in-place upgrade; the vault
  file is untouched), then reload the extension. Until then the popup shows
  "Vault is Locked" even with the app running.

1. **A8b Authenticode â€” deferred by product decision (2026-10-31):** no paid
   certificate for now; Ed25519 + SHA-256 + GitHub attestation is the current
   trust stack. If revisited, insert `signtool` after packaging and before
   hashing (never sign before the final bytes are fixed).
2. **Tray X-still-exits (user reports FIXED on their side):** re-verify on the
   next physical pass (X â†’ process stays as background tray process; Access
   Log close-path lines present). If it regresses, suspects in order:
   handler never fires (Slint close-request path) â†’ panic=abort in handler â†’
   env-specific tray failure.
3. **Live measurements (partial, needs the user's machine):** observed
   minimized+unlocked 7.3 MB / 0.1% CPU (screenshot) â€” still needed:
   locked+minimized release-build reading, idle CPU 0.00% Ã— 5 min, bridge
   warm p50 ~5 ms. Record in release notes.
4. **Master Password Rotation** â€” shipped in-app (A5, Settings > Security).
   The old export/import rotation is no longer needed. After a rekey, reprint
   the recovery shards and re-enroll the App PIN (both stay on the old secret
   until redone).
5. **GitHub cache check:** repo code-search `my_secure_vault` must return
   zero; else request GitHub Support cache purge. `gh` 2.102.1 is installed at `%LOCALAPPDATA%\Programs\gh\gh.exe` but
   not authenticated: run `gh auth login`, then
   `gh api "search/code?q=my_secure_vault+user:zjhasan13"` (web UI code search
   works too). Releases are now built and uploaded by `release.yml` (0.4.1 was
   the first automated run); no manual web-UI upload is needed.
6. **Follow-ups for the other line:** legacy host `assert` unreachable from
   extension (fails-closed test pinned â€” relay now uses
   `assert_full`/`attest`). Resolved (`621892c`): `write_adopted_head` is wired on BOTH
   adopt paths (`serve_conn`, `sync_with_peer`) and the guard is now a tested
   pure function (`adopt_rollback_blocked`); `AgentKey` is explicitly
   `ZeroizeOnDrop` (vault key wipe on session teardown, not just dalek drop).
7. **Standing item (do NOT blind-chase):** `Mutex::lock().unwrap()` pattern in
   `src/main.rs` (panic=abort design). Only touch attacker-influenced paths.
8. **Windows Hello — finish the enrollment/availability split (next UI batch):**
   the crypto path already ships (`seal_hello_token` on every successful
   password unlock, `vault_hello.dpapi` DPAPI-sealed, `request_biometric_unlock`,
   `[Re-enroll Hello]` on device mismatch, token removed on lock/panic/rotation).
   What is still wrong is the *state reporting*, and it is what makes the lock
   row read "not enrolled" on this machine even though a token file exists:
   - expose `hello_enrolled` (token file exists) separately from
     `hello_available` (WinRT `UserConsentVerifier::CheckAvailabilityAsync`);
     today only `hello_available` reaches the UI, so "enrolled but Windows Hello
     is off for this Windows account" is mislabelled as "not enrolled".
   - render four honest states on the lock row and the Settings row:
     available+enrolled (tappable), available+not enrolled ("unlock once with
     the password to enroll"), unavailable+enrolled ("enrolled, but Windows
     Hello is unavailable on this PC"), unavailable+not enrolled ("not
     available on this device").
   - add a **Remove Hello credential** action in Settings (delete
     `vault_hello.dpapi`) next to the status row; today the only removal paths
     are lock, panic wipe, rotation, and factory reset.
   - re-probe availability when the window is shown / Settings opens, so a user
     who configures Hello after launch does not need an app restart.
   - block enabling **Two-factor unlock (password + Hello)** while Hello is not
     enrolled; the unlock path currently downgrades loudly at unlock time
     (`main.rs` "Two-factor unlock is ON but Hello isn't enrolled").
   - keep the honest copy: `UserConsentVerifier` is a Windows Hello *consent*
     prompt, not a FIDO2/WebAuthn assertion, and the token is DPAPI-bound to
     this Windows user, not to a TPM PCR.
9. **Dependabot GHSA-h395-gr6q-cpjc — dismiss now, bump octocrab as its own task:**
   `jsonwebtoken 9.3.1` arrives only through `octocrab 0.41.2`
   (`cargo tree -i jsonwebtoken`); fixed in `jsonwebtoken 10.3.0`. The advisory
   is a type confusion in claim **validation** (`decode`): a malformed `nbf`/
   `exp` is treated as absent, so time checks are skipped. PhantomVault never
   verifies a JWT — `src/admin.rs:170` documents that there is no JWT/id_token
   verification dependency, and the GitHub client is built with a PAT
   (`github_sync.rs:121`), so octocrab only *signs* App JWTs. Not reachable.
   The alert is therefore dismissed as "vulnerable code not used" with this
   rationale; `rustsec/audit-check` stays green because the advisory is not in
   the RustSec DB yet — if it lands as `RUSTSEC-2026-*`, add it to the
   `security.yml` ignore list next to `RUSTSEC-2023-0071`/`RUSTSEC-2026-0387`.
   Real fix when scheduled: `octocrab 0.41.2 -> 0.54.9` (uses
   `jsonwebtoken ^10`), which is a 13-minor-version jump — re-check
   `Octocrab::builder().personal_token`, `is_not_found` error matching
   (`github_sync.rs:131`), and the emergency-export client (`emergency.rs:365`),
   then `cargo test` + one live sync round-trip.
   Dismiss command (needs `gh auth login` first):
   `gh api -X PATCH repos/zjhasan13/phantom_vault/dependabot/alerts/1 -f state=dismissed -f dismissed_reason=not_used -f dismissed_comment="jsonwebtoken 9.3.1 is only reachable through octocrab, which signs GitHub App JWTs; PhantomVault never verifies a JWT (no decode path). Fix tracked as the octocrab 0.54.9 bump."`
10. **Dropped scope (do not revisit without new cause):** full A2 encrypted-RAM
   rewrite (canceled), `rqrr-zeroize` fork (rejected), tokio current-thread
   (rejected), License purchase/vendor/seats, SSH passphrase decrypt,
   name-split/SSN, card billing address.

## 4. Key decisions log (don't re-litigate)

- Persistent extension port: strict FIFO (host echoes no rid), 60 s TTL unchanged,
  stale-read window documented in `background.js` header.
- Toast/UI text uses emoji + Bengali-mix is fine; keep code comments concise.
- Commit style: `type(scope): subject (test counts)`.
- Never force-push without explicit user approval (kills collaborators' work).
- Never commit `*.enc*`, `*.dpapi`, `access.log`, `com.phantomvault.host.json`
  (all gitignored â€” the C1 leak must never recur).
- Release folder (`Desktop/pv-release-0.2.0/`) is DISTRIBUTION only â€” never run
  the app from it (vault/seals accumulate there and could ship by accident).
- installer.iss references a firefox host JSON that the app button (not the
  installer) actually writes â€” placeholder pattern, keep in sync.
- Roadmap no-break contract (6â†’7â†’2â†’4â†’1 proven): additive model fields only
  (`#[serde(default)]`), no existing signature/semantics changes, new
  network/merge paths explicit + preview-first + default-OFF, every new
  behavior ships with regression tests, decoy refused on all new grantor
  paths, access log metadata-only.
- Do NOT "fix" the 2 `manual_clamp` clippy warnings with `.clamp()` â€” NaN
  propagation semantics differ from `.max().min()`; layout sizing must not
  change silently. An `#[allow(clippy::manual_clamp)]` on `push_hub_width`
  keeps CI's `-D warnings` green without changing behaviour.
- First-run audit-key creation is serialized (`chain_key_bytes` static mutex,
  double-checked). Without it, parallel first writes on a clean machine can
  each seal a different key and orphan every chain but their own â€” this is
  what made `chain_verifies_and_tamper_breaks` flake on a fresh CI runner.
- Test hygiene (proven twice): env-mutating tests sharing one process-global
  var MUST serialize via a static `Mutex` (see `browser_direct` ENV_LOCK
  precedent); single-use token consume MUST check-then-remove (failed
  attempts never burn); brand-new relay message names keep old fail-closed
  pins green (`PV_ASSERT` vs `PV_ASSERT_SIGN`).
- Crate `Result<T>` alias collision: new String-error fns use
  `std::result::Result` or a local `StdResult<T>` alias â€” never bare
  `Result<_, String>` next to `use crate::error::Result`.
- A5 rekey invariants: the rollback snapshot is the normal `.bak.1.enc`
  (sealed with the OLD password); App PIN is removed on rotation because the
  PIN cannot re-seal itself; old `.pvx` exports, backups and GitHub history
  stay on the old password â€” never claim otherwise in UI or docs.
- A6 backup invariants: `PVBK1` is a 5-byte prefix, not a new container
  version â€” `crypto.rs` stays untouched. A tagged file is opened ONLY with the
  backup passphrase (the master is never tried); untagged files keep the
  legacy master path, so pre-A6 `.pvx` files must never be broken. The export
  gate refuses a passphrase equal to the master (not a warning). Clearing the
  Slint fields happens on the event loop; property writes never cross threads.
- A11b dual-gate invariants: one cache key, two gates â€” never duplicate the
  ciphertext or wrap the key with the PIN. PIN unlock requires BOTH a set PIN
  and the explicit `offline_cache_pin.pref` consent; replacing/removing the PIN
  revokes it. `cache_status` must never prompt; `PV_QUERY` never prompts
  implicitly. Strength is min(Hello, PIN) â€” keep the fallback default OFF.
- A19 canary invariant: alerts carry only `id/time/title_hash/via/device` and
  are signed by a paired device; never send the title or secret. Pending retry
  is best-effort until P2P is reachable (no dead-drop yet).
- A18 decoy invariants: the duress verifier is the AEAD tag (never a sidecar);
  the decoy uses the backup naming family and no rotation; every payload is
  bucket-padded. Never reintroduce `decoy_vault.enc`/`duress.dpapi`.
- A15a pairing invariants: the code never crosses the wire (HMAC proof only),
  is single-use/5-min, and every non-pair request requires a paired Ed25519
  signature + fresh timestamp. 403 is the default. A15b removes the head
  hash/mtime from beacons; never reintroduce them.
- A16 revision invariants: `rev`/`prev_hash` live INSIDE the AEAD payload and
  every save increments the chain; never reset a revision when the file merely
  disappeared (refuse). `check_incoming` is the only freshness gate: lower rev =
  stale, equal rev + different hash = conflict, newer rev without the local hash
  as `prev_hash` = fork. Fresh-device first pull is TOFU â€” never claim otherwise.
  Rev-2 containers are unreadable by older builds; release notes must say so.
- A12 shadow-DOM invariants: traverse OPEN roots only (closed roots are
  inaccessible by design); every shadow observer must call the same debounced
  `pvScheduleScan`; submit listeners attach to the form itself (submit is not
  composed); grouping is per shadow tree, never page-wide.
- A17 favicon invariant: the only network URL is `https://{domain}/favicon.ico`
  (or the extension-harvested page icon). Never reintroduce a third-party
  favicon service; the letter circle is the offline fallback.
- A14 PIN invariants: the verifier never crosses the bridge (`ext_pin_status`
  is boolean only); Argon2id params live in the record; the lockout counter is
  file-backed and reset only by success/set/clear; a legacy SHA-256 record MUST
  fail closed. 4-digit PINs are shoulder-surfing protection â€” never call them
  vault-grade.
- A11 cache invariants: the snapshot is logins-only, read-only, refreshed at
  unlock; the key is DPAPI-sealed and the host requires a Hello prompt; the
  extension keeps plaintext only in SW memory (never `storage`) for 15 min.
  `cache_get` is the ONLY command allowed before the heartbeat gate. Decoy
  unlock MUST clear the cache (deniability), and reprompt-armed items MUST NOT
  fill from the cache. Hello is presence UI, not a key factor â€” never claim the
  cache is tamper-proof against same-user malware.
- A8a release invariants: `src/release_pubkey.rs` is the ONLY definition of
  the pinned key (updater + signer both consume it). `pv-sign` fails closed on
  a key mismatch and never prints the seed. CI and local builds call the same
  `scripts/package_release.ps1`. The updater asset is the portable
  `PhantomVault-<ver>-windows-x64.exe`, never the Inno installer â€” `pick_asset`
  skips `setup`/`installer` and returns `None` when only an installer exists.
  Sign AFTER the installer/zip bytes are final; hash after signing. Never
  rebuild/overwrite a published tag â€” the workflow refuses an existing release
  on manual dispatch. No UPX: the sub-8MB target was v0.2.0-only and
  compressing an unsigned binary raises AV false positives.
