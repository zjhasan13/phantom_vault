# PhantomVault — UI Parity Map (current app ⇄ Stitch mockups)

Purpose: a **one-file ground truth** of every UI element we ship today, so that after the
Slint redesign we can tick each line and prove nothing was lost and everything the mockup
promises is either implemented or deliberately rejected.

- Source of truth for "now": `ui/appwindow.slint` (2903 lines), Rust handlers in `src/main.rs`,
  `rules.md` (shipped baseline), `browser_extension/*`.
- Source of truth for "design": `expected ui/stitch_phantom_vault_desktop_ui/`
  (13 screens, `code.html` + `screen.png`; 3 PNGs are 28-byte placeholders → HTML only),
  `phantom_vault/DESIGN.md` (Inter, M3-ish purple `#d0bcff`, surface `#131315`).
- Legend: **KEEP** = must survive restyle · **MAP** = design equivalent exists · **NEW** = design
  asks for something we don't have · **REJECT** = mockup label we will not fake (see §15).
- Rule: property/callback names in `appwindow.slint` are a frozen contract with `src/main.rs`.
  A restyle may move visuals; it may **not** rename these.

Measured baseline: 546 hard-coded hex colours, `PhantomTheme` referenced 0 times (`:110-124`),
190 callbacks, 8 components, 3 windows.

Caveat: `expected ui/` is **untracked** in git — the design source is not in the repo history.
The 3 loose PNGs (`bpi…`, `chrome_…`, `all_vault_items` placeholder) are not referenced by any
folder; treat §14 as the authoritative list of the 13 screens.

---

## 0. Window chrome & global

| Element | Now | Design | Status |
|---|---|---|---|
| Main window | 1280×800 pref, min 960×620, 3-col (`:445`, `:1304`) | 1280×1024 canvas | MAP (compact vertically) |
| Title bar / frame | OS native frame | mockups show no OS chrome | NEW (custom titlebar = `no-frame` + drag area; risky, needs window controls) |
| Brand lockup | `P` tile + "PHANTOM / VAULT" (`:1320-1321`) | `PHANTOM` + `ENTERPRISE/PRO` pill | MAP |
| Toast | 4s auto-dismiss, 4 kinds (`:481-487`, `:2025-2026`) | bottom status bar | MAP |
| Global command palette | OS-global QuickBar Alt+Space (`:2669`) | in-app `⌘K` | NEW (in-app palette) |
| Crash/integrity banner | lock-screen `integrity_warning` (`:1108`) | — | KEEP (design lacks it) |

---

## 1. Onboarding (`:1216-1298`)

| Element | Now | Design | Status |
|---|---|---|---|
| 3-step carousel + dots | `:1236-1244` | none | KEEP |
| Entropy meter + label | `:1273-1276` | generator only | KEEP |
| Shard comprehension checkbox gate | `:1256`, `:1281` | none | KEEP |
| Master password create/confirm | `:1263-1269` | none | KEEP |
| Skip / continue | `:1291-1292` | none | KEEP |

## 2. Lock screen (`:1049-1212`)

| Element | Now | Design | Status |
|---|---|---|---|
| Unlock card 440px + aura glows | `:1086-1095` | settings "Enclave" look | MAP |
| EN/BN toggle | `:1100` | none | KEEP |
| Tabs: Password / PIN / Shards | `:1103-1107` | none | KEEP |
| Master password field + busy state | `:1118-1133` | none | KEEP |
| Windows Hello button | `:1134-1139` | "TouchID Ready" (HUD 3.0) | MAP (real name: Windows Hello) |
| App PIN pad | `:1140-1157` | 4–8 digit PIN (`settings`) | MAP |
| Shard recovery (3 inputs + show/clear) | `:1184-1202` | emergency kit dry-run | MAP |
| Unlock 2FA step | `:1165-1182` | none | KEEP |
| Factory reset link + warning | `:1204-1207` | danger zone | MAP |
| Portable badge | `:1081` | none | KEEP |

## 3. App shell / sidebar (`:1310-1364`)

| Element | Now | Design | Status |
|---|---|---|---|
| 220px rail, 64px collapsed | `:1311`, `:1323` | 260px rail | MAP |
| Brand block | `:1320-1321` | logo + PRO/ENTERPRISE chip | MAP |
| `All items` | `:1327` | `All Vault Items 184` | MAP + counter **NEW** |
| `Favorites` | `:1328` | `Starred` | MAP + counter NEW |
| `Trash` | `:1329` | `Trash 3` | MAP + counter NEW |
| Type nav: Login/Card/Identity/Note/License/SSH Key | `:1332-1337` | `Categories` counters | MAP + counters NEW |
| Folder list | `:1339` | `Folders` (no counters) | MAP |
| New folder input | `:1340` | — | KEEP |
| `+ New` menu (6 kinds) | `:1342-1350` | `+ New Secret Item` | MAP |
| `Generator` | `:1351` | `Generator Studio` | MAP |
| `2FA Hub` | `:1352` | `2FA Authenticator Hub 24` | MAP + counter NEW |
| `Import` | `:1353` | `Migration Wizard` | MAP |
| `Settings` | `:1354` | `Security & Developer Settings` | MAP |
| `Lock` / `Exit` | `:1355-1356` | `PANIC LOCK VAULT` | MAP (rename = panic lock) |
| Travel / Offline badges | `:1357-1358`, `:1361` | `Duress safe filter`, `Travel Mode` | MAP |
| Portable badge | `:1362` | none | KEEP |
| Route state (`active_nav`) | `:1826-1836` model; `:1357-1358` rails | sub-nav anchors | MAP |
| Keyboard: `Ctrl+F` search, `/`, `↑↓`, `Esc`, `Enter` | `:1905` + focus handlers in `src/main.rs` | `⌘K`, `j/k` palette | MAP (`⌘K` REJECT, keep Ctrl) |
| Rail collapse + persisted width | `:1311`, `:1323` | 64px / 220px | MAP |

## 4. Vault — Column 2 list (`:1870-1964`)

| Element | Now | Design | Status |
|---|---|---|---|
| `+ New Item` | `:1884` | `+ New Secret Item` | MAP |
| Shard nudge banner | `:1885-1892` | — | KEEP |
| New-kind menu | `:1893-1904` | `New Item ▾` | MAP |
| Search + `/` focus | `:1905` | search with `⌘K` chip | MAP |
| Clear search | `:1906` | — | KEEP |
| Select mode toggle | `:1908` | `Select items` | MAP |
| Favorites-only banner | `:1910` | `Starred` chip | MAP |
| Trash banner + empty-trash confirm | `:1911-1921` | `Trash` + `Purge` | MAP |
| Row height/select bar | 62px, 2px accent + left bar (`:1923-1925`) | 72px card w/ left accent | MAP |
| Favicon / kind icon | `:1928-1929` | brand logo tiles | MAP |
| Title + username•folder | `:1930` | title + subtitle + tag chips | MAP (+ chips NEW) |
| Verified ✅ | `:1930` | `verified` icon | MAP |
| Quick copy (login/card/2FA) | `:1932-1934` | `Copy` per row | MAP |
| Favorite star | `:1936` | star | MAP |
| Health icon → filter | `:1937` | `Reused in 154 items`, `Expiring in 4d` | MAP (+ expiry NEW) |
| Hover-only row actions | `:1931` | always-visible kebab | MAP |
| Empty states (trash/fav/search/empty) | `:1940-1945` | empty hints | MAP |
| Load 50 more + count | `:1946-1947` | virtual list | MAP (keep paging) |
| Bulk bar (fav all / move / trash / deselect) | `:1950-1961` | `Batch Tag`, `Purge`, `Export` | MAP + batch-tag/export-selected NEW |
| Row password strength % | — | `96%`, `35%` | NEW (needs strength in row model) |
| Copy ✓ feedback (`last_copied` flash) | `:481`, `:1931` area | inline "Copied" tooltip | MAP |
| Overflow/kebab actions | hover-only `:1931` | `⋮` always | NEW (kebab) |
| Selected-row indicator 2px bar | `:1924` | 2px `#8B5CF6` bar | MAP (exact match) |

## 5. Vault — Column 3 inspector (`:1966-2158`)

| Element | Now | Design | Status |
|---|---|---|---|
| Empty state + actions | `:2143-2148` | preview pane | MAP |
| Peep-hold pad | `:2034-2044` | — | KEEP |
| Header: icon, title, ✅, folder, 🔒 reprompt, star, custom logo | `:2047-2057` | header + `Edit Entry` | MAP |
| `⚡ Autofill / Type` | `:2058` | `Autofill & Inject Credentials` | MAP |
| Trash banner / stale warning | `:2060-2061` | — | KEEP |
| Username + copy | `:2065-2066` | `Username / Account Identifier` + Copy | MAP |
| Password reveal/copy/generate | `:2068-2069` | `Encrypted Password` + Copy | MAP |
| Strength bar + label | `:2070-2077` | `High Security (128-bit)` + crack time | MAP (+ crack-time NEW) |
| Password history (last 5) | `:2078-2083` | `Previous Passwords (2)` | MAP |
| TOTP card (code, ring, copy) | `:2086` | `One-Time Code (TOTP 2FA)` + `Add URL Match` | MAP |
| Autofill card: URL open/copy, extra URLs | `:2088-2092` | `Autofill Target URI Rules` editor | MAP (+ per-URL rule edit NEW) |
| Backup codes + copy all | `:2094-2098` | — | KEEP |
| Custom fields (text/hidden/checkbox/linked) | `:2099-2102` | — | KEEP |
| Notes | `:2103-2106` | — | KEEP |
| Attachments: empty, attach, preview/download/delete | `:2107-2116` | dropzone + `Max 50MB` | MAP (+ dropzone NEW) |
| Item history card: health text, age bar, fill info, verified toggle, travel | `:2118-2133` | `Item Audit Trail & Rotation Status`, `Mark Verified Working`, `Last rotated` | MAP (+ audit timeline/rotation NEW) |
| Bottom actions: restore/shred/edit/delete/close | `:2135-2141` | kebab + Edit | MAP |
| Moiré veil overlay | `:2150-2156` | — | KEEP |

## 6. Add / Edit form (`:1970-2024`; edit reuses it via `edit_item_requested`)

| Element | Now | Design | Status |
|---|---|---|---|
| Kind tabs (Login/Card/Note + Identity/License/SSH) | `:1971-1972` | `New Secret Item` type picker | MAP |
| Field-relabel warning | `:1973` | — | KEEP |
| Title + folder combo | `:1975-1976` | title + `Vault Partition` | MAP |
| Username/email (per-kind label) | `:1978` | `Identity / Username` + Edit | MAP |
| Alias button (login only) | `:1978` | — | KEEP |
| Password/secret (per-kind label) + 🎲 | `:1979` | `Secret Password` + entropy | MAP |
| Card extra: expiry/CVV | `:1985-1988` | — | KEEP |
| Identity extra: NID/email/phone/address/company/city/state/zip/country | `:1985-1997` | — | KEEP |
| SSH fingerprint | `:1985` | — | KEEP |
| TOTP + backup codes + website + URL rules + add website | `:1998-2006` | `+ Add TOTP authenticator key` | MAP |
| Custom fields list + add dialog | `:2010-2012`, `:2199-2257` | — | KEEP |
| Notes | `:2013-2014` | — | KEEP |
| Reprompt / Favorite / Travel checkboxes | `:2016-2018` | — | KEEP |
| Save / Cancel | `:2020-2023` | `Save to Vault` | MAP |

## 7. Folder model (honest current state)

| Capability | Now | Design | Status |
|---|---|---|---|
| List folders (sorted, deduped, `General` fallback) | `main.rs:2605-2630` | `Folders` / `Environments` | MAP |
| Create folder | input `:1340` → `main.rs:9841` (`Vault::add_folder`, save+rollback) | — | KEEP |
| Assign folder on item | form combo `:1976` | `Vault Partition` | MAP |
| Filter by folder | `:1339` → `main.rs:6146` | folder scope | MAP |
| Bulk move | `:1957-1958` → `main.rs:6532` | — | KEEP |
| Rename folder | **does not exist** (no callback/handler) | — | NEW (if wanted) |
| Delete folder | **does not exist** (no callback/handler) | — | NEW (if wanted) |
| Folder counters | **does not exist** | `184 / 12 / 7` | NEW |
| Nested folders | **not supported** (flat list) | `Environments` groups look nested | NEW (model change, large) |

## 8. 2FA Hub (`:1367-1505`)

| Element | Now | Design | Status |
|---|---|---|---|
| `+ Add 2FA` toggle | `:1372` | `+ Add New 2FA` | MAP |
| Search + clear (`totp_search_query`) | `:1373-1374` | search | MAP |
| `📲 Export` (Google migration QR) | `:1377`, modal `:1471-1503` | — | KEEP |
| Show/Hide NEXT | `:1378` | `Show NEXT Tokens` | MAP |
| `⚙ Settings` shortcut | `:1379` | — | KEEP |
| Add panel: QR / webcam / file / paste / import | `:1381-1387` | — | KEEP |
| 3-col cards (112px) | `:1392-1393`, width math `:1397` | 3-col cards | MAP (denser ~190px) |
| Issuer + name + DUP warning | `:1414-1418` | issuer + tag (`PROD/CRITICAL`) | MAP (+ tag NEW) |
| Big grouped code | `:1419` | big code | MAP |
| NEXT label (hidden default) | `:1423` | `NEXT: 912 045` (always shown) | MAP (keep hidden-by-default) |
| Countdown bar + ring | `:1424-1425`, `:1429-1431` | ring + `22s` | MAP |
| Star / copy / delete two-tap | `:1432-1438` | star, `Copy Code`, kebab | MAP |
| HOTP `Next` + label | `:1434-1435` | — | KEEP |
| Empty state | `:1443-1447` | — | KEEP |
| Passkeys: register (rp/user), list, star, copy, delete, trash restore/shred | `:1448-1467` | `Passkeys & Logins 89`, `YubiKey 5C` | MAP (rename claims REJECT) |
| Duplicate-secret confirm modal | `:1506-1527` | — | KEEP |
| KPI strip (keys / algorithm / drift / zero-leak) | — | `Active 2FA Keys`, `RFC 6238 30s/SHA1`, `Time Drift Check`, `Zero-Leak` | NEW |
| Filter chips + sort | — | `All(24) Starred Infrastructure Developer Cloud`, `Sort by` | NEW |
| Footer status bar | — | `Vault Health`, `Clipboard Auto-Purge`, `Biometric Re-check`, `RFC 6238 Specs`, `Panic Log` | NEW |
| Algorithm/digits/period per account | engine supports (`rules.md:338-341`) | shows `30s/SHA1` only | MAP (surface params) |

## 9. Import (`:1528-1551`)

| Element | Now | Design | Status |
|---|---|---|---|
| Browse & import any file | `:1531` | drag-drop + file picker | MAP |
| Detect browsers | `:1532-1533` | provider tiles (`Chromium`) | MAP |
| Status line (info/success/error) | `:1534` | parser log | MAP |
| Dry-run preview text + rows (cap 200, secrets hidden) | `:1535-1538` | manifest table (origin/target/type/entropy/collision) | MAP (+ columns NEW) |
| Merge modes: Skip dupes / Update existing / Import all | `:1539-1543` | `Merge & Revision` / `Keep existing` / `Overwrite` | MAP |
| Undo last import | `:1544` | — | KEEP |
| Confirm / Cancel | `:1545-1548` | `Begin Secure Migration` | MAP |
| 4-step stepper | — | `Source → Parsing → Schema → Ingestion` | NEW |
| Source master password input (1PUX/KDBX) | **not supported** (encrypted exports refused) | required | REJECT (feature gap, not UI) |
| Import progress % | — | `64%` chunk log | NEW |

## 10. Settings (`:1552-1866`) — all cards and controls

| Card | Controls (line) | Design section | Status |
|---|---|---|---|
| Security | Blackout `:1558`; favicons `:1559`; custom logos refresh/clear `:1560`; travel `:1562`; Hello status `:1563`; App PIN set/remove `:1564-1572`; Ext PIN `:1574-1582`; AND-mode `:1584`; hands-free 2FA `:1585`; unlock-2FA setup/confirm/disarm `:1587-1600`; clock offset `:1601-1607`; clipboard 10/15/30/60 `:1608-1614`; auto-lock 1/5/15/Never `:1615-1621`; offline kill-switch `:1622`; access log `:1623`; tray minimize `:1624` | `Master Authentication`, `Anti-Photography`, `Clipboard`, `Auto-Lock` | MAP (design has 1h option; we don't) |
| Updates | check / what's-new / download / restart `:1625-1633` | — | KEEP |
| Proximity BLE | toggle, device, sensitivity, save `:1636-1646` | `BLE Proximity Walk-Away` | MAP |
| GitHub sync | owner/repo/PAT, connect, sync, merge preview/apply `:1649-1656` | `GitHub/GitLab Private Repo` | MAP (GitLab claim REJECT) |
| Sharing | item id, grantee key, grant, grant id, revoke, priv key, envelope, open `:1659-1670` | — | KEEP |
| Secure Send | note, TTL, seal, code, read+burn, paste packet/key `:1673-1688` | exact design screen | MAP |
| Business | member CSV, import, deprovision, OIDC issuer/token, verify, bind key, audit export `:1691-1710` | `Governance` nav item | MAP |
| P2P | toggle, PIN, regen, scan, peer PIN, peer list sync `:1713-1722` | `Local & P2P Sync Mesh` | MAP (+ mesh topology NEW) |
| Browser bridge | ext ID, install Chrome, install Firefox `:1725-1731` | `Headless Browser Extension Host` | MAP |
| Export | Bitwarden JSON / CSV / `.pvx` / Full CSV `:1734-1738` | `Zero-Lock-In Raw Export` | MAP (+ KeePass/LastPass buttons NEW if wanted) |
| Backups | auto, daily/weekly/monthly, browse, now, path/status `:1741-1754` | `Encrypted Snapshots` | MAP |
| Paranoia | recovery badge, PDF sheet, stego hide/restore, duress, canary, emergency grant `:1757-1795` | `Danger Zone & Hardware Cold Purge`, `Duress` | MAP |
| Danger zone | factory reset `:1797-1801` | `Eradicate & Reset` | MAP |
| Aliases | provider, domain, token, save `:1804-1813` | `Email Aliases & Burner` | MAP |
| Anti-photo | peep mode, moiré `:1816-1820` | `Anti-Photography & Lens` | MAP |
| Health & Dev | scan secrets, audit, SSH agent start/stop/refresh, offline audit, shell completion `:1823-1833` | `Dev Tools & SSH Agent` | MAP (+ PowerShell/Bash/Fish choice: we have PS/Bash/Nushell) |
| Scoreboard | score, headline, re-scan, janitor, 4 filter buttons, clear, rotate reused, 2FA coverage `:1836-1863` | `Vault Health` | MAP |
| Sub-nav / anchors | — (single scroll) | 7 sections: Master Authentication & Hardware PIN · Anti-Photography & Lens Jammer Guard · Local Wi-Fi P2P & Sovereign Git Sync · SSH Agent Daemon & Headless Bridge · Email Aliases & Burner Privacy Shield · Scheduled Snapshots & Sovereignty Export · Danger Zone & Hardware Cold Purge | NEW |
| Header action bar | — | `Export Hardware Config` / `Apply Enclave Rules` | REJECT (no such config) |

## 11. Overlays / modals

| Overlay | Line | Design counterpart | Status |
|---|---|---|---|
| Duplicate import confirm | `:1506` | collision engine | MAP |
| Google Auth export QR | `:1471` | — | KEEP |
| Generator panel | `:2169`, `:231` | Generator Studio | MAP |
| Add custom field | `:2199` | — | KEEP |
| Master reprompt | `:2260` | save prompt auth | MAP |
| Changelog | `:2313` | — | KEEP |
| Attachment preview | `:2344` | — | KEEP |
| Factory reset | `:2379` | danger zone | MAP |
| New-device (Hello re-enroll) | `:2412` | — | KEEP |
| Webcam QR | `:2438` | — | KEEP |
| Health report | `:2477` | `Forensic & Decoy` (partly) | MAP |
| Access log | `:2548` | Forensic Audit Log | MAP (text → event stream NEW) |
| Shred import source | `:2586` | migration "3-pass" | MAP |
| Recovery shards + drill | `:2620` | Emergency Kit | MAP |

## 12. Quick Bar / Capture / desktop affordances

| Element | Now | Design | Status |
|---|---|---|---|
| QuickBar (Alt+Space) search/↑↓/copy/type/TOTP/open | `:2669-2812` | none (desktop HUD mockups are extension) | KEEP |
| QuickCapture (Alt+S) | `:2815-2903` | save prompt (web only) | KEEP |
| Autofill pill | `:2162-2167` | — | KEEP |
| Tray menu | `rules.md:354` | — | KEEP |

## 13. Browser extension (`browser_extension/`)

| Element | Now | Design | Status |
|---|---|---|---|
| Popup tabs | `popup.html:136-140` → Vault / Stats / Autofill Settings | HUD tabs Autofill/2FA/Generator/Passkeys | MAP (different tab set) |
| Search | `popup.html:142` | search | MAP |
| Folder filter / type filter | `:144-152` | `All Folders`, `All Vault 493` | MAP |
| Suggestions header + rows | `:153-154`, `render()` `popup.js:1076` | `Suggested for active tab (2)` | MAP |
| `Never suggest on this site` | `:154`, `popup.js:524` | `Never offer suggestions for …` | MAP |
| `Fill 2FA code` | `:155`, `popup.js:1264-1318` | `Streaming 2FA Token`, `Copy TOTP` | MAP |
| `Sign with vault` (passkey) | `:156`, `popup.js:1320` | `Passkey Tap`, `FIDO2 WebAuthn Passkey Bound` | MAP (metadata-only in v1, `rules.md:410`) |
| All-items list | `:159-160` | `All Vault 493` | MAP |
| Generator panel (len/symbols/new/copy) | `:161-179`, `popup.js:1215-1262` | `Generator`, diceware | MAP (+ diceware NEW in popup) |
| Lock card + desktop Retry | `:124-133`, `popup.js:796-812` | `RAM Enclave Locked` | MAP |
| PIN overlay | `:129-130`, `popup.js:826-872` | `TouchID Ready` | MAP (PIN, not biometric) |
| Inactivity auto-lock + hint | `popup.js:873-953`, `rules.md:443-446` | `Clipboard purge in 12s` | MAP |
| Row health icons | `rules.md:449` | `%` entropy + tags | MAP (+ % NEW) |
| Popup password view (eye, 15s remask) | `rules.md:447` | reveal eye | MAP |
| Stats pane | `popup.js:274-343` | `Stats` | MAP |
| Settings pane (lock timeout, etc.) | `:186-192` | `Autofill Settings` | MAP |
| i18n EN/BN | `:135`, `popup.js:189` | — | KEEP |
| In-page dropdown | `content.js:1528` | In-Page Autofill & Multi-2FA Dropdown | MAP (+ multi-2FA expand NEW) |
| Inline save form on empty | `popup.js:1134-1214`, `content.js` save path | Save Password Prompt (rich) | MAP (+ folder/TOTP/defer options NEW) |
| Page-world fetch/XHR SPA hook | `rules.md:438` | — | KEEP |
| OTP fill toasts | `rules.md:439` | — | KEEP |
| Context-menu generator | `rules.md:439` | — | KEEP |
| Debounced badge | `rules.md:441` | — | KEEP |
| Full HUD panels 2.0/3.0 (tabs + KPI + footer) | — | yes | NEW (popup restructure) |
| "Quantum Diceware", "Wasm Isolated", "0.1ms IPC" | — | yes | REJECT labels (§15) |
| Auto-verify after 3 fills (`PV_FILLED` → background `pvVerify`) | `content.js:1200`, `background.js` | `Verified working` chip | MAP |
| Reprompt + URL/domain guards before fill | `popup.js:535 fillGuards`, `:567 pvVerify` | `Autofill Target URI Rules` | MAP |
| Passkey discovery observer (page-world WebAuthn) | `content.js` bridge, `rules.md:410` | `Passkey Tap` | MAP (metadata-only v1) |
| HUD 3.0 origin whitelist | none | `Whitelisted Targets` | NEW |
| Popup stats detail (logins/cards/2FA/passkeys/health counts) | `popup.js:274-343` | `Stats` + KPI strip | MAP |
| Save-prompt deferral (not now / never / edit before save) | basic save only | `Defer`, `Never for domain`, `Edit & Save` | NEW |

## 14. Feature → mockup coverage (quick matrix)

| Our feature | Best mockup home | Covered today? |
|---|---|---|
| Vault list/detail | Vault Browser 2.0, All Items | mostly |
| 2FA + passkeys | 2FA Hub 2.0 | mostly |
| Generator | Generator Studio | partially |
| Import | Migration Wizard | partially |
| Export/backup | Settings → Snapshots | mostly |
| Sync (GitHub/P2P) | Settings → P2P Mesh | mostly |
| Sharing / Secure Send | Crypto Envelope | UI stub vs full studio |
| Recovery/Shamir | Emergency Kit | mostly |
| Health/audit | Forensic Log | modal vs page |
| Duress/decoy | Forensic & Decoy | settings only |
| Dev tools/SSH | Settings → Dev Tools | mostly |
| Extension | HUD 2.0/3.0, save prompt, dropdown | partially |

## 15. Deliberate non-parity (labels we will not fake)

Full evidence table lives in the audit report; keep short here:
`AES-256-GCM` → we use **XChaCha20Poly1305**; `Hardware Enclave/TPM/YubiKey/TouchID` → DPAPI +
Windows Hello (no YubiKey code); `SLIP-39/Reed-Solomon` → **GF(2^8) Shamir + EFF words**;
`BLAKE3 Merkle` → **HMAC-SHA256 chain**; `Tauri/SQLite` → Slint + single encrypted file;
`Wasm/ZK-SNARK/Noise-IK/mDNS/Nostr/CRDT` → absent or planned-only; `7-pass flash` → file-level
3-pass DoD; `GPS distress beacon / dead-man switch` → absent; `⌘K` → Windows hotkeys.

## 16. Acceptance checklist (run after each redesign slice)

1. Every **KEEP** row renders and its `callback` still fires (click-through test per row).
2. Every **MAP** row matches the mockup's region/order; deviations listed in the PR description.
3. Every **NEW** row is either implemented or explicitly deferred with a ticket.
4. Every **REJECT** label replaced by our real term (grep the UI strings for the banned list).
5. No `PhantomTheme.`-dead-code regression: either all colours flow through one token global or
   the count of raw hex literals drops and stays down (record the number in the PR).
6. Secrets still never enter row models (`import_preview_rows`, `AuthView` rules at `:63-91`).
7. Two-tap confirms, disabled states, and EN/BN lock strings unchanged.
8. `cargo test --release` count ≥ baseline (468) and `npm test` 79/79.
9. Window works at min 960×620 (design was drawn on 1280×1024).
10. Extension: lock card, PIN overlay, never-suggest, health icons, fill, save still work.

## 17. How to compare visually

1. Run the app at 1280×1024 (design canvas) and capture each surface.
2. Put capture and `screen.png` side by side; tick §0–§13 rows in this file.
3. Record per-screen parity: layout / colour / type / icons / motion (5 columns, 0–5 each).
4. Anything < 4/5 either gets fixed or gets a line in §15 explaining why not.


## 18. Design tokens (adopt once, then delete 546 literals)

**The design doc contradicts itself** — frontmatter is generated Material-3, the prose describes a
different zinc/violet palette. Decide once and record it here; screenshots follow the frontmatter.

| Role | Frontmatter (screenshots) | Prose (§Colors) | Decision |
|---|---|---|---|
| Canvas | `#131315` | `#09090B` | frontmatter |
| Panel (T1) | `#1c1b1d` | `#121215` | frontmatter |
| Card/input (T2) | `#201f22` | `#18181B` | frontmatter |
| Hover/overlay (T3) | `#2a2a2c` / `#353437` | `#27272A` | frontmatter |
| Border | `#494454` (`outline-variant`) | `#27272A` / `#3F3F46` | frontmatter, but use prose's 1px hairline rule |
| Primary | `#d0bcff` | `#8B5CF6` / `#A78BFA` / `#7C3AED` | frontmatter |
| Success | `#4edea3` | `#10B981` | frontmatter |
| Error | `#ffb4ab` | `#EF4444` | frontmatter (prose crimson for text-on-dark) |
| Warning | — | `#F59E0B` | borrow from prose (frontmatter has none) |
| Text / muted / code | `#e5e1e4` / `#cbc3d7` / — | `#FAFAFA` / `#A1A1AA` / `#71717A` | frontmatter + prose's muted scale |

Type scale (Slint px): headline 32/26/24/18 semibold · body 15/13/12 regular · mono 14/12/10.
Mono (`JetBrains Mono`) is **required** for secrets, OTPs, hashes, badges — we currently render
those in the default UI font. Verify whether Slint 1.8 honours per-`Text` `font-family` fallback
and `letter-spacing`; if tracking is unsupported, drop it rather than fake it.

Shapes: 4px badges/kbd/inputs · 8px cards/modals/buttons · 12px floating palette/toast · pills 9999.
Spacing: 4/8 rhythm; gutter 16 (24 desktop); margin 16 (32 desktop); rail 64/220 (matches ours);
list 320–380px; detail fluid. Effects: 1px hairline borders + luminance stacking; single scattered
violet glow `0 8px 30px rgba(139,92,246,.15)`; `backdrop-filter: blur(12px)` **not possible** in
Slint software renderer → use opaque overlay + 1px ring.

## 19. Settings information architecture (18 cards → 7 design sections)

| Design section | Our cards that move here | Gap |
|---|---|---|
| Master Authentication & Hardware PIN | Security (Hello, app PIN, ext PIN, AND-mode, unlock-2FA, auto-lock, clipboard, offline switch, tray) | design's TPM/PIN-pad/dead-man labels → REJECT, keep real DPAPI/Hello wording |
| Anti-Photography & Lens Jammer Guard | Anti-photo (peep, moiré), Blackout, favicon/custom-logo refresh, travel mode | design's "lens jammer" has no hardware backing → label as screen-privacy only |
| Local Wi-Fi P2P & Sovereign Git Sync | P2P (PIN/scan/peers), GitHub sync (owner/repo/PAT/merge), Proximity BLE | design "Noise-IK / 0.1ms IPC / mDNS" → REJECT |
| SSH Agent Daemon & Headless Bridge | Health & Dev (SSH agent, offline audit, shell completion), Browser bridge (ext ID, install buttons) | design adds PowerShell/Bash/Fish picker → we ship PS/Bash/Nushell → MAP |
| Email Aliases & Burner Privacy Shield | Aliases (provider/domain/token), canary, duress | burner-email feature is provider-token only, no inbox → label honestly |
| Scheduled Snapshots & Sovereignty Export | Backups (auto/daily/weekly/monthly/browse/now/path), Export (JSON/CSV/`.pvx`/full CSV), stego hide/restore | design adds KeePass/LastPass buttons + `.zip` manifest → NEW |
| Danger Zone & Hardware Cold Purge | Danger (factory reset), Paranoia (duress, canary, emergency grant, PDF kit) | "Hardware Cold Purge / 7-pass flash" → REJECT (file-level 3-pass only) |
| *no design home* | Updates (check/notes/download/restart), Vault Health scoreboard, Access log, Secure Send, Sharing/Crypto Envelope, Business/Governance | map to design's own nav: Vault Health / Forensic Log / Crypto Envelope / Governance screens |

## 20. Icons & fonts

Measured: **434 emoji-glyph uses, 101 distinct glyphs** inside `appwindow.slint`; no font is
bundled, so Windows falls back to Segoe UI and colour emoji. Mockups use Material Symbols (outline)
+ Inter + JetBrains Mono.

| Option | Fidelity | Cost | Notes |
|---|---|---|---|
| Keep emoji | low (coloured, inconsistent weight) | 0 | current state |
| PNG sprite / per-icon images | medium | low–med | needs 1x/2x/3x; blurry scaling under software renderer |
| `Path` vector glyphs | high | med | works today (no `svg` feature needed); each icon = hand-ported path, no colour emoji |
| Icon TTF by codepoint | high | med | **ligatures won't work in Slint** → use codepoints, not Material Symbols' text names |

Recommended: Inter + JetBrains Mono TTFs + one icon font subset (codepoints only), all OFL/Apache,
registered at startup (`slint::register_font_from_path` — verify it exists in 1.8 and is called
before `MainWindow::new()`), with `Path` fallback for the 10 security-critical marks.

## 21. 13-screen readiness

| Screen (folder) | Data/feature today | Missing for design | Effort |
|---|---|---|---|
| `all_vault_items` (png placeholder) | list/detail/bulk/trash | counters, strength %, kebab, chips | M |
| `phantom_vault_vault_browser_2.0` (png placeholder) | same | same | M |
| `phantom_vault_2fa_hub_2.0` (1280×1024) | TOTP engine, grouping, passkeys, GA export, dup-detect, drift offset | KPI strip, filters/sort, per-account params, footer status | M |
| `settings_dev_center` (938×1600) | all 18 cards functional | 7-section IA, sub-nav, token sweep, honesty rewrites | L |
| `migration_wizard_vault_importer` | any-file import, dry-run, merge modes, undo | 4-step stepper, source password (1PUX/KDBX), progress, manifest columns | M |
| `password_passphrase_generator` | length, sets, custom chars, history, entropy | diceware/passphrase mode surface, quality meter, preset history chips | M |
| `crypto_envelope_secure_send` | seal/open, TTL, burn, paste packet/key | envelope studio, Shamir split of packet, relay/burner-alias narrative | L |
| `emergency_kit_shamir_recovery` | 3-of-5 GF(2^8), drill, PDF kit, stego, recovery badge | shard grid visual, kit card, QR for shards | M |
| `forensic_audit_log_duress_mode` | HMAC-SHA256 chain log, health report, duress/canary | page view, timeline, filters, export | M |
| `phantom_vault_save_password_prompt` | minimal save in extension | folder/type/TOTP fields, defer, never-domain, edit-first | M |
| `phantom_vault_browser_extension_hud_2.0` | popup (Vault/Stats/Settings), lock, PIN, generator | tab restructure, KPI, health %, footer | M |
| `phantom_vault_browser_extension_hud_3.0_ultra` (1600×1280) | same as above | second layout sharing components | M |
| `phantom_vault_in_page_autofill_multi_2fa_dropdown` (png placeholder) | `showDrop` single list, OTP fill | multi-account/2FA expand, keyboard nav, badges | S–M |

3 unreferenced PNGs (`bpi6n3ifbr` 608×749, `chrome_2kq9l2jhdt` 1600×749, `chrome_pesstwstdb`
1600×749) are browser reference shots, not screens — excluded from scope.

## 22. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| 546 literals + dead `PhantomTheme` | every restyle edit touches raw hex | introduce token global first, sweep in one commit, add a grep gate to CI |
| Software renderer + many shadows/rings | frame drops on 1280 wide lists | hairline borders instead of shadows; cap one glow per view |
| Custom titlebar (`no-frame`) | window drag/snap/a11y regressions on Windows | keep OS frame for v1; revisit with explicit win32 hit-test |
| `LineEdit`/`ComboBox`/`CheckBox` skinning | focus ring, IME, RTL, a11y names | wrap, don't reimplement; test keyboard-only path |
| Font licence/registration | silent fallback to Segoe UI | bundle OFL files, assert registered family at startup |
| Callback/property renames during restyle | breaks 190 Rust bindings | freeze names; grep `main.rs` after each slice |
| `expected ui/` untracked | design source lost on fresh clone | commit or submodule the design folder (ask user) |
| Design doc conflict (§18) | inconsistent colours between screens | decide palette in §18 and encode as tokens |
| Min window 960×620 vs 1280×1024 designs | clipping | test every screen at min size in checklist |

## 23. Verified facts used above (so the map doesn't drift)

- KDF: Argon2id v19, 64 MiB, t=3, p=4, 32-byte output (`src/crypto.rs:53-56`).
- Binary self-integrity: hash checked on worker; tamper → lock-screen warning (`src/main.rs:3747-3755`).
- Not found in code: secure-desktop switch, IME suppression, admin-elevation prompt, YubiKey/TPM
  calls → treat those mockup claims as REJECT until implemented.
- Shamir: GF(2^8)/0x11B, 3-of-5, EFF 7776 (`src/security/shamir.rs:4-6,18-19`).
- Access log: HMAC-SHA256 chain (`src/security/access_log.rs:89-105`).
- No folder rename/delete; folders are derived from items (`src/main.rs:2605-2630`), only
  create (`:9841`), filter (`:6146`), bulk move (`:6532`).

## 24. Open decisions (blockers for the redesign, not for this map)

1. Palette: frontmatter (`#131315/#d0bcff`) vs prose (`#09090B/#8B5CF6`)? (§18 recommends frontmatter)
2. Canvas target: keep 1280×800 window or adopt 1280×1024 / per-screen canvases?
3. Fonts: bundle Inter + JetBrains Mono + icon font, or ship Segoe UI first pass?
4. Folder model: add rename/delete (small) and nesting (large) — or keep flat?
5. Ship-first screen: 2FA Hub (recommended) vs Vault list vs Settings?
6. Aspirational labels (Enclave/TPM/SLIP-39/BLAKE3/YubiKey/Noise/CRDT/Nostr): rewrite to real
   terms in v1, or keep design strings and defer? (§15 assumes rewrite)
7. Commit `expected ui/` into the repo (currently untracked)?


## 25. Item field → UI surface (what the design asks vs what we store)

`Credential` (`src/models.rs:242-282`):

| Field | Source | Shown today | Design asks |
|---|---|---|---|
| `title` | `:244` | list row + detail header | yes |
| `username` | `:245` | list subtitle + detail | yes |
| `password` | `:246` | masked detail + strength bar | yes ("Encrypted Password", entropy line) |
| `totp_secret` | `:248` | detail TOTP card | yes ("One-Time Code") |
| `urls` + rule | `:250`, enum `:169-172` | detail autofill card, extension matching | yes ("URI Rules") |
| `apps` | `:254` | QuickBar prefilter / Auto-Type only, never displayed | "App associations" — NEW display |
| `backup_codes` | `:256` | detail card | not in design |
| `custom_fields` | `:258` | detail list + add dialog | "Additional Fields" — MAP |
| `notes` | `:259` | detail | yes |
| `folder` | `:261` | sidebar, filter, form combo | yes ("Vault Partition") |
| `reprompt` | `:263` | 🔒 badge + unlock gate | yes |
| `attachments` | `:265` | detail list + preview | dropzone + "Max 50MB" — **no size cap today**, NEW guard |
| `travel_safe` | `:267` | travel badge | "Travel Mode" — MAP |
| `last_changed` | `:272` | age bar, stale warning | "Last rotated 3d ago" — MAP |
| `password_history` | `:275` | last 5 in detail | "Previous Passwords (2)" — MAP |
| `favorite` | `:278` | star, Favorites filter | yes |
| `deleted_at` | `:281` | trash list / restore / shred | yes |
| **`last_used` / `usage_count`** | — | — | "Used 4h ago" — **no field** |
| **`expires_at`** | — | — | "Expiring in 4d" — **no field** |
| **`tags` / criticality** | — | — | chips `PROD`, `CRITICAL` — **no field at all** |
| **`created_at`** | — | — | "Added …" — absent on `Credential` (only passkeys have it) |
| row strength % | computed | not in row model (only detail) | `96%` per row — NEW derived prop |

`TotpAccount` (`:319-336`): `digits`, `period`, `algorithm`, `otp_type` (`totp/hotp/steam`),
`counter`, `favorite` all stored → per-account params UI is **NEW**, KPI "RFC 6238 30s/SHA1" is
computable. `PasskeyItem` (`:488-510`): `sign_count`, `created_at` → "Passkey Tap" data exists.
`SshKeyItem` (`:513+`): `fingerprint` → "SHA256 fingerprint" exists.

## 26. State coverage (empty / busy / error)

| Surface | Empty | Busy | Error | Missing vs design |
|---|---|---|---|---|
| Vault list | 4 variants `:1940-1945` | — | toast | skeleton rows NEW |
| Detail | `:2143` | — | toast | skeleton NEW |
| 2FA hub | `:1443` | — | toast | empty KPI cards NEW |
| Import | idle text | **no % progress** (status string `:1534`) | info/error line | stepper + progress NEW |
| Sync / merge | — | **no spinner** (status text) | status text | progress NEW |
| Unlock | — | spinner `:1118-1133` | inline error | MAP |
| Settings | n/a (always cards) | scan results text | toast | — |
| Extension popup | lock overlay `popup.html:124-133` | fill busy button | status line | skeletons NEW |

## 27. Motion & destructive-confirmation inventory

- `animate` declarations in `appwindow.slint`: **0** → the mockups' 50ms hover, no-bounce toggles,
  ring countdown and drawer slides are all NEW (Slint `animate` exists, software renderer-friendly
  for colors/opacity; avoid per-frame layout animation).
- Verified two-step/confirm states (do not lose these in a restyle):
  `confirm_bulk_trash :573`, `confirm_pin_remove :575`, `confirm_ext_pin_remove :576`,
  `show_empty_confirm :583`, `exp_confirm :597` (Google export), `show_dup_confirm :903`,
  `fr_armed :1013` (factory reset), `confirm_delete_detail :1037`.
- Hover-revealed actions (row copy/star, password actions) — keep; design's always-visible kebab is additive.
- Toast lifetime 4s, 4 severity kinds.

## 28. Language / accessibility / keyboard

- Desktop app is **English-only except the lock screen**: Bengali glyphs occur only at
  `:1100-1199` (14 lines), driven by the EN/BN toggle at `:1100`. Every other screen has no
  translation layer — design has no language switch, so this is a parity *extra*, not a gap.
- Extension: EN/BN via `popup.js:189 applyLang`; diceware wordlist language toggle is separate
  (`gen_dice_lang :248`, "English (EFF 7776)" `:356`).
- Accessibility: **0** `accessible-*` attributes in `appwindow.slint` → focus roles/labels must be
  added (Slint supports `accessible-role`/`accessible-label`); design's AAA-contrast claim is
  measurable only after token adoption (§18).
- Keyboard today: `Ctrl+F`/`/` search, `↑↓` + `Enter` list navigation, `Esc` back/close,
  `Alt+Space` QuickBar, `Alt+S` QuickCapture. Design's vim `j/k` + `⌘K` palette = NEW/REJECT (§15).

## 29. Tray & desktop integration

| Element | Now | Design | Status |
|---|---|---|---|
| Tray menu | Open / QuickBar / Lock / Exit (`src/windows_native/tray.rs:218-221`) | none | KEEP |
| Close-to-tray preference | `tray_minimize.pref`, `main.rs:3478`, settings `:1624` | none | KEEP |
| Tooltip / icon | "PhantomVault - Zero-Knowledge Native Vault" `:159`, `assets\app.ico` | none | KEEP |
| Notifications | in-app toasts only (`notify_*` call sites), no OS balloons | footer status bars | MAP |
| Global hotkeys | Alt+Space, Alt+S | none | KEEP |

## Appendix A - callback wiring index (generated from source)

Declared: 190 - wired to Rust: 188 - UI-only (no Rust handler): 2.

UI-only callbacks (handled entirely inside Slint, or currently unused): `clicked`, `tapped`.

<details><summary>All 190 callback declarations</summary>

| # | callback | decl line | Rust handler |
|---|---|---|---|
| 1 | `clicked` | 135 | UI-only |
| 2 | `tapped` | 174 | UI-only |
| 3 | `regenerate` | 253 | yes (1) |
| 4 | `use_password` | 254 | yes (1) |
| 5 | `close_panel` | 255 | yes (1) |
| 6 | `register_passkey` | 474 | yes (1) |
| 7 | `delete_passkey` | 475 | yes (1) |
| 8 | `restore_passkey` | 476 | yes (1) |
| 9 | `toggle_passkey_fav` | 477 | yes (1) |
| 10 | `copy_passkey_pub` | 478 | yes (1) |
| 11 | `export_recovery_sheet` | 479 | yes (1) |
| 12 | `verify_shard_drill` | 480 | yes (1) |
| 13 | `cycle_url_rule` | 510 | yes (1) |
| 14 | `load_more_items` | 569 | yes (1) |
| 15 | `restore_item` | 585 | yes (1) |
| 16 | `empty_trash` | 586 | yes (1) |
| 17 | `webcam_camera_picked` | 630 | yes (1) |
| 18 | `refresh_ssh_status` | 661 | yes (1) |
| 19 | `start_ssh_agent` | 666 | yes (1) |
| 20 | `stop_ssh_agent` | 667 | yes (1) |
| 21 | `set_and_mode` | 669 | yes (1) |
| 22 | `set_chain_2fa` | 672 | yes (1) |
| 23 | `verify_totp_unlock` | 679 | yes (1) |
| 24 | `cancel_totp_step` | 680 | yes (1) |
| 25 | `setup_totp_unlock` | 681 | yes (1) |
| 26 | `confirm_totp_unlock` | 682 | yes (1) |
| 27 | `disable_totp_unlock` | 683 | yes (1) |
| 28 | `set_peep_mode` | 687 | yes (1) |
| 29 | `set_moire` | 688 | yes (1) |
| 30 | `ob_pw_changed` | 712 | yes (1) |
| 31 | `reenroll_hello_requested` | 720 | yes (1) |
| 32 | `dismiss_new_device_modal` | 721 | yes (1) |
| 33 | `shard_nudge_generate` | 722 | yes (1) |
| 34 | `shard_nudge_later` | 723 | yes (1) |
| 35 | `generate_shards` | 724 | yes (1) |
| 36 | `recover_with_shards` | 725 | yes (1) |
| 37 | `emg_new_keypair` | 735 | yes (1) |
| 38 | `emg_publish_request` | 736 | yes (1) |
| 39 | `emg_release_envelope` | 737 | yes (1) |
| 40 | `emg_fetch_envelope` | 738 | yes (1) |
| 41 | `emg_open_envelope` | 739 | yes (1) |
| 42 | `stego_hide` | 740 | yes (1) |
| 43 | `stego_restore` | 741 | yes (1) |
| 44 | `audit_vault` | 751 | yes (1) |
| 45 | `open_health_url` | 752 | yes (1) |
| 46 | `filter_health` | 753 | yes (1) |
| 47 | `toggle_log_bridge` | 758 | yes (1) |
| 48 | `set_offline_mode` | 760 | yes (1) |
| 49 | `view_access_log` | 761 | yes (1) |
| 50 | `set_tray_minimize` | 762 | yes (1) |
| 51 | `set_backup_enabled` | 763 | yes (1) |
| 52 | `set_backup_interval` | 764 | yes (1) |
| 53 | `browse_backup_dir` | 765 | yes (1) |
| 54 | `backup_now` | 766 | yes (1) |
| 55 | `set_prox_enabled` | 772 | yes (1) |
| 56 | `save_prox_device` | 773 | yes (1) |
| 57 | `set_prox_sensitivity` | 774 | yes (1) |
| 58 | `confirm_import_file` | 785 | yes (1) |
| 59 | `cancel_import_file` | 786 | yes (1) |
| 60 | `import_mode_changed` | 787 | yes (1) |
| 61 | `undo_import` | 788 | yes (1) |
| 62 | `detect_browsers` | 792 | yes (1) |
| 63 | `confirm_shred_source` | 796 | yes (1) |
| 64 | `cancel_shred_source` | 797 | yes (1) |
| 65 | `unlock_requested` | 872 | yes (1) |
| 66 | `copy_password_requested` | 873 | yes (1) |
| 67 | `quick_copy` | 874 | yes (1) |
| 68 | `toggle_totp_favorite` | 883 | yes (1) |
| 69 | `toggle_totp_next` | 889 | yes (1) |
| 70 | `copy_totp_requested` | 893 | yes (1) |
| 71 | `set_totp_offset` | 899 | yes (1) |
| 72 | `reset_totp_offset` | 900 | yes (1) |
| 73 | `dup_confirm_replace` | 906 | yes (1) |
| 74 | `dup_confirm_keep` | 907 | yes (1) |
| 75 | `dup_confirm_cancel` | 908 | yes (1) |
| 76 | `add_item_requested` | 909 | yes (1) |
| 77 | `delete_item_requested` | 910 | yes (1) |
| 78 | `type_filter_changed` | 911 | yes (1) |
| 79 | `folder_filter_changed` | 912 | yes (1) |
| 80 | `fav_filter_changed` | 913 | yes (1) |
| 81 | `toggle_favorite` | 914 | yes (1) |
| 82 | `toggle_verified` | 915 | yes (1) |
| 83 | `open_janitor` | 916 | yes (1) |
| 84 | `toggle_select` | 917 | yes (1) |
| 85 | `clear_selection` | 918 | yes (1) |
| 86 | `bulk_favorite` | 919 | yes (1) |
| 87 | `bulk_move` | 920 | yes (1) |
| 88 | `bulk_trash` | 921 | yes (1) |
| 89 | `rotate_reused` | 922 | yes (1) |
| 90 | `show_trash_view` | 923 | yes (1) |
| 91 | `open_url` | 924 | yes (1) |
| 92 | `open_new_form` | 925 | yes (1) |
| 93 | `cancel_form` | 926 | yes (1) |
| 94 | `add_folder_requested` | 927 | yes (1) |
| 95 | `add_custom_field` | 928 | yes (1) |
| 96 | `delete_custom_field` | 929 | yes (1) |
| 97 | `add_url` | 930 | yes (1) |
| 98 | `update_url` | 931 | yes (1) |
| 99 | `remove_url` | 932 | yes (1) |
| 100 | `toggle_pending_field` | 933 | yes (1) |
| 101 | `toggle_saved_field` | 934 | yes (1) |
| 102 | `edit_item_requested` | 935 | yes (1) |
| 103 | `open_detail` | 936 | yes (1) |
| 104 | `close_detail` | 937 | yes (1) |
| 105 | `cycle_select` | 938 | yes (1) |
| 106 | `reprompt_confirm` | 939 | yes (1) |
| 107 | `search_changed` | 940 | yes (1) |
| 108 | `totp_search_changed` | 941 | yes (1) |
| 109 | `scan_qr_requested` | 942 | yes (1) |
| 110 | `scan_webcam_requested` | 943 | yes (1) |
| 111 | `cancel_webcam_scan` | 944 | yes (1) |
| 112 | `generate_alias_for_form` | 945 | yes (1) |
| 113 | `save_alias_config` | 946 | yes (1) |
| 114 | `import_url_requested` | 947 | yes (1) |
| 115 | `import_2fa_file` | 948 | yes (1) |
| 116 | `hotp_next` | 949 | yes (1) |
| 117 | `delete_auth_account` | 950 | yes (1) |
| 118 | `request_biometric_unlock` | 951 | yes (1) |
| 119 | `request_pin_unlock` | 952 | yes (1) |
| 120 | `setup_app_pin` | 953 | yes (1) |
| 121 | `disable_app_pin` | 954 | yes (1) |
| 122 | `setup_ext_pin` | 955 | yes (1) |
| 123 | `disable_ext_pin` | 956 | yes (1) |
| 124 | `type_credential_requested` | 957 | yes (1) |
| 125 | `type_item_requested` | 958 | yes (1) |
| 126 | `save_sync_config` | 959 | yes (1) |
| 127 | `sync_now` | 960 | yes (1) |
| 128 | `merge_preview_remote` | 961 | yes (1) |
| 129 | `merge_apply` | 962 | yes (1) |
| 130 | `share_grant_login` | 963 | yes (1) |
| 131 | `share_revoke` | 964 | yes (1) |
| 132 | `share_open_envelope` | 965 | yes (1) |
| 133 | `send_create` | 974 | yes (1) |
| 134 | `send_open` | 975 | yes (1) |
| 135 | `send_open_pasted` | 976 | yes (1) |
| 136 | `admin_import_members` | 985 | yes (1) |
| 137 | `admin_deprovision` | 986 | yes (1) |
| 138 | `admin_oidc_verify` | 987 | yes (1) |
| 139 | `admin_bind_key` | 988 | yes (1) |
| 140 | `admin_export_audit` | 989 | yes (1) |
| 141 | `set_p2p` | 990 | yes (1) |
| 142 | `scan_p2p` | 991 | yes (1) |
| 143 | `sync_peer` | 992 | yes (1) |
| 144 | `regen_p2p_pin` | 993 | yes (1) |
| 145 | `check_updates` | 994 | yes (1) |
| 146 | `download_update` | 995 | yes (1) |
| 147 | `restart_update` | 996 | yes (1) |
| 148 | `pick_import_file` | 997 | yes (1) |
| 149 | `install_browser_host` | 998 | yes (1) |
| 150 | `install_firefox_host` | 1001 | yes (1) |
| 151 | `ga_export_start` | 1003 | yes (1) |
| 152 | `ga_export_page` | 1004 | yes (1) |
| 153 | `ga_copy_uri` | 1005 | yes (1) |
| 154 | `export_vault` | 1006 | yes (1) |
| 155 | `set_blackout` | 1007 | yes (1) |
| 156 | `set_favicons` | 1008 | yes (1) |
| 157 | `factory_reset_start` | 1018 | yes (1) |
| 158 | `factory_reset_cancel` | 1019 | yes (1) |
| 159 | `factory_reset_arm` | 1020 | yes (1) |
| 160 | `factory_reset_confirm` | 1021 | yes (1) |
| 161 | `set_clipboard_timeout` | 1022 | yes (1) |
| 162 | `set_autolock_timeout` | 1023 | yes (1) |
| 163 | `autofill_pill_clicked` | 1024 | yes (1) |
| 164 | `lock_now` | 1025 | yes (1) |
| 165 | `exit_app` | 1026 | yes (1) |
| 166 | `scan_secrets` | 1027 | yes (1) |
| 167 | `copy_shell_complete` | 1028 | yes (1) |
| 168 | `set_duress_password` | 1029 | yes (1) |
| 169 | `plant_canary` | 1030 | yes (1) |
| 170 | `set_travel_mode` | 1032 | yes (1) |
| 171 | `pick_attachment` | 1033 | yes (1) |
| 172 | `download_attachment` | 1034 | yes (1) |
| 173 | `delete_attachment` | 1035 | yes (1) |
| 174 | `preview_attachment` | 1039 | yes (1) |
| 175 | `override_favicon` | 1040 | yes (1) |
| 176 | `clear_custom_favicons` | 1041 | yes (1) |
| 177 | `refresh_favicons` | 1042 | yes (1) |
| 178 | `toggle_travel` | 1043 | yes (1) |
| 179 | `regenerate` | 1044 | yes (1) |
| 180 | `use_password` | 1045 | yes (1) |
| 181 | `close_panel` | 1046 | yes (1) |
| 182 | `query_changed` | 2682 | yes (1) |
| 183 | `item_selected` | 2685 | yes (1) |
| 184 | `copy_totp_selected` | 2686 | yes (1) |
| 185 | `type_selected` | 2687 | yes (1) |
| 186 | `qb_open_url` | 2688 | yes (1) |
| 187 | `dismiss` | 2689 | yes (1) |
| 188 | `capture_save` | 2831 | yes (1) |
| 189 | `capture_generate` | 2832 | yes (1) |
| 190 | `capture_cancel` | 2833 | yes (1) |

</details>


## Appendix B - binding contract coverage

| Contract | Count | Note |
|---|---|---|
| UI properties declared (`in/in-out/out/private`) | 355 | names are the Rust↔Slint contract |
| Rust `set_*` call sites | 1388 | every renamed property breaks one of these |
| Rust `get_*` call sites | 164 | reads back user input/state |
| Rust `invoke_*` call sites | 1 | `open_detail` at `main.rs:10136` |
| Callback declarations | 190 | 188 wired, 2 component-internal (`clicked`, `tapped`) - Appendix A |

Restyle rule: you may change body/layout/colors freely, but a property/callback rename is a
breaking API change and must be a separate, test-covered commit.
