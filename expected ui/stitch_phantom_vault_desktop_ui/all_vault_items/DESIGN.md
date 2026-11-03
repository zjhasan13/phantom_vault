---
name: Obsidian Vault
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394d'
  surface-container-lowest: '#060e20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3d'
  surface-container-highest: '#2d3449'
  on-surface: '#dae2fd'
  on-surface-variant: '#bbcabf'
  inverse-surface: '#dae2fd'
  inverse-on-surface: '#283044'
  outline: '#86948a'
  outline-variant: '#3c4a42'
  surface-tint: '#4edea3'
  primary: '#4edea3'
  on-primary: '#003824'
  primary-container: '#10b981'
  on-primary-container: '#00422b'
  inverse-primary: '#006c49'
  secondary: '#4cd7f6'
  on-secondary: '#003640'
  secondary-container: '#03b5d3'
  on-secondary-container: '#00424e'
  tertiary: '#c0c1ff'
  on-tertiary: '#1000a9'
  tertiary-container: '#9699ff'
  on-tertiary-container: '#1d17b2'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#6ffbbe'
  primary-fixed-dim: '#4edea3'
  on-primary-fixed: '#002113'
  on-primary-fixed-variant: '#005236'
  secondary-fixed: '#acedff'
  secondary-fixed-dim: '#4cd7f6'
  on-secondary-fixed: '#001f26'
  on-secondary-fixed-variant: '#004e5c'
  tertiary-fixed: '#e1e0ff'
  tertiary-fixed-dim: '#c0c1ff'
  on-tertiary-fixed: '#07006c'
  on-tertiary-fixed-variant: '#2f2ebe'
  background: '#0b1326'
  on-background: '#dae2fd'
  surface-variant: '#2d3449'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.015em
  headline-md:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Inter
    fontSize: 15px
    fontWeight: '600'
    lineHeight: 20px
  body-lg:
    fontFamily: Inter
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 22px
  body-md:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  label-lg:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: 0.02em
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.04em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 14px
    letterSpacing: 0.05em
  code-totp:
    fontFamily: JetBrains Mono
    fontSize: 26px
    fontWeight: '700'
    lineHeight: 32px
    letterSpacing: 0.15em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 0.75rem
  margin: 1rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1.25rem
  space-xl: 2rem
---

## Brand & Style

The design system projects absolute cryptographic integrity, local-first autonomy, and high-performance desktop utility. Built for engineers, security specialists, and privacy-conscious operators, it strips away consumer-grade fluff in favor of surgical precision, technical confidence, and instantaneous responsiveness. 

The aesthetic fuses **Modern Technical Minimalism** with **Subtle Acrylic Glassmorphism**:
- Deep, light-absorbing obsidian foundations convey fortress-like permanence.
- Electric mint and emerald cyan accents act as verified indicators of cryptographic trust, active zero-knowledge encryption, and local-only bridge states.
- Clean 1px translucent borders and hairline glass partitions delineate complex multi-column vault structures without adding visual weight.
- Every state transition—from unlocking an encrypted enclave to generating an ephemeral TOTP code—must feel deterministic, immediate, and mathematically robust.

## Colors

The palette relies on deep black-slate value scales to minimize eye strain during intensive screen use, accented by high-frequency emeralds and cyans that denote active cryptographic security.

### Color Roles & Semantics
- **Background Root (`#090D16`):** The primary desktop window canvas, active beneath sidebars and title bars.
- **Surface Elevation (`#0F172A` / `#1E293B`):** Surface tiers for lists, master vault panes, inspector cards, and dialogue sheets.
- **Primary Accent (`#10B981` / `#34D399`):** Represents verified integrity, active local database status, successful hash validations, and positive actions.
- **Secondary Accent (`#06B6D4`):** Represents active sync pipelines, peer-to-peer bridge verification, and read-only telemetry.
- **Tertiary Accent (`#6366F1`):** Applied strictly to system metadata, organization vaults, cryptographic protocols (e.g., Argon2id, ChaCha20-Poly1305), and credential categorization tags.
- **Critical / Vulnerable (`#F43F5E`):** Compromised passwords, duplicate credential warnings, and breached database notices.
- **Hairline Borders (`rgba(148, 163, 184, 0.08)` to `rgba(148, 163, 184, 0.16)`): Subtle structural outlines for list dividers, card perimeters, and input boundaries.

## Typography

Typography balances human-interface legibility with algorithmic rigor:
- **Inter** handles structural navigation, titles, section headers, and field labels. Its optical neutrality maintains focus on dense data matrices.
- **JetBrains Mono** is enforced across all security-sensitive and computational data: master password input characters, generated credentials, TOTP counter strings, cryptographic fingerprint hashes, public keys, and timestamps.
- **Tabular Figures (`tnum`):** Enabled globally for numerical readouts to prevent layout shift during countdowns and real-time TOTP expiry refreshes.

## Layout & Spacing

The layout is built for native multi-pane desktop paradigms (3-column layout):
- **Column 1 (Sidebar / Enclaves):** Fixed width (220px–260px). Houses vault collections, security health dashboards, and tag filters.
- **Column 2 (Item Index / Master List):** Fluid with min/max clamps (280px–380px). Dense list representation of items, search inputs, and sort filters.
- **Column 3 (Detail / Inspector View):** Primary fluid workspace occupying remaining canvas. Displays credential cards, decrypted fields, event logs, and audit trails.

Grid rhythm follows a compact 4px/8px coordinate base. Window drag regions occupy the top 38px of the primary chrome with native macOS traffic-light inset spacing (`margin-left: 78px` when framed natively).

## Elevation & Depth

This system avoids heavy, muddy drop shadows in favor of **Tonal Tiering**, **Crisp Backdrops**, and **Subtle Edge Reflections**:

- **Window Chrome & Background (Level 0):** `#090D16`. Light-absorbing base.
- **Navigation & Collapsible Sidebars (Level 1):** `#0F172A` with `backdrop-filter: blur(20px)` and an interior right hairline border of `1px solid rgba(255, 255, 255, 0.05)`.
- **Primary Item Cards & Detail Containers (Level 2):** `#1E293B` at `70%` opacity overlaid on deep slate, framed with `1px solid rgba(148, 163, 184, 0.12)`.
- **Flyouts, Context Menus & Command Palettes (Level 3):** `#0F172A` elevated with a double-ring effect: `0 0 0 1px rgba(16, 185, 129, 0.2), 0 16px 32px -8px rgba(0, 0, 0, 0.65)`.
- **Cryptographic Focus / Active State:** Elements in edit or decrypt mode cast a focused glow: `0 0 0 1px #10B981, 0 0 16px -2px rgba(16, 185, 129, 0.25)`.

## Shapes

The design system employs a calibrated **Soft (Level 1)** geometric standard. This geometry mirrors technical desktop tooling—compact, clean, and space-efficient:
- Standard interactive elements (inputs, buttons, segmented controls): `rounded` (`4px` / `0.25rem`).
- Cards, modal containers, and inspector groupings: `rounded-lg` (`8px` / `0.5rem`).
- Floating command palettes and toast alerts: `rounded-xl` (`12px` / `0.75rem`).
- Status dots, TOTP circular countdown rings, and avatar glyphs: strict full pills (`rounded-full`).

## Components

### Credential Fields
- **Container:** Dark slate input (`#0A0F1D`) with subtle `1px` border (`rgba(148, 163, 184, 0.15)`). Changes to `#10B981` border on active focus.
- **Text:** Rendered in `JetBrains Mono`. Masked state uses geometric dots (`U+2022`) with generous tracking. Decrypted state renders in bright neutral text.
- **Action Cluster:** Right-aligned inline actions (Copy, Reveal/Mask, Password Generator) styled as ghost icon buttons (`16px`) that transition to `rgba(255, 255, 255, 0.1)` on hover.

### TOTP Token Blocks
- Large numeric visualization in `code-totp` (`JetBrains Mono`).
- Grouped into two three-digit blocks with a center separator for instantaneous cognitive capture.
- Accompanied by a circular SVG countdown timer (pie fill or depleting stroke) that shifts color from `#10B981` (safe) to `#F59E0B` (warning, &lt;7s) to `#F43F5E` (critical, &lt;3s).

### Buttons
- **Primary:** High-saturation mint (`#10B981`) background, solid dark obsidian typography (`#06110D`), font weight 600. Glowing focus ring on keyboard interaction.
- **Secondary:** Surface slate background (`#1E293B`) with a 1px border (`rgba(255, 255, 255, 0.08)`), text in `#E2E8F0`.
- **Danger:** Deep crimson fill (`rgba(244, 63, 94, 0.1)`) with `#F43F5E` text and border for sensitive actions (e.g., "Purge Enclave").

### Status Indicator Badges (Local-First Bridge)
- Pill-shaped indicator with a leading 6px pulsing dot.
- **Local Enclave Only:** Solid emerald dot with text `LOCAL SECURE` in `label-sm`.
- **P2P Encrypted Sync:** Solid cyan dot with text `P2P LINKED`.
- **Vault Locked:** Muted zinc dot with text `ENCRYPTED`.

### Master Item List Row
- Displays service icon/monogram, entry title, username/identifier, and category tag.
- Selected state uses a subtle mint gradient rail (`2px` solid `#10B981` on the left border) with a background fill of `rgba(16, 185, 129, 0.06)`.