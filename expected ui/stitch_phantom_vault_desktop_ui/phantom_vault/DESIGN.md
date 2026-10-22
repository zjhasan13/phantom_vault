---
name: Phantom Vault
colors:
  surface: '#131315'
  surface-dim: '#131315'
  surface-bright: '#39393b'
  surface-container-lowest: '#0e0e10'
  surface-container-low: '#1c1b1d'
  surface-container: '#201f22'
  surface-container-high: '#2a2a2c'
  surface-container-highest: '#353437'
  on-surface: '#e5e1e4'
  on-surface-variant: '#cbc3d7'
  inverse-surface: '#e5e1e4'
  inverse-on-surface: '#313032'
  outline: '#958ea0'
  outline-variant: '#494454'
  surface-tint: '#d0bcff'
  primary: '#d0bcff'
  on-primary: '#3c0091'
  primary-container: '#a078ff'
  on-primary-container: '#340080'
  inverse-primary: '#6d3bd7'
  secondary: '#cebdff'
  on-secondary: '#381385'
  secondary-container: '#4f319c'
  on-secondary-container: '#bea8ff'
  tertiary: '#4edea3'
  on-tertiary: '#003824'
  tertiary-container: '#00a572'
  on-tertiary-container: '#00311f'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#e9ddff'
  primary-fixed-dim: '#d0bcff'
  on-primary-fixed: '#23005c'
  on-primary-fixed-variant: '#5516be'
  secondary-fixed: '#e8ddff'
  secondary-fixed-dim: '#cebdff'
  on-secondary-fixed: '#21005e'
  on-secondary-fixed-variant: '#4f319c'
  tertiary-fixed: '#6ffbbe'
  tertiary-fixed-dim: '#4edea3'
  on-tertiary-fixed: '#002113'
  on-tertiary-fixed-variant: '#005236'
  background: '#131315'
  on-background: '#e5e1e4'
  surface-variant: '#353437'
typography:
  headline-xl:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.025em
  headline-xl-mobile:
    fontFamily: Inter
    fontSize: 26px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 26px
    letterSpacing: -0.015em
  body-lg:
    fontFamily: Inter
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 22px
    letterSpacing: -0.01em
  body-md:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
    letterSpacing: -0.005em
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  label-code-lg:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: -0.01em
  label-code-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0em
  label-badge:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '600'
    lineHeight: 12px
    letterSpacing: 0.06em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-desktop: 1.5rem
  margin: 1rem
  margin-desktop: 2rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1.25rem
  space-xl: 2rem
---

## Brand & Style

The design system embodies precision, cryptographically verified privacy, and sovereign local-first utility. Inspired by modern native developer environments and performance-focused GUI tools, it delivers an aesthetic of calculated restraint, technical confidence, and uncompromising security.

Key attributes:
- **Sovereign & Local-First:** Communicates that data lives and stays on the client machine; latency is zero, operations feel immediate, and security is verifiable rather than promised.
- **Architectural Minimalism:** Eliminates ornamental clutter in favor of high-density clarity, structural 1px gridlines, and clear functional affordances.
- **Developer-Native Precision:** Combines utilitarian neutral geometry with technical monospace cadences for sensitive strings, cryptographic hashes, and status states.
- **Calculated Energy:** Anchored by an ultra-deep charcoal ground, puncturing focus states and actionable verification vectors with a vivid electric violet and signal-driven status indicators.

## Colors

The palette is engineered for prolonged sessions in low-light environments, prioritizing contrast ratios that exceed WCAG AAA standards for legibility.

- **Primary (`#8B5CF6`) & Secondary Accent (`#A78BFA`):** Used strictly for high-intent interactive states, verified security anchors, active selection rings, and biometric confirmation triggers. A deeper variant (`#7C3AED`) serves as active/pressed feedback.
- **Tertiary / Security Semantic (`#10B981`):** A razor-sharp emerald green reserved exclusively for cryptographically secure states, operational health, zero-leak audit markers, and successful sync confirmations.
- **Neutrals & Dark Foundation:** 
  - Canvas / Background: `#09090B` (pure dark zinc)
  - Surface Tier 1 (Panels, Sidebars): `#121215`
  - Surface Tier 2 (Cards, Groups, Input Grounds): `#18181B`
  - Surface Tier 3 (Hover highlights, Overlays): `#27272A`
  - Borders & Dividers: Subtle structural boundaries mapped to `#27272A` (default resting) and `#3F3F46` (focused/hovered).
  - Text: Primary `#FAFAFA`, Muted Secondary `#A1A1AA`, Code/Meta `#71717A`.
- **System Diagnostics:** Amber (`#F59E0B`) for expiring secrets or weak entropy; Crimson (`#EF4444`) for compromised credentials, breached domains, or clipboard timeout warnings.

## Typography

The typographic hierarchy distinguishes narrative guidance from programmatic data:

- **Inter:** Drives general interface communication, category titles, section headers, and field descriptors. Engineered with tight tracking at larger sizes to maintain technical density without sacrificing readability.
- **JetBrains Mono:** Dedicated to raw credentials, cryptographic keys, master seeds, audit hashes, OTP tokens, status badges, and keyboard shortcuts. Ensures unambiguous character distinction (e.g., distinguishing `0` vs `O`, `l` vs `1`).
- **Tabular Numerics:** All alphanumeric numeric rendering within lists, timers, and clipboard countdowns must invoke `font-variant-numeric: tabular-nums` to eliminate layout jitter during high-frequency syncs.

## Layout & Spacing

The layout philosophy mirrors multi-pane workspace utilities (such as code editors and system shells), relying on structural split panes, vertical dividers, and rigorous information packing.

- **Workspace Panes:** Desktop experiences adopt a strict 3-pane paradigm: navigation rail (64px fixed or 220px collapsable), vault item list (320px–380px fixed width), and detail inspection panel (fluid flex child).
- **Responsive Adaptation:**
  - **Desktop (>=1024px):** Persistent 3-column architecture, 1px vertical borders defining workspace boundaries.
  - **Tablet (768px - 1023px):** Two-pane view (collapsible sidebar drawer, persistent master-detail view).
  - **Mobile (<768px):** Single-pane drilldown stack with instant directional transitions; action bars pinned to safe viewport bottom edges.
- **Rhythm:** Layout spaces strictly use 4px and 8px base increments. Internal component grouping uses compact padding (`space-xs` and `space-sm`) to allow visibility of 15+ credentials per view without vertical scrolling.

## Elevation & Depth

Visual hierarchy rejects heavy drop shadows in favor of low-contrast hairline borders, meticulous luminance stacking, and localized electric glow.

- **Luminance Stacking:** Depth is achieved by shifting background brightness up through surface tiers (`#09090B` foundation -> `#121215` panel -> `#18181B` card/input -> `#27272A` hover).
- **Hairline Boundary Outlines:** Every card, modal, and panel boundary is delineated by a 1px solid stroke (`#27272A`), providing crisp separation on high-DPI displays.
- **Targeted Glow:** Overlays and primary action focal points (like the quick-switcher or master unlock field) use an ambient violet focus drop (`0 0 0 1px #8B5CF6, 0 8px 30px rgba(139, 92, 246, 0.15)`).
- **Modals & Overlays:** Quick-switchers (command palettes) float over an intense backdrop blur (`backdrop-filter: blur(12px)`) with an inner 1px border highlighted with a subtle gradient ring.

## Shapes

The design system uses a strict **Soft (`1`)** shape language, communicating high-density engineering, structural durability, and tool-like precision.

- **Base Radii (`0.25rem` / `4px`):** Applied to badges, code tags, nested inputs, keyboard shortcut keys (`<kbd>`), and toggle switches.
- **Container Radii (`0.5rem` / `8px`):** Applied to modal dialogs, item cards, drop-down menus, and action buttons.
- **Floating Overlays (`0.75rem` / `12px`):** Applied exclusively to the top-level command palette and floating notifications.
- Rounding never exceeds `12px` to prevent consumer-app softness and maintain a focused terminal/desktop developer personality.

## Components

### Buttons
- **Primary:** Background `#8B5CF6`, text `#FAFAFA`, 1px border `#A78BFA` at 20% opacity. Hover: `#7C3AED`. Active: scale 0.99 with an immediate 50ms transition.
- **Secondary / Subdued:** Background `#18181B`, text `#FAFAFA`, border 1px solid `#27272A`. Hover: `#27272A`, border `#3F3F46`.
- **Destructive:** Background `rgba(239, 68, 68, 0.1)`, text `#EF4444`, border 1px solid `rgba(239, 68, 68, 0.2)`.

### Inputs & Password Fields
- Background `#18181B`, border 1px solid `#27272A`, text `Inter` 13px. Focus: 1px ring of `#8B5CF6` with zero layout shift.
- **Secret Fields:** Rendered in `JetBrains Mono`. Masked characters display as large mid-line solid dots. Include an integrated, copy-on-click trigger with quick-feedback tooltip ("Copied"), an entropy strength meter line (2px bar anchored to the bottom border), and an immediate unmask icon toggle.

### Lists & Vault Item Rows
- Flat row structures separated by 1px subtle borders (`#1F1F23`) or structured padding.
- Item state: Resting `#00000000`, Selected `#1F1F24` with a 2px vertical indicator bar in `#8B5CF6` along the left border. Hover displays quick actions (Copy User, Copy Pass, Launch URL) revealed at the trailing edge.

### Toggles & Status Badges
- **Toggles:** Ultra-compact track (32px x 18px) in `#27272A` (OFF) switching to `#8B5CF6` (ON). Knob is 14px crisp white square-circle (`rounded-xs`), shifting with zero bounce.
- **Status Badges:** Strict uppercase in `label-badge` (`JetBrains Mono`). Embedded with a 4px status dot.
  - "SECURED": dot `#10B981`, background `rgba(16, 185, 129, 0.1)`, text `#10B981`.
  - "EXPOSED": dot `#EF4444`, background `rgba(239, 68, 68, 0.1)`, text `#EF4444`.
  - "LOCAL": dot `#A1A1AA`, background `rgba(161, 161, 170, 0.1)`, text `#A1A1AA`.

### Cards & Section Groupings
- Grouped panels feature a distinct upper meta-bar containing a category label in uppercase `label-code-md` accompanied by an inline item count.
- Enclosed with a unified 1px border in `#27272A` with an internal ground of `#121215`.

### Security-Specific Components
- **Entropy Meter:** Segmented 4-step horizontal progress bar (Crack Time: Instant, Hours, Centuries, Heat Death of Universe) shifting from `#EF4444` to `#F59E0B` to `#10B981`.
- **Clipboard Countdown Pill:** Fixed-width monospaced pill widget displaying an automatic 30s memory purge timer with an animated SVG radial progress ring.
- **Quick-Switcher / Command Palette:** Centered modal with search-as-you-type fuzzy indexing across credentials, tags, and private keys, operable entirely through vim/emacs keys (`j`/`k` or arrow keys).