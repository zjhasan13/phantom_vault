# FeatureGapAnalyst — run 33a85550 participant 2

রিপোর্ট পাঠানো হয়েছে — [C-gap.md](<C:/Users/Admin/AppData/Local/Temp/pv-scan/C-gap.md>) (253 lines, 11 sections). Static analysis only: nothing was built or run.

**Top 5 gaps**
1. **Delete reprompt is a dead control** — arm `rp_action = 3` is fully implemented (`src/main.rs:12106-12160`) but nothing ever sets it; the live delete (`src/main.rs:6598`) checks decoy mode only.
2. **Reveal bypasses Rust entirely** — `ui/appwindow.slint:3198` flips `d_secret_visible` in Slint: no gate, no access-log entry.
3. **Auto-lock + clipboard timeout are memory-only** (`src/main.rs:4591-4592`, written at `:15445-15466`): every restart silently reverts to Never / 15 s.
4. **Idle clock has only 7 feeds** (`:5012, :5565, :8508, :8549, :15461, :15725, :4724`) — none on editor typing, so a 1-minute setting can lock the vault mid-edit.
5. **Honeytoken and PIN-disable writes are swallowed** (`src/security/canary.rs:52,162,164`; `src/security/app_pin.rs:207-208`) — the trip record or the disable can silently not happen.

Also verified: export failure goes to `eprintln!` only (`:12222`), and the custom-logo picker (`appwindow.slint:1321`) has no emitter.

**Maturity:** ~99% wired (all 222 window callbacks resolve, zero empty handlers), ~90% on lock/wipe, but ~55% on reprompt coverage and ~50% on settings persistence — a finished shell with brittle security edges.

Note: the repo's AGENTS.md asks for Bangla replies; I answered in English to match your brief's language and its English section names.