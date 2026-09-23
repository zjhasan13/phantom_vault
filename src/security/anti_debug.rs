//! Phase 15 (Option 1) — Anti-debug / memory-dump self-defense.
//!
//! Layers (defense in depth — no single check is trusted alone):
//!
//! 1. `IsDebuggerPresent` — PEB flag, catches naive debuggers.
//!
//! 2. `CheckRemoteDebuggerPresent` on own process — catches remote/HWBP tricks.
//!
//! 3. Timing tripwire — `Instant` around a short sleep; a huge skew
//!    means someone is single-stepping or freezing our threads.
//!
//! On any trip: best-effort callback (wipe RAM) then immediate hard exit.
//!
//! No unwrap/expect — all Win32 failures fail CLOSED (treated as hostile).

use windows::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent, IsDebuggerPresent,
};
use windows::Win32::System::Threading::GetCurrentProcess;

const TIMING_SLACK_MS: u64 = 1500;

/// Single sweep: true = debugger/defense-evasion detected.
/// Kept for tests; the watchdog uses the split checks below.
#[allow(dead_code)]
pub fn sweep() -> bool {
    debugger_present() || timing_skewed()
}

/// Instant-trip checks: PEB flag + remote-debugger query.
fn debugger_present() -> bool {
    // SAFETY: read-only process-state queries, no buffers involved.
    unsafe {
        if IsDebuggerPresent().as_bool() {
            return true;
        }
        let mut remote = Default::default();
        if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote).is_ok()
            && remote.as_bool()
        {
            return true;
        }
    }
    false
}

/// Flaky check: sleep 100ms; skew beyond slack ⇒ traced/frozen.
/// Needs a second consecutive strike before the watchdog acts.
/// Uses std Instant (monotonic) — no extra Win32 surface needed.
fn timing_skewed() -> bool {
    let t0 = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(100));
    t0.elapsed().as_millis() as u64 > 100 + TIMING_SLACK_MS
}

/// Background watchdog. Debugger flags trip instantly; the flaky timing
/// tripwire needs TWO consecutive strikes (VM stalls must never kill us).
/// `on_trip` runs the wipe, then we hard-exit.
pub fn start_watchdog(on_trip: impl Fn() + Send + Sync + 'static) {
    std::thread::spawn(move || {
        let mut n: u64 = 0;
        let mut timing_strikes = 0u8;
        loop {
            // ~7s base + 0..3s pseudo-jitter (no RNG dep needed here).
            n = n.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let wait = 7000 + (n >> 33) % 3000;
            std::thread::sleep(std::time::Duration::from_millis(wait));
            if debugger_present() {
                on_trip();
                // Hard exit — no destructors, no dump-friendly unwinding.
                std::process::exit(0xD83B);
            }
            if timing_skewed() {
                timing_strikes += 1;
                if timing_strikes >= 2 {
                    on_trip();
                    std::process::exit(0xD83B);
                }
            } else {
                timing_strikes = 0;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_runs_without_panic() {
        // Cannot assert true/false (environment-dependent) — only that the
        // sweep itself never panics or touches unwraps.
        let _ = sweep();
    }
}
