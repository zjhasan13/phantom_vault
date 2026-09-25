//! Session-lock probe (rules Cat 8 — Workstation-Lock + Screensaver + RDP).
//!
//! Win+L, screensaver start, and RDP disconnect all converge on one
//! observable: our session stops presenting a foreground window (locked
//! sessions have none) or the screensaver engine reports running. Polled
//! from the auto-lock ticker — no message pump or HWND hooks required.
//! A 2-consecutive-hit debounce (`LockMonitor`) absorbs single-poll
//! flakiness (UAC prompts, fullscreen transitions).

/// True when the session looks locked right now: no foreground window
/// (Win+L / RDP disconnect) or the screensaver is actively running.
pub fn workstation_locked() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, SPI_GETSCREENSAVERRUNNING, SystemParametersInfoW,
    };
    // SAFETY: parameterless read; null HWND means "no foreground window".
    let fg = unsafe { GetForegroundWindow() };
    if fg.is_null() {
        return true;
    }
    // SAFETY: bounded u32 out-param, no buffers retained.
    let mut running: u32 = 0;
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETSCREENSAVERRUNNING,
            0,
            &mut running as *mut u32 as *mut core::ffi::c_void,
            0,
        )
    };
    ok != 0 && running != 0
}

/// Debounce: only report "locked" after N consecutive locked polls.
/// Pure — unit tested.
pub struct LockMonitor {
    threshold: u32,
    hits: u32,
}

impl LockMonitor {
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold: threshold.max(1),
            hits: 0,
        }
    }

    /// Feed one poll; returns true exactly when the lock tripwire fires.
    /// A single unlocked poll resets the streak (no sticky false positive).
    pub fn observe(&mut self, locked: bool) -> bool {
        if locked {
            self.hits = self.hits.saturating_add(1);
            if self.hits >= self.threshold {
                self.hits = 0; // re-arm: each firing consumes the streak
                return true;
            }
            return false;
        }
        self.hits = 0;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_after_threshold_consecutive_hits() {
        let mut m = LockMonitor::new(2);
        assert!(!m.observe(true));
        assert!(m.observe(true)); // 2nd consecutive → fire
        assert!(!m.observe(true)); // re-armed: needs a fresh streak
        assert!(m.observe(true));
    }

    #[test]
    fn single_unlocked_poll_resets_streak() {
        let mut m = LockMonitor::new(3);
        assert!(!m.observe(true)); // hits=1
        assert!(!m.observe(true)); // hits=2
        assert!(!m.observe(false)); // reset
        assert!(!m.observe(true)); // hits=1
        assert!(!m.observe(true)); // hits=2
        assert!(m.observe(true)); // hits=3 → fire (only post-reset streak counts)
        assert!(!m.observe(true)); // re-armed
    }

    #[test]
    fn probe_never_panics() {
        // Touches the real session; asserts only "it answers".
        let _ = workstation_locked();
    }
}
