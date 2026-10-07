//! Phase 25 — Bluetooth Low Energy (BLE) proximity auto-lock.
//!
//! Watches BLE advertisement packets from the user's own device (phone/watch)
//! via WinRT `BluetoothLEAdvertisementWatcher`. When the device walks away —
//! no packet for `grace_period_secs`, or RSSI below threshold for 3 straight
//! heartbeats — the vault takes the standard `lock_vault_now` path.
//!
//! Fail-safe by construction:
//! - No radio / radio off / watcher error ⇒ clean status string, NEVER a lock.
//! - Never-seen device ⇒ quiet (a fresh boot with the phone absent must not
//!   instant-lock before the user does anything).
//! - Momentary dips are debounced (3 consecutive weak strikes).
//! - Everything WinRT runs on a worker thread; the Slint loop is only ever
//!   touched via `on_status` / `on_fire` callbacks.
//! - The debounce core (`ProximityMonitor`) is pure and unit-tested with
//!   zero hardware.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Sidecar beside the vault (device name + thresholds are NOT secrets).
pub const CONFIG_FILE: &str = "proximity.json";
/// Default cutoff: Medium sensitivity (~15 ft).
pub const DEFAULT_RSSI_THRESHOLD: i16 = -85;
/// Default debounce window before a missing device locks.
pub const DEFAULT_GRACE_SECS: u64 = 15;
/// Consecutive weak heartbeats required to fire (momentary dips ignored).
pub const WEAK_STRIKES_TO_FIRE: u32 = 3;
/// Heartbeat cadence (spec: every 3–5 seconds).
pub const HEARTBEAT_SECS: u64 = 4;

/// Sensitivity presets shared with the Slint segmented control:
/// 0 = Close (~10 ft / −75 dBm), 1 = Medium (~15 ft / −85 dBm),
/// 2 = Far (~25 ft / −95 dBm). Pure — unit tested.
pub fn threshold_for_sensitivity(level: i32) -> i16 {
    match level {
        0 => -75,
        2 => -95,
        _ => -85,
    }
}

/// Inverse of `threshold_for_sensitivity` (nearest preset wins). Pure.
pub fn sensitivity_for_threshold(threshold: i16) -> i32 {
    if threshold > -80 {
        0
    } else if threshold > -90 {
        1
    } else {
        2
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProximityConfig {
    pub enabled: bool,
    /// Bluetooth device name to track (substring, case-insensitive).
    pub device_name: String,
    /// Signal cutoff in dBm (more negative = allow farther).
    pub rssi_threshold: i16,
    /// Debounce window for a missing device.
    pub grace_period_secs: u64,
}

impl Default for ProximityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            device_name: String::new(),
            rssi_threshold: DEFAULT_RSSI_THRESHOLD,
            grace_period_secs: DEFAULT_GRACE_SECS,
        }
    }
}

impl ProximityConfig {
    /// Load persisted settings. Missing/corrupt file = defaults (fail open,
    /// feature stays OFF — never surprise-lock on a broken config).
    pub fn load() -> Self {
        Self::load_from(std::path::Path::new(CONFIG_FILE))
    }

    pub fn load_from(path: &std::path::Path) -> Self {
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let mut cfg: ProximityConfig =
            serde_json::from_str(&raw).unwrap_or_default();
        if cfg.grace_period_secs == 0 {
            cfg.grace_period_secs = DEFAULT_GRACE_SECS;
        }
        cfg
    }

    /// Persist settings. Best effort — a failed write must never break the UI.
    pub fn save(&self) {
        let _ = self.save_to(std::path::Path::new(CONFIG_FILE));
    }

    pub fn save_to(&self, path: &std::path::Path) -> Result<(), String> {
        let text =
            serde_json::to_string_pretty(self).map_err(|e| format!("encode: {e}"))?;
        std::fs::write(path, text).map_err(|e| format!("write: {e}"))
    }
}

/// Pure debounce state machine: no WinRT, no clock reads (time is injected),
/// fully deterministic under test.
#[derive(Debug, Default)]
pub struct ProximityMonitor {
    last_rssi: Option<i16>,
    last_seen: Option<Instant>,
    weak_strikes: u32,
}

impl ProximityMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget all sightings (device change, lock, disable).
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Record one advertisement packet from the tracked device.
    pub fn note_packet(&mut self, rssi: i16, now: Instant) {
        self.last_rssi = Some(rssi);
        self.last_seen = Some(now);
    }

    /// Latest signal (for the Settings status line). None = nothing heard yet.
    pub fn last_rssi(&self) -> Option<i16> {
        self.last_rssi
    }

    /// One heartbeat tick. Returns true exactly when the vault must lock.
    pub fn heartbeat(&mut self, cfg: &ProximityConfig, now: Instant) -> bool {
        if !cfg.enabled {
            self.weak_strikes = 0;
            return false;
        }
        let Some(seen) = self.last_seen else {
            // Heard nothing since (re)start — stay quiet, never lock blind.
            return false;
        };
        if now.duration_since(seen) >= Duration::from_secs(cfg.grace_period_secs.max(1)) {
            self.weak_strikes = 0;
            return true; // device gone past the grace window
        }
        match self.last_rssi {
            // Strictly below the cutoff counts as weak; equality is "holding on".
            Some(rssi) if rssi < cfg.rssi_threshold => {
                self.weak_strikes += 1;
                if self.weak_strikes >= WEAK_STRIKES_TO_FIRE {
                    self.weak_strikes = 0;
                    return true;
                }
                false
            }
            _ => {
                self.weak_strikes = 0;
                false
            }
        }
    }
}

/// Bring up one watcher bound to the CURRENT config snapshot. Returns the
/// live watcher (dropping it stops the scan) + registration token.
///
/// The watcher bring-up itself is the radio gate: no radio / radio off /
/// no permission surfaces here as a clean `Err` (typically naming the radio),
/// and the service loop turns that into a status line + 30s retry — the vault
/// is never locked on radio errors.
fn bring_up_watcher(
    config: &Arc<Mutex<ProximityConfig>>,
    monitor: &Arc<Mutex<ProximityMonitor>>,
) -> Result<
    (
        windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher,
        windows::Foundation::EventRegistrationToken,
    ),
    String,
> {
    use windows::Devices::Bluetooth::Advertisement::{
        BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
        BluetoothLEScanningMode,
    };
    use windows::Foundation::TypedEventHandler;

    let watcher =
        BluetoothLEAdvertisementWatcher::new().map_err(|e| format!("watcher init: {e}"))?;
    watcher
        .SetScanningMode(BluetoothLEScanningMode::Passive)
        .map_err(|e| format!("scan mode: {e}"))?;
    let token = watcher
        .Received(&TypedEventHandler::new({
            let config = Arc::clone(config);
            let monitor = Arc::clone(monitor);
            move |_: &Option<BluetoothLEAdvertisementWatcher>,
                  args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                let Some(args) = args.as_ref() else {
                    return Ok(());
                };
                let rssi = args.RawSignalStrengthInDBm()?;
                let name = args
                    .Advertisement()
                    .and_then(|a| a.LocalName())
                    .map(|h| h.to_string())
                    .unwrap_or_default();
                let want = config
                    .lock()
                    .map(|c| c.device_name.clone())
                    .unwrap_or_default();
                if want.trim().is_empty() {
                    return Ok(());
                }
                if name
                    .to_lowercase()
                    .contains(&want.trim().to_lowercase())
                {
                    if let Ok(mut m) = monitor.lock() {
                        m.note_packet(rssi, Instant::now());
                    }
                }
                Ok(())
            }
        }))
        .map_err(|e| format!("subscribe: {e}"))?;
    watcher.Start().map_err(|e| format!("start: {e}"))?;
    Ok((watcher, token))
}

/// Background service: passive scan + heartbeat evaluation.
/// - `is_unlocked`: vault-open probe (locked ticks reset the monitor).
/// - `on_status`: Settings live-status line (worker thread — route to UI).
/// - `on_fire`: lock trigger (worker thread — route to UI).
///
/// Never panics, never locks the vault on radio errors.
pub fn start_proximity_service(
    config: Arc<Mutex<ProximityConfig>>,
    monitor: Arc<Mutex<ProximityMonitor>>,
    is_unlocked: Arc<dyn Fn() -> bool + Send + Sync>,
    on_status: impl Fn(String) + Send + Sync + 'static,
    on_fire: impl Fn() + Send + Sync + 'static,
) {
    std::thread::spawn(move || {
        // The live watcher is held here; dropping it (disable/rename/failure)
        // stops the radio scan. Recreated on the next loop as needed.
        let mut watcher: Option<(
            windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher,
            windows::Foundation::EventRegistrationToken,
        )> = None;
        loop {
            let cfg = config.lock().map(|c| c.clone()).unwrap_or_default();
            if !cfg.enabled || cfg.device_name.trim().is_empty() {
                drop(watcher.take());
                if let Ok(mut m) = monitor.lock() {
                    m.reset();
                }
                on_status(if !cfg.enabled {
                    "⚪ Proximity Inactive".to_string()
                } else {
                    "⚪ Proximity on — enter your phone's Bluetooth name.".to_string()
                });
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
            if watcher.is_none() {
                match bring_up_watcher(&config, &monitor) {
                    Ok(w) => {
                        watcher = Some(w);
                        on_status(format!(
                            "🟢 Tracking “{}” (waiting for signal…)",
                            cfg.device_name.trim()
                        ));
                    }
                    Err(e) => {
                        // Radio off / unsupported / no permission: report, wait,
                        // retry — the vault stays exactly as it was.
                        on_status(format!("⚪ Proximity unavailable ({e})."));
                        std::thread::sleep(Duration::from_secs(30));
                        continue;
                    }
                }
            }
            // Heartbeat: locked ticks just re-arm the debounce.
            let fire = if is_unlocked() {
                monitor
                    .lock()
                    .map(|mut m| m.heartbeat(&cfg, Instant::now()))
                    .unwrap_or(false)
            } else {
                if let Ok(mut m) = monitor.lock() {
                    m.reset();
                }
                false
            };
            if fire {
                crate::security::access_log::log_event(
                    "proximity/auto-lock",
                    &cfg.device_name,
                );
                on_fire();
                // Re-arm so a still-absent device doesn't spam the trigger;
                // the lock screen + monitor reset on next unlock own the rest.
                if let Ok(mut m) = monitor.lock() {
                    m.reset();
                }
            } else {
                // Live signal readout (Strong ≥ cutoff, else Weak).
                let readout = monitor.lock().ok().and_then(|m| m.last_rssi()).map(
                    |rssi| {
                        if rssi >= cfg.rssi_threshold {
                            "Strong"
                        } else {
                            "Weak"
                        }
                    },
                );
                match readout {
                    Some(level) => on_status(format!(
                        "🟢 Tracking “{}” (Signal: {level})",
                        cfg.device_name.trim()
                    )),
                    None => on_status(format!(
                        "🟢 Tracking “{}” (waiting for signal…)",
                        cfg.device_name.trim()
                    )),
                }
            }
            std::thread::sleep(Duration::from_secs(HEARTBEAT_SECS));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_on(threshold: i16, grace_secs: u64) -> ProximityConfig {
        ProximityConfig {
            enabled: true,
            device_name: "Phone".into(),
            rssi_threshold: threshold,
            grace_period_secs: grace_secs,
        }
    }

    #[test]
    fn momentary_dip_does_not_fire_sustained_weak_does() {
        let cfg = cfg_on(-85, 60);
        let mut m = ProximityMonitor::new();
        let t0 = Instant::now();
        m.note_packet(-70, t0);
        assert!(!m.heartbeat(&cfg, t0)); // strong: no strike
        m.note_packet(-90, t0);
        assert!(!m.heartbeat(&cfg, t0)); // strike 1
        assert!(!m.heartbeat(&cfg, t0)); // strike 2
        // Recovery before the 3rd strike clears the count…
        m.note_packet(-70, t0);
        assert!(!m.heartbeat(&cfg, t0));
        // …so three fresh weak ticks are needed.
        m.note_packet(-90, t0);
        assert!(!m.heartbeat(&cfg, t0));
        assert!(!m.heartbeat(&cfg, t0));
        assert!(m.heartbeat(&cfg, t0)); // strike 3 → fire
    }

    #[test]
    fn cutoff_equality_holds_on() {
        let cfg = cfg_on(-85, 60);
        let mut m = ProximityMonitor::new();
        let t0 = Instant::now();
        // Exactly at the cutoff is "holding on", never a strike.
        for _ in 0..5 {
            m.note_packet(-85, t0);
            assert!(!m.heartbeat(&cfg, t0));
        }
    }

    #[test]
    fn absence_past_grace_fires_inside_grace_does_not() {
        let cfg = cfg_on(-85, 15);
        let mut m = ProximityMonitor::new();
        let t0 = Instant::now();
        m.note_packet(-60, t0);
        assert!(!m.heartbeat(&cfg, t0 + Duration::from_secs(14)));
        assert!(m.heartbeat(&cfg, t0 + Duration::from_secs(15)));
    }

    #[test]
    fn never_seen_stays_quiet() {
        let cfg = cfg_on(-85, 15);
        let mut m = ProximityMonitor::new();
        // No packet ever — even far in the future, no blind lock.
        assert!(!m.heartbeat(&cfg, Instant::now() + Duration::from_secs(3600)));
    }

    #[test]
    fn disabled_ignores_everything() {
        let mut off = cfg_on(-85, 15);
        off.enabled = false;
        let mut m = ProximityMonitor::new();
        let t0 = Instant::now();
        m.note_packet(-99, t0);
        // Deep weak + far-past-grace, still silent while disabled.
        assert!(!m.heartbeat(&off, t0 + Duration::from_secs(3600)));
        assert!(!m.heartbeat(&off, t0 + Duration::from_secs(3600)));
        assert!(!m.heartbeat(&off, t0 + Duration::from_secs(3600)));
    }

    #[test]
    fn sensitivity_presets_roundtrip() {
        assert_eq!(threshold_for_sensitivity(0), -75);
        assert_eq!(threshold_for_sensitivity(1), -85);
        assert_eq!(threshold_for_sensitivity(2), -95);
        assert_eq!(threshold_for_sensitivity(99), -85);
        assert_eq!(sensitivity_for_threshold(-75), 0);
        assert_eq!(sensitivity_for_threshold(-85), 1);
        assert_eq!(sensitivity_for_threshold(-95), 2);
    }

    #[test]
    fn config_persists_and_heals() {
        let dir = std::env::temp_dir().join("pv-prox-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("proximity.json");
        let cfg = ProximityConfig {
            enabled: true,
            device_name: "Galaxy S24".into(),
            rssi_threshold: -75,
            grace_period_secs: 15,
        };
        cfg.save_to(&path).unwrap();
        assert_eq!(ProximityConfig::load_from(&path), cfg);
        // Corrupt file heals to safe defaults (feature OFF).
        std::fs::write(&path, b"{{{not json").unwrap();
        assert_eq!(ProximityConfig::load_from(&path), ProximityConfig::default());
        // Missing file likewise.
        let _ = std::fs::remove_file(&path);
        assert_eq!(ProximityConfig::load_from(&path.join("nope.json")), ProximityConfig::default());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
