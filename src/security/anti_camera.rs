//! Phase 26 — Anti-photography lens guard & ephemeral peep-hole.
//!
//! Software capture (DWM affinity) can't stop a phone pointed at the monitor.
//! Two optical/behavioral layers, BOTH DEFAULT OFF (zero impact unless armed):
//! - Peep-hole: secrets render ONLY while the pointer is physically held down.
//! - Moiré veil: micro-stripe overlay that shimmers for CMOS sensors.
//!
//! Config persists in `anticamera.json`; corrupt/missing file ⇒ safe OFF.

use serde::{Deserialize, Serialize};

const CONFIG_FILE: &str = "anticamera.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AntiCameraConfig {
    #[serde(default)]
    pub moire_enabled: bool,
    #[serde(default)]
    pub peep_hole_enabled: bool,
}

impl AntiCameraConfig {
    /// Canonical all-off state (also `Default`). Kept as a named constructor
    /// for call sites that want the intent explicit; tests pin it.
    #[allow(dead_code)]
    pub fn off() -> Self {
        Self { moire_enabled: false, peep_hole_enabled: false }
    }

    #[allow(dead_code)]
    pub fn any_armed(&self) -> bool {
        self.moire_enabled || self.peep_hole_enabled
    }
}

/// Load config; missing/corrupt file degrades to all-OFF (fail-closed).
pub fn load_config() -> AntiCameraConfig {
    std::fs::read_to_string(CONFIG_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Best-effort persist (never blocks the UI thread caller).
pub fn save_config(cfg: &AntiCameraConfig) {
    if let Ok(json) = serde_json::to_string(cfg) {
        let _ = std::fs::write(CONFIG_FILE, json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_off() {
        let cfg = AntiCameraConfig::default();
        assert!(!cfg.moire_enabled);
        assert!(!cfg.peep_hole_enabled);
        assert!(!cfg.any_armed());
        assert_eq!(cfg, AntiCameraConfig::off());
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = AntiCameraConfig { moire_enabled: true, peep_hole_enabled: false };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: AntiCameraConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn corrupt_config_fails_closed() {
        let parsed: Option<AntiCameraConfig> =
            serde_json::from_str("{not valid json").ok();
        assert_eq!(parsed.unwrap_or_default(), AntiCameraConfig::off());
    }

    #[test]
    fn partial_json_defaults_rest_off() {
        let cfg: AntiCameraConfig = serde_json::from_str(r#"{"peep_hole_enabled":true}"#).unwrap();
        assert!(cfg.peep_hole_enabled);
        assert!(!cfg.moire_enabled);
    }
}
