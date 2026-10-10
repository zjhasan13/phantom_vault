//! Live webcam QR capture (Batch-4).
//!
//! Camera 0 → luma frames → the same `rqrr` pipeline as clipboard screenshots.
//! Runs on the caller's worker thread (never the Slint loop): ~10 fps polls,
//! 60 s timeout, cooperative cancel via [`cancel_webcam_scan`] (the scan modal
//! Cancel button). Camera errors fail LOUD with the OS message — a missing
//! camera is a setup problem, not a silent no-op.

use crate::error::{Result, VaultError};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "camera")]
use std::time::{Duration, Instant};

/// Scan budget per session; the modal Cancel path sets the flag below.
/// Camera-gated: slim builds neither link nor keep this timer code.
#[cfg(feature = "camera")]
const SCAN_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(feature = "camera")]
const FRAME_PERIOD: Duration = Duration::from_millis(100);

static CANCEL: AtomicBool = AtomicBool::new(false);
/// Generation counter: a fresh spawn must never resurrect a cancelled
/// predecessor (the new spawn clears CANCEL while the old thread may still
/// be inside one last frame poll — the stale generation exits regardless).
static SCAN_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Cooperative stop for an in-flight [`capture_and_scan_frame`] (modal Cancel,
/// camera switch, lock). Bumps the generation so late polls die too.
pub fn cancel_webcam_scan() {
    CANCEL.store(true, Ordering::SeqCst);
    SCAN_GEN.fetch_add(1, Ordering::SeqCst);
}

/// Enumerate usable cameras as (driver index, display name). Empty = none
/// visible (privacy off / no device / busy) — the caller shows guidance,
/// never a black scan modal. Camera-gated like the rest of this module.
#[cfg(feature = "camera")]
pub fn list_cameras() -> Vec<(u32, String)> {
    use nokhwa::utils::{ApiBackend, CameraIndex};
    let infos = nokhwa::query(ApiBackend::Auto).unwrap_or_default();
    infos
        .into_iter()
        .filter_map(|info| {
            let idx = match info.index() {
                CameraIndex::Index(n) => *n,
                _ => return None,
            };
            let mut name = info.human_name();
            if name.trim().is_empty() {
                name = format!("Camera {idx}");
            }
            Some((idx, format!("{name} (#{idx})")))
        })
        .collect()
}

/// Slim builds have no camera stack: empty list, guidance path only.
#[cfg(not(feature = "camera"))]
pub fn list_cameras() -> Vec<(u32, String)> {
    Vec::new()
}

/// Pure helper: QR-detect over a raw luma8 buffer. No camera, fully tested.
/// Kept for the camera path and the test suite; slim non-test builds drop it.
#[cfg(any(feature = "camera", test))]
pub fn scan_luma_buffer(width: u32, height: u32, pixels: &[u8]) -> Option<String> {
    if width == 0 || height == 0 {
        return None;
    }
    if pixels.len() != width as usize * height as usize {
        return None;
    }
    let gray = image::GrayImage::from_raw(width, height, pixels.to_vec())?;
    crate::authenticator::qr_scanner::decode_qr_from_image(image::DynamicImage::ImageLuma8(
        gray,
    ))
    .ok()
}

/// Grab live frames until a QR decodes, then stop the camera and hand the
/// payload to `on_qr_found` (which feeds the migration/otpauth pipeline).
/// `on_frame` receives every decoded frame as RGBA bytes (w, h) for live
/// preview rendering; it runs on this worker thread (hop to the UI loop).
/// Blocking — call from a worker thread.
///
/// Lightweight-release: the live-camera half lives behind the `camera`
/// Cargo feature (default ON — normal builds are byte-identical). Slim
/// builds (`--no-default-features`) get the stub below: same signature,
/// loud error, no nokhwa linkage.
#[cfg(feature = "camera")]
pub fn capture_and_scan_frame(
    camera_index: u32,
    on_frame: impl Fn(Vec<u8>, u32, u32) + Send + Sync + 'static,
    on_qr_found: impl FnOnce(String) + Send + 'static,
) -> Result<()> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
    use nokhwa::Camera;

    CANCEL.store(false, Ordering::SeqCst);
    let gen = SCAN_GEN.fetch_add(1, Ordering::SeqCst);
    let mut cam = Camera::new(
        CameraIndex::Index(camera_index),
        RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate),
    )
    .map_err(|e| VaultError::Security(format!("camera open: {e}")))?;
    // Format fallback: picky webcams reject exotic negotiations outright —
    // retry with the driver default before failing loud.
    if cam.open_stream().is_err() {
        cam = Camera::new(
            CameraIndex::Index(camera_index),
            RequestedFormat::new::<RgbFormat>(RequestedFormatType::None),
        )
        .map_err(|e| VaultError::Security(format!("camera open: {e}")))?;
        cam.open_stream()
            .map_err(|e| VaultError::Security(format!("camera stream: {e}")))?;
    }
    let deadline = Instant::now() + SCAN_TIMEOUT;
    // Consecutive dead frames mean a stuck/denied device, not bad luck:
    // fail LOUD after ~5s instead of staring at a black modal for 60s.
    // (Windows privacy "Let desktop apps access your camera" OFF and
    // device-busy both present exactly like this.)
    let mut dead_frames = 0u32;
    loop {
        // Stale generation (a newer spawn cleared CANCEL beneath us) exits
        // exactly like an explicit cancel — no resurrection, no double-serve.
        if CANCEL.load(Ordering::SeqCst) || gen != SCAN_GEN.load(Ordering::SeqCst) {
            let _ = cam.stop_stream();
            return Err(VaultError::Security("webcam scan cancelled".into()));
        }
        if Instant::now() > deadline {
            let _ = cam.stop_stream();
            return Err(VaultError::Security("webcam scan timed out (60s)".into()));
        }
        match cam.frame() {
            Ok(frame) => {
                dead_frames = 0;
                // Decode to RGB, fold to luma, run the shared choke-point
                // (the same helper the unit tests pin — one detection path).
                let hit = frame.decode_image::<RgbFormat>().ok().map(|rgb| {
                    // Live preview first (best-effort render; a decode miss
                    // below still counts as a live frame, not a dead one).
                    let (w, h) = (rgb.width(), rgb.height());
                    let mut rgba = Vec::with_capacity((w * h * 4) as usize);
                    for px in rgb.pixels() {
                        rgba.extend_from_slice(&[px.0[0], px.0[1], px.0[2], 255]);
                    }
                    on_frame(rgba, w, h);
                    let luma = image::DynamicImage::ImageRgb8(rgb).to_luma8();
                    scan_luma_buffer(luma.width(), luma.height(), luma.as_raw())
                });
                if let Some(Some(payload)) = hit {
                    let _ = cam.stop_stream();
                    on_qr_found(payload);
                    return Ok(());
                }
            }
            Err(_) => {
                // Dropped frame — keep polling until the budget runs out,
                // but a permanently dead stream aborts early (see above).
                dead_frames += 1;
                if dead_frames >= 50 {
                    let _ = cam.stop_stream();
                    return Err(VaultError::Security(
                        "camera delivers no frames — allow desktop-app camera access in Windows Privacy settings, or close apps using the camera".into(),
                    ));
                }
            }
        }
        std::thread::sleep(FRAME_PERIOD);
    }
}

/// Slim-build stub: same signature as the `camera`-feature function above,
/// so call sites compile unchanged. Loud error, never silent.
#[cfg(not(feature = "camera"))]
pub fn capture_and_scan_frame(
    _camera_index: u32,
    _on_frame: impl Fn(Vec<u8>, u32, u32) + Send + Sync + 'static,
    _on_qr_found: impl FnOnce(String) + Send + 'static,
) -> Result<()> {
    Err(VaultError::Security(
        "webcam unavailable in this build (compiled without the `camera` feature)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_and_malformed_buffers_find_nothing() {
        // All-black 64×64: no grids, fast reject.
        assert!(scan_luma_buffer(64, 64, &vec![0u8; 64 * 64]).is_none());
        // All-white likewise.
        assert!(scan_luma_buffer(64, 64, &vec![255u8; 64 * 64]).is_none());
        // Size mismatch and zero dims are structural rejects, never panics.
        assert!(scan_luma_buffer(64, 64, &[0u8; 10]).is_none());
        assert!(scan_luma_buffer(0, 0, &[]).is_none());
        assert!(scan_luma_buffer(0, 64, &[]).is_none());
    }

    #[test]
    fn cancel_flag_roundtrips() {
        CANCEL.store(false, Ordering::SeqCst);
        cancel_webcam_scan();
        assert!(CANCEL.load(Ordering::SeqCst));
        CANCEL.store(false, Ordering::SeqCst);
    }

    #[test]
    #[cfg(feature = "camera")]
    fn list_cameras_never_panics() {
        // Hardware-dependent output (empty on CI, populated on dev PCs) —
        // assert only well-formedness: no panic, sane display names.
        let cams = list_cameras();
        assert!(cams.len() < 64);
        for (idx, name) in &cams {
            assert!(!name.trim().is_empty());
            assert!(name.contains(&idx.to_string()));
        }
    }
}
