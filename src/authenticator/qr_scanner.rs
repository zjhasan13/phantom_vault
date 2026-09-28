//! Indestructible QR ingestion: 4-pass adaptive pipeline.
//!
//! Pass 1 — rxing pure (bit-exact digital screenshots, TRY_HARDER +
//! PURE_BARCODE). Pass 2 — rxing HybridBinarizer without PURE (rotated /
//! optical captures). Pass 3 — rxing over the auto-cropped bright card
//! (dark-mode screenshot borders stripped). Pass 4 — rqrr legacy fallback.

use crate::error::{Result, VaultError};
use image::DynamicImage;
use std::collections::{HashMap, HashSet};

/// Bright-card threshold: luma above this belongs to the QR card, darker
/// pixels are screenshot chrome / dark-mode surroundings.
const BRIGHT_LUMA: u8 = 160;
/// Quiet-zone margin kept around the detected bright box.
const CROP_MARGIN: u32 = 4;

/// Bounding box of the bright card (luma > threshold). Returns None when no
/// distinct bright rectangle exists (caller skips the crop pass).
fn bright_bbox(gray: &image::GrayImage) -> Option<(u32, u32, u32, u32)> {
    let (w, h) = (gray.width(), gray.height());
    if w == 0 || h == 0 {
        return None;
    }
    let (mut x0, mut y0) = (w, h);
    let (mut x1, mut y1) = (0u32, 0u32);
    for (x, y, px) in gray.enumerate_pixels() {
        if px.0[0] > BRIGHT_LUMA {
            x0 = x0.min(x);
            y0 = y0.min(y);
            x1 = x1.max(x);
            y1 = y1.max(y);
        }
    }
    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    // Distinct rectangle only: must not span ~the whole frame (else there
    // is no dark border to strip) and must cover a sane area.
    let bw = x1 - x0;
    let bh = y1 - y0;
    if bw >= w * 95 / 100 && bh >= h * 95 / 100 {
        return None;
    }
    if bw < 64 || bh < 64 {
        return None;
    }
    let x0 = x0.saturating_sub(CROP_MARGIN);
    let y0 = y0.saturating_sub(CROP_MARGIN);
    let x1 = (x1 + CROP_MARGIN).min(w - 1);
    let y1 = (y1 + CROP_MARGIN).min(h - 1);
    Some((x0, y0, x1 - x0 + 1, y1 - y0 + 1))
}

fn crop_gray(gray: &image::GrayImage, bbox: (u32, u32, u32, u32)) -> image::GrayImage {
    use image::GenericImageView;
    gray.view(bbox.0, bbox.1, bbox.2, bbox.3).to_image()
}

fn rxing_hints(pure: bool) -> rxing::DecodingHintDictionary {
    let mut hints: rxing::DecodingHintDictionary = HashMap::new();
    hints.insert(
        rxing::DecodeHintType::POSSIBLE_FORMATS,
        rxing::DecodeHintValue::PossibleFormats(HashSet::from([rxing::BarcodeFormat::QR_CODE])),
    );
    hints.insert(
        rxing::DecodeHintType::TRY_HARDER,
        rxing::DecodeHintValue::TryHarder(true),
    );
    if pure {
        hints.insert(
            rxing::DecodeHintType::PURE_BARCODE,
            rxing::DecodeHintValue::PureBarcode(true),
        );
    }
    hints
}

/// One rxing attempt over raw luma bytes (caller picks pure or hybrid).
fn rxing_try(luma: Vec<u8>, w: u32, h: u32, pure: bool) -> Option<String> {
    use rxing::Reader;
    let mut reader = rxing::MultiFormatReader::default();
    let mut hints = rxing_hints(pure);
    let mut bitmap = rxing::BinaryBitmap::new(rxing::common::HybridBinarizer::new(
        rxing::Luma8LuminanceSource::new(luma, w, h),
    ));
    reader
        .decode_with_hints(&mut bitmap, &mut hints)
        .ok()
        .map(|r| r.getText().to_owned())
        .filter(|s| !s.is_empty())
}

/// rqrr legacy fallback over every detected grid (multi-QR sheets supported
/// by the batch importer; here the first success wins).
fn rqrr_try(gray: &image::GrayImage) -> Option<String> {
    let mut prepared = rqrr::PreparedImage::prepare(gray.clone());
    for grid in prepared.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            if !content.is_empty() {
                return Some(content);
            }
        }
    }
    None
}

/// Decode QR content from an image buffer (4-pass adaptive pipeline).
pub fn decode_qr_from_image(img: DynamicImage) -> Result<String> {
    let gray = img.to_luma8();
    let (w, h) = (gray.width(), gray.height());
    if w == 0 || h == 0 {
        return Err(VaultError::Sync("Empty image".into()));
    }
    if w > 8192 || h > 8192 {
        return Err(VaultError::Sync("Image too large (8192px cap)".into()));
    }
    let flat: Vec<u8> = gray.as_raw().to_vec();
    // Pass 1: pure bit-exact (digital screenshots).
    if let Some(s) = rxing_try(flat.clone(), w, h, true) {
        return Ok(s);
    }
    // Pass 2: hybrid, no PURE (rotated / optical captures).
    if let Some(s) = rxing_try(flat.clone(), w, h, false) {
        return Ok(s);
    }
    // Pass 3: auto-cropped bright card (dark-mode borders stripped).
    if let Some(bbox) = bright_bbox(&gray) {
        let cropped = crop_gray(&gray, bbox);
        let (cw, ch) = (cropped.width(), cropped.height());
        if let Some(s) = rxing_try(cropped.into_raw(), cw, ch, false) {
            return Ok(s);
        }
    }
    // Pass 4: rqrr legacy fallback.
    rqrr_try(&gray).ok_or_else(|| VaultError::Sync("No QR code found in image".into()))
}

/// Read clipboard image (Win+Shift+S screenshot) and decode QR.
pub fn decode_qr_from_clipboard() -> Result<String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| VaultError::Sync(format!("Clipboard error: {e}")))?;
    let img_data = clipboard
        .get_image()
        .map_err(|e| VaultError::Sync(format!("No image in clipboard (use Win+Shift+S): {e}")))?;

    let width = img_data.width as u32;
    let height = img_data.height as u32;
    let bytes = img_data.bytes.into_owned();

    // arboard returns RGBA (4 bytes per pixel) — convert to image buffer
    if bytes.len() != (width * height * 4) as usize {
        return Err(VaultError::Sync(format!(
            "Clipboard image size mismatch: {}x{} bytes {}",
            width,
            height,
            bytes.len()
        )));
    }

    let rgba = image::RgbaImage::from_raw(width, height, bytes)
        .ok_or_else(|| VaultError::Sync("Failed to create RgbaImage from clipboard".into()))?;
    let dyn_img = DynamicImage::ImageRgba8(rgba);
    decode_qr_from_image(dyn_img)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid_luma(w: u32, h: u32, v: u8) -> image::GrayImage {
        image::GrayImage::from_pixel(w, h, image::Luma([v]))
    }

    #[test]
    fn bright_bbox_finds_card_and_skips_full_frame() {
        // Dark frame with a bright card block in the middle.
        let mut img = solid_luma(200, 200, 10);
        for x in 50..150 {
            for y in 40..160 {
                img.put_pixel(x, y, image::Luma([220u8]));
            }
        }
        let bbox = bright_bbox(&img).unwrap();
        // 100x120 card + 4px margin each side → 108x128 at ~(46,36).
        assert_eq!(bbox, (46, 36, 108, 128));
        // All-bright frame: no distinct rectangle → no crop.
        assert!(bright_bbox(&solid_luma(100, 100, 255)).is_none());
        // All-dark frame: nothing bright.
        assert!(bright_bbox(&solid_luma(100, 100, 10)).is_none());
    }

    #[test]
    fn pipeline_rejects_empty_and_blank() {
        let blank = DynamicImage::ImageLuma8(solid_luma(64, 64, 200));
        assert!(decode_qr_from_image(blank).is_err());
    }

    #[test]
    fn qr_roundtrip_through_all_passes() {
        // Encode a real migration URI with our own QR writer, then prove
        // the pipeline reads it back (exercises rxing end to end).
        let uri = "otpauth-migration://offline?data=QVJDSElURUNUVVJF";
        let code = qrcode::QrCode::new(uri.as_bytes()).unwrap();
        let w = code.width() as u32;
        let scale = 8u32;
        let size = w * scale;
        let mut img = image::GrayImage::from_pixel(size, size, image::Luma([255u8]));
        for y in 0..w {
            for x in 0..w {
                if code[(x as usize, y as usize)] == qrcode::Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            img.put_pixel(x * scale + dx, y * scale + dy, image::Luma([0u8]));
                        }
                    }
                }
            }
        }
        // Pass 1 gets a clean digital QR…
        assert_eq!(
            decode_qr_from_image(DynamicImage::ImageLuma8(img.clone())).unwrap(),
            uri
        );
        // …and the dark-bordered variant still decodes (crop pass).
        let mut bordered = image::GrayImage::from_pixel(size + 80, size + 80, image::Luma([5u8]));
        image::imageops::replace(&mut bordered, &img, 40, 40);
        assert!(bright_bbox(&bordered).is_some());
        assert_eq!(
            decode_qr_from_image(DynamicImage::ImageLuma8(bordered)).unwrap(),
            uri
        );
    }
}
