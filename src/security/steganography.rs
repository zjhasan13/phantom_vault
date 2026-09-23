//! Phase 21 — PNG vault locker (LSB steganography).
//!
//! Hides the encrypted vault blob inside RGB pixel LSBs of a carrier PNG.
//! Alpha is never touched; output is a perfectly ordinary PNG.
//! Layout (bit stream, MSB-first): [PSTE magic 4B][len u32 BE][payload].
//! Core operates on image buffers (fully unit-tested); thin wrappers do files.

use crate::error::{Result, VaultError};
use image::RgbaImage;
use std::path::Path;

pub const STEGO_MAGIC: &[u8; 4] = b"PSTE";
pub const MAX_PAYLOAD: usize = 48 * 1024 * 1024;

/// Bits available in RGB channels (alpha untouched).
fn capacity_bits(img: &RgbaImage) -> usize {
    img.width() as usize * img.height() as usize * 3
}

fn packed_bits(payload_len: usize) -> usize {
    (4 + 4 + payload_len) * 8
}

/// Embed into a live image buffer. Pure pixel math — no I/O.
pub fn embed_in_image(img: &mut RgbaImage, payload: &[u8]) -> Result<()> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(VaultError::Security("payload size out of range".into()));
    }
    if capacity_bits(img) < packed_bits(payload.len()) {
        return Err(VaultError::Security(
            "Carrier image too small to hold vault. Choose a larger image.".into(),
        ));
    }
    let mut stream = Vec::with_capacity(4 + 4 + payload.len());
    stream.extend_from_slice(STEGO_MAGIC);
    stream.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    stream.extend_from_slice(payload);

    let mut bit_iter = stream.iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1));
    for px in img.pixels_mut() {
        for channel in px.0.iter_mut().take(3) {
            let Some(bit) = bit_iter.next() else {
                return Ok(());
            };
            *channel = (*channel & 0xFE) | bit;
        }
    }
    Ok(())
}

/// Extract from an image buffer. Validates magic + sane length.
pub fn extract_from_image(img: &RgbaImage) -> Result<Vec<u8>> {
    let mut bits = img.pixels().flat_map(|px| px.0.iter().take(3).map(|c| c & 1));
    let mut take_byte = || -> Option<u8> {
        let mut b = 0u8;
        for _ in 0..8 {
            b = (b << 1) | bits.next()?;
        }
        Some(b)
    };
    let magic: Vec<u8> = (0..4).map(|_| take_byte()).collect::<Option<Vec<_>>>().ok_or_else(
        || VaultError::Security("No hidden PhantomVault container found in this image.".into()),
    )?;
    if magic.as_slice() != STEGO_MAGIC {
        return Err(VaultError::Security(
            "No hidden PhantomVault container found in this image.".into(),
        ));
    }
    let len_bytes: Vec<u8> = (0..4)
        .map(|_| take_byte())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| VaultError::Security("Truncated stego header.".into()))?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if len == 0 || len > MAX_PAYLOAD {
        return Err(VaultError::Security("Corrupt stego length.".into()));
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(
            take_byte().ok_or_else(|| VaultError::Security("Truncated stego payload.".into()))?,
        );
    }
    Ok(out)
}

/// File wrapper: carrier PNG + vault bytes → stego PNG.
pub fn embed_in_png(carrier_path: &Path, payload: &[u8], output_path: &Path) -> Result<()> {
    let mut img = image::open(carrier_path)
        .map_err(|e| VaultError::Security(format!("cannot open carrier: {e}")))?
        .to_rgba8();
    embed_in_image(&mut img, payload)?;
    img.save(output_path)
        .map_err(|e| VaultError::Security(format!("cannot save stego image: {e}")))?;
    Ok(())
}

/// File wrapper: stego PNG → raw vault bytes.
pub fn extract_from_png(image_path: &Path) -> Result<Vec<u8>> {
    let img = image::open(image_path)
        .map_err(|e| VaultError::Security(format!("cannot open image: {e}")))?
        .to_rgba8();
    extract_from_image(&img)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgba;

    fn carrier(w: u32, h: u32) -> RgbaImage {
        let mut img = RgbaImage::new(w, h);
        // Deterministic pseudo-texture (no RNG needed in tests).
        for (x, y, px) in img.enumerate_pixels_mut() {
            let v = ((x * 31 + y * 17) % 256) as u8;
            *px = Rgba([v, 255 - v, (v >> 1) | 0x80, 255]);
        }
        img
    }

    #[test]
    fn roundtrip_byte_exact() {
        let mut img = carrier(128, 128);
        let payload: Vec<u8> = (0..5000).map(|i| (i * 37 % 251) as u8).collect();
        embed_in_image(&mut img, &payload).unwrap();
        let back = extract_from_image(&img).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn alpha_untouched_and_near_lossless() {
        let mut img = carrier(64, 64);
        let before: Vec<u8> = img.pixels().map(|p| p.0[3]).collect();
        embed_in_image(&mut img, b"hello-phantom").unwrap();
        let after: Vec<u8> = img.pixels().map(|p| p.0[3]).collect();
        assert_eq!(before, after);
        // At most LSB flips in RGB: total channel drift is tiny.
        let drift: u64 = img
            .pixels()
            .zip(carrier(64, 64).pixels())
            .map(|(a, b)| {
                (a.0[0].abs_diff(b.0[0]) + a.0[1].abs_diff(b.0[1]) + a.0[2].abs_diff(b.0[2])) as u64
            })
            .sum();
        assert!(drift <= (4 + 4 + 13) as u64 * 8);
    }

    #[test]
    fn rejects_plain_image() {
        let img = carrier(100, 100);
        assert!(extract_from_image(&img).is_err());
    }

    #[test]
    fn rejects_undersized_carrier() {
        let mut img = carrier(4, 4); // 48 bits < 64-bit header
        assert!(embed_in_image(&mut img, b"way-too-much-data-for-this-tiny-image").is_err());
    }

    #[test]
    fn rejects_empty_payload() {
        let mut img = carrier(100, 100);
        assert!(embed_in_image(&mut img, b"").is_err());
    }

    #[test]
    fn file_wrappers_roundtrip() {
        let dir = std::env::temp_dir().join("pv_stego_test");
        let _ = std::fs::create_dir_all(&dir);
        let carrier_path = dir.join("carrier.png");
        let out_path = dir.join("hidden.png");
        carrier(128, 128).save(&carrier_path).unwrap();
        let payload = b"vault-bytes-12345".to_vec();
        embed_in_png(&carrier_path, &payload, &out_path).unwrap();
        assert_eq!(extract_from_png(&out_path).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
