use image::DynamicImage;

/// Decode QR content from an image buffer using rqrr (pure Rust, no native deps)
pub fn decode_qr_from_image(img: DynamicImage) -> Result<String, String> {
    // Convert to grayscale luminance
    let gray = img.to_luma8();
    let width = gray.width() as usize;
    let height = gray.height() as usize;
    if width == 0 || height == 0 {
        return Err("Empty image".to_string());
    }

    let mut prepared = rqrr::PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err("No QR code found in image".to_string());
    }

    // Try each detected grid until one decodes
    for grid in grids {
        match grid.decode() {
            Ok((_meta, content)) => return Ok(content),
            Err(e) => {
                // Try next grid
                let _ = e;
                continue;
            }
        }
    }
    Err("QR decode failed for all detected grids".to_string())
}

/// Read clipboard image (Win+Shift+S screenshot) and decode QR via rqrr
/// Uses arboard::Clipboard::get_image() — returns RGBA bytes
pub fn decode_qr_from_clipboard() -> Result<String, String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| format!("Clipboard error: {}", e))?;
    let img_data = clipboard
        .get_image()
        .map_err(|e| format!("No image in clipboard (use Win+Shift+S): {}", e))?;

    let width = img_data.width as u32;
    let height = img_data.height as u32;
    let bytes = img_data.bytes.into_owned();

    // arboard returns RGBA (4 bytes per pixel) — convert to image buffer
    if bytes.len() != (width * height * 4) as usize {
        return Err(format!(
            "Clipboard image size mismatch: {}x{} bytes {}",
            width,
            height,
            bytes.len()
        ));
    }

    let rgba = image::RgbaImage::from_raw(width, height, bytes)
        .ok_or("Failed to create RgbaImage from clipboard")?;
    let dyn_img = DynamicImage::ImageRgba8(rgba);
    decode_qr_from_image(dyn_img)
}
