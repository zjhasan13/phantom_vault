//! Printable emergency recovery sheet (rules Cat 7).
//!
//! Offline, dependency-free, single-page PDF 1.4 built from raw syntax:
//! base-14 Helvetica only (no font embedding), explicit xref table with
//! byte-exact offsets. The sheet carries the five Shamir shards in boxed
//! rows plus storage instructions — never the master password itself.
//! Every structural claim below is pinned by parser-grade unit tests.

use crate::error::{Result, VaultError};

const PAGE_W: f32 = 612.0; // US Letter
const PAGE_H: f32 = 792.0;
const MARGIN: f32 = 54.0;
const WRAP_COLS: usize = 78;

/// PDF string escape: backslash + parens. Non-WinAnsi bytes become `?`
/// (shards are ASCII by construction; this only guards the header path).
fn pdf_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            c if (c as u32) < 32 || (c as u32) > 126 => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

/// Hard-wrap a long shard line (shards carry no spaces to break on).
fn wrap_shard(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars
        .chunks(WRAP_COLS)
        .map(|c| c.iter().collect())
        .collect()
}

fn text_line(font: &str, size: u32, x: f32, y: f32, text: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(
        format!("BT /{font} {size} Tf {x:.1} {y:.1} Td ({}) Tj ET\n", pdf_escape(text)).as_bytes(),
    );
}

/// Build the complete PDF document bytes. Pure — unit tested.
pub fn build_recovery_sheet_pdf(shards: &[String], generated_note: &str) -> Result<Vec<u8>> {
    if shards.len() != 5 {
        return Err(VaultError::Storage(format!(
            "recovery sheet needs exactly 5 shards, got {}",
            shards.len()
        )));
    }
    if shards.iter().any(|s| s.trim().is_empty()) {
        return Err(VaultError::Storage("recovery sheet shard is empty".into()));
    }

    // ---- content stream ----
    let mut content: Vec<u8> = Vec::new();
    let mut y = PAGE_H - 52.0;
    text_line("F2", 18, MARGIN, y, "PHANTOM_VAULT - EMERGENCY DISASTER RECOVERY SHEET", &mut content);
    y -= 22.0;
    text_line("F1", 10, MARGIN, y, "Any 3 of the 5 shards below reconstruct your master secret.", &mut content);
    y -= 15.0;
    text_line(
        "F1",
        10,
        MARGIN,
        y,
        "Store in a secure, fireproof location. Never photograph or cloud-sync this page.",
        &mut content,
    );
    y -= 28.0;

    let box_w = PAGE_W - 2.0 * MARGIN;
    for (i, shard) in shards.iter().enumerate() {
        let lines = wrap_shard(shard);
        // Box height scales with wrapped lines (label + lines + padding).
        let box_h = 30.0 + lines.len() as f32 * 13.0;
        y -= box_h;
        content.extend_from_slice(
            format!("0.85 0.87 1.0 rg {MARGIN:.1} {y:.1} {box_w:.1} {box_h:.1} re f\n").as_bytes(),
        );
        content.extend_from_slice(
            format!("0.35 0.30 0.75 RG 1.2 w {MARGIN:.1} {y:.1} {box_w:.1} {box_h:.1} re S\n").as_bytes(),
        );
        text_line(
            "F2",
            11,
            MARGIN + 10.0,
            y + box_h - 18.0,
            &format!("SHARD {} OF 5", i + 1),
            &mut content,
        );
        for (j, line) in lines.iter().enumerate() {
            text_line("F1", 10, MARGIN + 10.0, y + box_h - 34.0 - j as f32 * 13.0, line, &mut content);
        }
        y -= 10.0;
    }
    text_line("F1", 9, MARGIN, 96.0, generated_note, &mut content);
    text_line(
        "F1",
        9,
        MARGIN,
        82.0,
        "Verify: lock the vault, recover via any 3 shards, unlock.",
        &mut content,
    );

    // ---- objects ----
    let mut pdf: Vec<u8> = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offsets: Vec<usize> = vec![0]; // object 0 = free entry
    let mut emit = |body: &[u8]| {
        offsets.push(pdf.len());
        pdf.extend_from_slice(body);
    };
    emit(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    emit(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    emit(
        format!(
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:.0} {PAGE_H:.0}] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>\nendobj\n"
        )
        .as_bytes(),
    );
    emit(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");
    emit(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n");
    let head = format!("6 0 obj\n<< /Length {} >>\nstream\n", content.len());
    let mut stream_obj = head.into_bytes();
    stream_obj.extend_from_slice(&content);
    stream_obj.extend_from_slice(b"\nendstream\nendobj\n");
    emit(&stream_obj);

    // ---- xref ----
    let xref_pos = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", offsets.len()).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1) {
        pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n", offsets.len())
            .as_bytes(),
    );
    Ok(pdf)
}

/// Write the sheet to disk. Plaintext by design (it IS the backup) — the
/// caller (UI) warns before writing and logs the export.
pub fn export_recovery_sheet_pdf(output_path: &std::path::Path, shards: &[String]) -> Result<()> {
    let note = "PhantomVault offline backup — no network was used to create this page.";
    let pdf = build_recovery_sheet_pdf(shards, note)?;
    std::fs::write(output_path, pdf)
        .map_err(|e| VaultError::Storage(format!("sheet write failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_shards() -> Vec<String> {
        (1..=5)
            .map(|i| format!("PHANTOM-{i}-x7f2a91 (demo) correct horse battery staple extra words number {i}"))
            .collect()
    }

    #[test]
    fn rejects_bad_input() {
        assert!(build_recovery_sheet_pdf(&demo_shards()[..4], "").is_err());
        assert!(build_recovery_sheet_pdf(&demo_shards()[..5], "").is_ok());
        let mut bad = demo_shards();
        bad[2] = "   ".into();
        assert!(build_recovery_sheet_pdf(&bad, "").is_err());
    }

    #[test]
    fn header_trailer_and_all_shards_present() {
        let pdf = build_recovery_sheet_pdf(&demo_shards(), "note").unwrap();
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        for s in demo_shards() {
            let esc = pdf_escape(&s);
            assert!(
                pdf.windows(esc.len()).any(|w| w == esc.as_bytes()),
                "shard missing: {s}"
            );
        }
        assert!(pdf.windows(7).any(|w| w == b"SHARD 3"));
    }

    #[test]
    fn xref_offsets_point_at_objects() {
        let pdf = build_recovery_sheet_pdf(&demo_shards(), "").unwrap();
        let text = String::from_utf8_lossy(&pdf);
        // startxref value must equal the true byte position of "xref".
        let sx: usize = text
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let xref_at = pdf.windows(4).position(|w| w == b"xref").unwrap();
        assert_eq!(sx, xref_at, "startxref must match xref position");
        // Every table entry must land on "N 0 obj" (skip header, count,
        // AND the free entry 0 — only 1..=6 are real objects).
        // Byte-exact: the lossy UTF-8 view shifts indices (binary header
        // comment), so offsets are validated against the raw bytes.
        for (n, line) in text
            .lines()
            .skip_while(|l| !l.starts_with("xref"))
            .skip(3)
            .enumerate()
        {
            if line.starts_with("trailer") {
                break;
            }
            let off: usize = line[..10].parse().unwrap();
            let want = format!("{} 0 obj", n + 1);
            assert!(
                pdf[off..].starts_with(want.as_bytes()),
                "entry {n} must point at {want:?}"
            );
        }
    }

    #[test]
    fn escaping_neutralizes_pdf_breakouts() {
        let mut shards = demo_shards();
        shards[0] = "a)b(c\\d".into();
        let pdf = build_recovery_sheet_pdf(&shards, "").unwrap();
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("a\\)b\\(c\\\\d"), "parens/backslash must be escaped");
    }
}
