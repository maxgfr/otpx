//! QR codes: decoding from images or camera frames, encoding to SVG and terminal text.

use qrcode::{EcLevel, QrCode};

use crate::{Error, Result};

/// Every QR code found in an image file (PNG, JPEG, GIF, WebP, BMP).
pub fn decode_image(bytes: &[u8]) -> Result<Vec<String>> {
    let img =
        image::load_from_memory(bytes).map_err(|e| Error::Qr(format!("unreadable image: {e}")))?;
    Ok(decode_luma(img.to_luma8()))
}

/// Every QR code in an RGBA frame (a browser `ImageData`).
pub fn decode_rgba(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<String>> {
    let img = image::RgbaImage::from_raw(width, height, rgba.to_vec())
        .ok_or_else(|| Error::Qr("frame size does not match its dimensions".into()))?;
    Ok(decode_luma(image::DynamicImage::ImageRgba8(img).to_luma8()))
}

fn decode_luma(img: image::GrayImage) -> Vec<String> {
    let mut found = scan(&img);
    // Screenshots of phones are often huge; a smaller copy is found more reliably.
    if found.is_empty() && img.width().max(img.height()) > 1200 {
        let small = image::imageops::resize(
            &img,
            img.width() / 2,
            img.height() / 2,
            image::imageops::FilterType::Triangle,
        );
        found = scan(&small);
    }
    // White codes on a dark background (dark mode screenshots).
    if found.is_empty() {
        let mut inv = img.clone();
        image::imageops::invert(&mut inv);
        found = scan(&inv);
    }
    found
}

fn scan(img: &image::GrayImage) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare(img.clone());
    let mut out = Vec::new();
    for grid in prepared.detect_grids() {
        if let Ok((_, content)) = grid.decode()
            && !out.contains(&content)
        {
            out.push(content);
        }
    }
    out
}

fn code(text: &str) -> Result<QrCode> {
    QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|e| Error::Qr(e.to_string()))
}

/// An SVG image of `text`, black on white with a quiet zone.
pub fn svg(text: &str) -> Result<String> {
    Ok(code(text)?
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(200, 200)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

/// The modules of `text`'s QR code, row by row (`true` = dark), without quiet zone.
pub fn modules(text: &str) -> Result<(usize, Vec<bool>)> {
    let c = code(text)?;
    let w = c.width();
    Ok((
        w,
        c.to_colors()
            .into_iter()
            .map(|m| m == qrcode::Color::Dark)
            .collect(),
    ))
}

/// `text`'s QR code drawn with Unicode half blocks, two rows per line, light on dark-aware:
/// dark modules are spaces on a light background so it scans on any terminal theme.
pub fn terminal(text: &str) -> Result<String> {
    let (w, m) = modules(text)?;
    let quiet = 2usize;
    let size = w + 2 * quiet;
    let dark = |x: usize, y: usize| -> bool {
        if x < quiet || y < quiet || x >= w + quiet || y >= w + quiet {
            return false;
        }
        m[(y - quiet) * w + (x - quiet)]
    };
    let mut out = String::new();
    let mut y = 0;
    while y < size {
        for x in 0..size {
            let top = dark(x, y);
            let bottom = y + 1 < size && dark(x, y + 1);
            // Light modules are drawn, dark ones are left as the terminal background.
            out.push(match (top, bottom) {
                (false, false) => '█',
                (false, true) => '▀',
                (true, false) => '▄',
                (true, true) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode() {
        let text = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let (w, m) = modules(text).unwrap();
        let scale = 6u32;
        let quiet = 4u32;
        let size = (w as u32 + 2 * quiet) * scale;
        let img = image::GrayImage::from_fn(size, size, |x, y| {
            let (mx, my) = (x / scale, y / scale);
            let dark = mx >= quiet
                && my >= quiet
                && mx < w as u32 + quiet
                && my < w as u32 + quiet
                && m[((my - quiet) as usize) * w + (mx - quiet) as usize];
            image::Luma([if dark { 0 } else { 255 }])
        });
        let mut png = Vec::new();
        image::DynamicImage::ImageLuma8(img.clone())
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert_eq!(decode_image(&png).unwrap(), vec![text.to_owned()]);
        // Inverted (dark mode) still decodes.
        let mut inv = img;
        image::imageops::invert(&mut inv);
        let rgba = image::DynamicImage::ImageLuma8(inv).to_rgba8();
        assert_eq!(
            decode_rgba(rgba.width(), rgba.height(), rgba.as_raw()).unwrap(),
            vec![text.to_owned()]
        );
        assert!(svg(text).unwrap().starts_with("<?xml"));
        assert!(terminal(text).unwrap().contains('█'));
    }
}
