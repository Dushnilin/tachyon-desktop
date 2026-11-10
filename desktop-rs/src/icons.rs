use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use gpui::{AssetSource, Image, ImageFormat, Result as GpuiResult, SharedString};

include!(concat!(env!("OUT_DIR"), "/flags_assets.rs"));

pub struct TachyonAssetSource;

impl AssetSource for TachyonAssetSource {
    fn load(&self, path: &str) -> GpuiResult<Option<Cow<'static, [u8]>>> {
        let svg: &'static str = match path {
            "icons/bolt.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 4 14h7l-1 8 10-12h-7l1-8z"/></svg>"#
            }
            "icons/power.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/></svg>"#
            }
            "icons/route.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="4" r="2"/><circle cx="18" cy="4" r="2"/><circle cx="12" cy="20" r="2"/><path d="M6 6v3a4 4 0 0 0 4 4h4a4 4 0 0 0 4-4V6"/><path d="M12 13v5"/></svg>"#
            }
            "icons/server.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><circle cx="7" cy="7" r="1"/><circle cx="7" cy="17" r="1"/></svg>"#
            }
            "icons/activity.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-7 4 14 3-7h4"/></svg>"#
            }
            "icons/sliders.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/><circle cx="9" cy="6" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="10" cy="18" r="2"/></svg>"#
            }
            "icons/globe.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18"/><path d="M12 3a14 14 0 0 0 0 18"/></svg>"#
            }
            "icons/lock.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>"#
            }
            "icons/refresh.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><polyline points="21 3 21 9 15 9"/></svg>"#
            }
            "icons/search.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>"#
            }
            "icons/plus.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>"#
            }
            "icons/trash.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>"#
            }
            "icons/copy.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>"#
            }
            "icons/folder.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>"#
            }
            "icons/check.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>"#
            }
            "icons/close.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>"#
            }
            "icons/min.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>"#
            }
            "icons/max.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><rect x="5" y="5" width="14" height="14" rx="1.5"/></svg>"#
            }
            "icons/sun.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>"#
            }
            "icons/moon.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/></svg>"#
            }
            "icons/chevron_down.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>"#
            }
            "icons/chevron_right.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>"#
            }
            "icons/shield.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>"#
            }
            "icons/qr.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 14h3v3h-3zM18 18h3v3h-3zM14 19h2v2M19 14h2v2"/></svg>"#
            }
            "icons/heart.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19.5 12.57 12 20l-7.5-7.43A5 5 0 1 1 12 6a5 5 0 1 1 7.5 6.57Z"/></svg>"#
            }
            "icons/filter.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M7 12h10M10 18h4"/></svg>"#
            }
            "icons/edit.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>"#
            }
            "icons/ext.svg" => {
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17 17 7"/><path d="M9 7h8v8"/></svg>"#
            }
            _ => return gpui_kit::assets::Assets.load(path),
        };
        Ok(Some(Cow::Borrowed(svg.as_bytes())))
    }

    fn list(&self, path: &str) -> GpuiResult<Vec<SharedString>> {
        gpui_kit::assets::Assets.list(path)
    }
}

static FLAG_IMAGE_CACHE: OnceLock<Mutex<HashMap<String, Option<Arc<Image>>>>> = OnceLock::new();

pub fn flag_image(cc: &str) -> Option<Arc<Image>> {
    let clean = cc.trim().to_ascii_lowercase();
    if clean.is_empty() || clean == "auto" || clean == "xx" {
        return None;
    }
    let cache = FLAG_IMAGE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(found) = guard.get(&clean) {
            return found.clone();
        }
    }
    let img = render_flag_png(&clean)
        .map(|png_bytes| Arc::new(Image::from_bytes(ImageFormat::Png, png_bytes)))
        .or_else(|| {
            get_embedded_flag_svg(&clean)
                .map(|bytes| Arc::new(Image::from_bytes(ImageFormat::Svg, bytes.to_vec())))
        });
    if let Ok(mut guard) = cache.lock() {
        guard.insert(clean, img.clone());
    }
    img
}

fn render_flag_png(cc: &str) -> Option<Vec<u8>> {
    use image::{ImageEncoder, Rgba, RgbaImage, codecs::png::PngEncoder};

    let code = if cc == "uk" { "gb" } else { cc };
    let w = 24u32;
    let h = 18u32;
    let mut img = RgbaImage::new(w, h);

    let put_rect = |img: &mut RgbaImage, x0: u32, y0: u32, x1: u32, y1: u32, col: [u8; 4]| {
        for y in y0.min(h)..y1.min(h) {
            for x in x0.min(w)..x1.min(w) {
                img.put_pixel(x, y, Rgba(col));
            }
        }
    };

    let h3 = |img: &mut RgbaImage, c1: [u8; 4], c2: [u8; 4], c3: [u8; 4]| {
        put_rect(img, 0, 0, w, 6, c1);
        put_rect(img, 0, 6, w, 12, c2);
        put_rect(img, 0, 12, w, h, c3);
    };

    let v3 = |img: &mut RgbaImage, c1: [u8; 4], c2: [u8; 4], c3: [u8; 4]| {
        put_rect(img, 0, 0, 8, h, c1);
        put_rect(img, 8, 0, 16, h, c2);
        put_rect(img, 16, 0, w, h, c3);
    };

    let nordic = |img: &mut RgbaImage, bg: [u8; 4], cross: [u8; 4], inner: Option<[u8; 4]>| {
        put_rect(img, 0, 0, w, h, bg);
        put_rect(img, 6, 0, 11, h, cross);
        put_rect(img, 0, 6, w, 12, cross);
        if let Some(in_col) = inner {
            put_rect(img, 7, 0, 10, h, in_col);
            put_rect(img, 0, 7, w, 11, in_col);
        }
    };

    match code {
        "ru" => h3(
            &mut img,
            [245, 245, 247, 255],
            [0, 57, 166, 255],
            [213, 43, 30, 255],
        ),
        "nl" => h3(
            &mut img,
            [174, 28, 40, 255],
            [255, 255, 255, 255],
            [33, 70, 139, 255],
        ),
        "de" => h3(
            &mut img,
            [20, 20, 24, 255],
            [221, 0, 0, 255],
            [255, 206, 0, 255],
        ),
        "ee" => h3(
            &mut img,
            [0, 114, 206, 255],
            [20, 20, 24, 255],
            [245, 245, 247, 255],
        ),
        "lt" => h3(
            &mut img,
            [253, 185, 19, 255],
            [0, 106, 68, 255],
            [193, 39, 45, 255],
        ),
        "lv" => {
            put_rect(&mut img, 0, 0, w, h, [158, 48, 57, 255]);
            put_rect(&mut img, 0, 7, w, 11, [255, 255, 255, 255]);
        }
        "at" => h3(
            &mut img,
            [237, 41, 57, 255],
            [255, 255, 255, 255],
            [237, 41, 57, 255],
        ),
        "hu" => h3(
            &mut img,
            [206, 41, 57, 255],
            [255, 255, 255, 255],
            [71, 112, 80, 255],
        ),
        "bg" => h3(
            &mut img,
            [255, 255, 255, 255],
            [0, 150, 110, 255],
            [214, 38, 18, 255],
        ),
        "am" => h3(
            &mut img,
            [217, 0, 18, 255],
            [0, 51, 160, 255],
            [242, 168, 0, 255],
        ),
        "az" => h3(
            &mut img,
            [0, 181, 226, 255],
            [239, 51, 64, 255],
            [80, 158, 47, 255],
        ),
        "uz" => h3(
            &mut img,
            [0, 153, 181, 255],
            [255, 255, 255, 255],
            [30, 181, 58, 255],
        ),
        "es" => {
            put_rect(&mut img, 0, 0, w, 4, [170, 21, 27, 255]);
            put_rect(&mut img, 0, 4, w, 14, [241, 191, 0, 255]);
            put_rect(&mut img, 0, 14, w, h, [170, 21, 27, 255]);
        }
        "pl" => {
            put_rect(&mut img, 0, 0, w, 9, [245, 245, 247, 255]);
            put_rect(&mut img, 0, 9, w, h, [220, 20, 60, 255]);
        }
        "ua" => {
            put_rect(&mut img, 0, 0, w, 9, [0, 87, 183, 255]);
            put_rect(&mut img, 0, 9, w, h, [255, 215, 0, 255]);
        }
        "sg" => {
            put_rect(&mut img, 0, 0, w, 9, [239, 51, 64, 255]);
            put_rect(&mut img, 0, 9, w, h, [245, 245, 247, 255]);
        }
        "by" => {
            put_rect(&mut img, 0, 0, w, 12, [200, 49, 62, 255]);
            put_rect(&mut img, 0, 12, w, h, [74, 166, 87, 255]);
            put_rect(&mut img, 0, 0, 3, h, [245, 245, 247, 255]);
        }
        "fr" => v3(
            &mut img,
            [0, 38, 84, 255],
            [255, 255, 255, 255],
            [237, 41, 57, 255],
        ),
        "it" => v3(
            &mut img,
            [0, 146, 70, 255],
            [255, 255, 255, 255],
            [206, 43, 55, 255],
        ),
        "be" => v3(
            &mut img,
            [20, 20, 24, 255],
            [253, 218, 36, 255],
            [239, 51, 64, 255],
        ),
        "ro" | "md" => v3(
            &mut img,
            [0, 43, 127, 255],
            [252, 209, 22, 255],
            [206, 17, 38, 255],
        ),
        "ie" => v3(
            &mut img,
            [22, 155, 98, 255],
            [255, 255, 255, 255],
            [255, 136, 62, 255],
        ),
        "ca" => {
            put_rect(&mut img, 0, 0, 6, h, [255, 0, 0, 255]);
            put_rect(&mut img, 6, 0, 18, h, [255, 255, 255, 255]);
            put_rect(&mut img, 18, 0, w, h, [255, 0, 0, 255]);
            put_rect(&mut img, 9, 5, 15, 13, [255, 0, 0, 255]);
        }
        "fi" => nordic(&mut img, [255, 255, 255, 255], [0, 47, 108, 255], None),
        "se" => nordic(&mut img, [0, 106, 167, 255], [254, 204, 2, 255], None),
        "dk" => nordic(&mut img, [200, 16, 46, 255], [255, 255, 255, 255], None),
        "no" => nordic(
            &mut img,
            [186, 12, 47, 255],
            [255, 255, 255, 255],
            Some([0, 32, 91, 255]),
        ),
        "ch" => {
            put_rect(&mut img, 0, 0, w, h, [218, 41, 28, 255]);
            put_rect(&mut img, 10, 3, 14, 15, [255, 255, 255, 255]);
            put_rect(&mut img, 6, 7, 18, 11, [255, 255, 255, 255]);
        }
        "ge" => {
            put_rect(&mut img, 0, 0, w, h, [255, 255, 255, 255]);
            put_rect(&mut img, 10, 0, 14, h, [255, 0, 0, 255]);
            put_rect(&mut img, 0, 7, w, 11, [255, 0, 0, 255]);
        }
        "gb" => {
            put_rect(&mut img, 0, 0, w, h, [1, 33, 105, 255]);
            for y in 0..h {
                for x in 0..w {
                    let d1 = ((x as i32 * 18) - (y as i32 * 24)).abs();
                    let d2 = (((w - 1 - x) as i32 * 18) - (y as i32 * 24)).abs();
                    if d1 < 48 || d2 < 48 {
                        img.put_pixel(x, y, Rgba([255, 255, 255, 255]));
                    }
                    if d1 < 22 || d2 < 22 {
                        img.put_pixel(x, y, Rgba([200, 16, 46, 255]));
                    }
                }
            }
            put_rect(&mut img, 9, 0, 15, h, [255, 255, 255, 255]);
            put_rect(&mut img, 0, 6, w, 12, [255, 255, 255, 255]);
            put_rect(&mut img, 10, 0, 14, h, [200, 16, 46, 255]);
            put_rect(&mut img, 0, 7, w, 11, [200, 16, 46, 255]);
        }
        "us" => {
            for row in 0..9u32 {
                let col = if row % 2 == 0 {
                    [178, 34, 52, 255]
                } else {
                    [255, 255, 255, 255]
                };
                put_rect(&mut img, 0, row * 2, w, (row + 1) * 2, col);
            }
            put_rect(&mut img, 0, 0, 11, 10, [60, 59, 110, 255]);
            for sy in [2u32, 5, 8] {
                for sx in [2u32, 5, 8] {
                    img.put_pixel(sx, sy, Rgba([255, 255, 255, 255]));
                }
            }
        }
        "cz" => {
            put_rect(&mut img, 0, 0, w, 9, [255, 255, 255, 255]);
            put_rect(&mut img, 0, 9, w, h, [215, 20, 26, 255]);
            for y in 0..h {
                let dist_mid = (y as i32 - 9).unsigned_abs();
                let max_x = (12u32).saturating_sub(dist_mid * 4 / 3);
                for x in 0..max_x {
                    img.put_pixel(x, y, Rgba([17, 69, 126, 255]));
                }
            }
        }
        "tr" => {
            put_rect(&mut img, 0, 0, w, h, [227, 10, 23, 255]);
            for y in 0..h {
                for x in 0..w {
                    let dx1 = x as i32 - 9;
                    let dy1 = y as i32 - 9;
                    let dx2 = x as i32 - 11;
                    let dy2 = y as i32 - 9;
                    if dx1 * dx1 + dy1 * dy1 <= 25 && dx2 * dx2 + dy2 * dy2 > 16 {
                        img.put_pixel(x, y, Rgba([255, 255, 255, 255]));
                    }
                }
            }
            put_rect(&mut img, 14, 8, 17, 11, [255, 255, 255, 255]);
        }
        "kz" => {
            put_rect(&mut img, 0, 0, w, h, [0, 175, 202, 255]);
            for y in 0..h {
                for x in 0..w {
                    let dx = x as i32 - 12;
                    let dy = y as i32 - 9;
                    if dx * dx + dy * dy <= 16 {
                        img.put_pixel(x, y, Rgba([254, 197, 12, 255]));
                    }
                }
            }
        }
        "jp" => {
            put_rect(&mut img, 0, 0, w, h, [255, 255, 255, 255]);
            for y in 0..h {
                for x in 0..w {
                    let dx = x as i32 - 12;
                    let dy = y as i32 - 9;
                    if dx * dx + dy * dy <= 25 {
                        img.put_pixel(x, y, Rgba([188, 0, 45, 255]));
                    }
                }
            }
        }
        "kr" => {
            put_rect(&mut img, 0, 0, w, h, [255, 255, 255, 255]);
            for y in 0..h {
                for x in 0..w {
                    let dx = x as i32 - 12;
                    let dy = y as i32 - 9;
                    if dx * dx + dy * dy <= 20 {
                        let col = if dy < 0 {
                            [205, 46, 58, 255]
                        } else {
                            [0, 71, 160, 255]
                        };
                        img.put_pixel(x, y, Rgba(col));
                    }
                }
            }
        }
        "hk" => {
            put_rect(&mut img, 0, 0, w, h, [222, 41, 16, 255]);
            for y in 0..h {
                for x in 0..w {
                    let dx = x as i32 - 12;
                    let dy = y as i32 - 9;
                    if dx * dx + dy * dy <= 16 {
                        img.put_pixel(x, y, Rgba([255, 255, 255, 255]));
                    }
                }
            }
        }
        "ae" => {
            put_rect(&mut img, 0, 0, w, 6, [0, 115, 47, 255]);
            put_rect(&mut img, 0, 6, w, 12, [255, 255, 255, 255]);
            put_rect(&mut img, 0, 12, w, h, [20, 20, 24, 255]);
            put_rect(&mut img, 0, 0, 6, h, [255, 0, 0, 255]);
        }
        "il" => {
            put_rect(&mut img, 0, 0, w, h, [255, 255, 255, 255]);
            put_rect(&mut img, 0, 2, w, 5, [0, 56, 184, 255]);
            put_rect(&mut img, 0, 13, w, 16, [0, 56, 184, 255]);
            put_rect(&mut img, 10, 7, 14, 11, [0, 56, 184, 255]);
        }
        "in" => {
            h3(
                &mut img,
                [255, 153, 51, 255],
                [255, 255, 255, 255],
                [19, 136, 8, 255],
            );
            put_rect(&mut img, 10, 7, 14, 11, [0, 0, 128, 255]);
        }
        "br" => {
            put_rect(&mut img, 0, 0, w, h, [0, 156, 59, 255]);
            for y in 3..15u32 {
                let dy = (y as i32 - 9).unsigned_abs();
                let span = (12u32).saturating_sub(dy * 2);
                for x in (12 - span)..(12 + span) {
                    img.put_pixel(x, y, Rgba([255, 223, 0, 255]));
                }
            }
            put_rect(&mut img, 9, 6, 15, 12, [0, 39, 118, 255]);
        }
        "au" => {
            put_rect(&mut img, 0, 0, w, h, [0, 0, 139, 255]);
            put_rect(&mut img, 0, 0, 11, 9, [200, 16, 46, 255]);
            put_rect(&mut img, 16, 5, 19, 8, [255, 255, 255, 255]);
            put_rect(&mut img, 18, 12, 20, 14, [255, 255, 255, 255]);
        }
        "eu" => {
            put_rect(&mut img, 0, 0, w, h, [0, 51, 153, 255]);
            for &(sx, sy) in &[
                (12u32, 3u32),
                (15, 4),
                (17, 6),
                (18, 9),
                (17, 12),
                (15, 14),
                (12, 15),
                (9, 14),
                (7, 12),
                (6, 9),
                (7, 6),
                (9, 4),
            ] {
                put_rect(&mut img, sx, sy, sx + 2, sy + 2, [255, 204, 0, 255]);
            }
        }
        _ => return None,
    }

    let mut out = Vec::with_capacity(512);
    PngEncoder::new(&mut out)
        .write_image(img.as_raw(), w, h, image::ExtendedColorType::Rgba8)
        .ok()?;
    Some(out)
}
