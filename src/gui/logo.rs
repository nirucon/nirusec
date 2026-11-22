//! Retro pixel lettering: chunky 5x7 letters in the theme accent with a
//! one-pixel drop shadow and faint scanlines, the way the rest of the suite
//! does retro. Used for the window title and the window icon.
use super::canvas::{Canvas, Rect};
use super::theme::{blend, Palette};
use super::ui::Ui;

/// 5x7 glyphs, one row per byte, bit 4 = leftmost column.
fn glyph(c: char) -> [u8; 7] {
    match c {
        'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        'I' => [0x0e, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0e],
        'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        'E' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
        'C' => [0x0e, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0e],
        'G' => [0x0e, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0f],
        'A' => [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        'M' => [0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11],
        _ => [0; 7],
    }
}

pub fn word_width(s: &str, px: i32) -> i32 {
    let n = s.chars().count() as i32;
    (n * 6 - 1).max(0) * px
}

fn dots(cv: &mut Canvas, x: i32, y: i32, s: &str, px: i32, color: u32) {
    for (i, c) in s.chars().enumerate() {
        let g = glyph(c.to_ascii_uppercase());
        let gx = x + i as i32 * 6 * px;
        for (row, bits) in g.iter().enumerate() {
            for col in 0..5 {
                if bits & (0x10 >> col) != 0 {
                    cv.fill(Rect::new(gx + col * px, y + row as i32 * px, px, px), color);
                }
            }
        }
    }
}

/// The program name in pixel letters at the current position of `ui`;
/// returns the space it took.
pub fn title(ui: &mut Ui, s: &str, px: i32) -> Rect {
    let w = word_width(s, px) + px;
    let h = 7 * px + px;
    let r = ui.alloc(w, h);
    let p = ui.pal.clone();
    let shadow = blend(p.background, p.accent, 0.3);
    for (dx, color) in [(px.max(2) / 2, shadow), (0, p.accent)] {
        for (i, c) in s.chars().enumerate() {
            let g = glyph(c.to_ascii_uppercase());
            let gx = r.x + dx + i as i32 * 6 * px;
            for (row, bits) in g.iter().enumerate() {
                for col in 0..5 {
                    if bits & (0x10 >> col) != 0 {
                        ui.paint_fill(
                            Rect::new(gx + col * px, r.y + dx + row as i32 * px, px, px),
                            color,
                        );
                    }
                }
            }
        }
    }
    let mut y = r.y;
    while y < r.y + 7 * px {
        ui.paint_tint(Rect::new(r.x, y, w, 1), p.background, 70);
        y += 2;
    }
    r
}

/// ARGB window icons: a rounded accent tile with one pixel letter.
pub fn window_icons(p: &Palette, letter: char) -> Vec<(u32, u32, Vec<u32>)> {
    [16u32, 32, 48]
        .iter()
        .map(|&s| {
            let si = s as i32;
            let mut cv = Canvas::new(si, si);
            cv.round_fill(Rect::new(0, 0, si, si), si / 5, p.accent);
            let px = (si / 10).max(1);
            let (lw, lh) = (5 * px, 7 * px);
            let mut letters = Canvas::new(si, si);
            dots(
                &mut letters,
                (si - lw) / 2,
                (si - lh) / 2,
                &letter.to_string(),
                px,
                0xffffff,
            );
            let argb = cv
                .px
                .iter()
                .zip(letters.px.iter())
                .map(|(v, l)| {
                    if *l != 0 {
                        0xff00_0000 | p.background
                    } else if *v == 0 {
                        0
                    } else {
                        0xff00_0000 | v
                    }
                })
                .collect();
            (s, s, argb)
        })
        .collect()
}
