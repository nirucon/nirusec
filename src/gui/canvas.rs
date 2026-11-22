//! A client-side framebuffer (0x00RRGGBB per pixel) and the few drawing
//! operations the NIRU tools need. Everything is drawn here and sent to the
//! window in one copy (MIT-SHM when the server offers it), so a redraw never
//! flickers and costs one memory copy instead of many X requests.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && py >= self.y && px < self.x + self.w && py < self.y + self.h
    }
    pub fn intersect(&self, o: &Rect) -> Rect {
        let x0 = self.x.max(o.x);
        let y0 = self.y.max(o.y);
        let x1 = (self.x + self.w).min(o.x + o.w);
        let y1 = (self.y + self.h).min(o.y + o.h);
        Rect::new(x0, y0, (x1 - x0).max(0), (y1 - y0).max(0))
    }
    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }
    pub fn right(&self) -> i32 {
        self.x + self.w
    }
}

pub struct Canvas {
    pub w: i32,
    pub h: i32,
    pub px: Vec<u32>,
    clip: Rect,
}

impl Canvas {
    pub fn new(w: i32, h: i32) -> Self {
        let w = w.max(1);
        let h = h.max(1);
        Self {
            w,
            h,
            px: vec![0; (w * h) as usize],
            clip: Rect::new(0, 0, w, h),
        }
    }

    pub fn resize(&mut self, w: i32, h: i32) {
        let w = w.max(1);
        let h = h.max(1);
        if w != self.w || h != self.h {
            self.w = w;
            self.h = h;
            self.px = vec![0; (w * h) as usize];
        }
        self.clip = Rect::new(0, 0, w, h);
    }

    pub fn set_clip(&mut self, r: Rect) {
        self.clip = r.intersect(&Rect::new(0, 0, self.w, self.h));
    }

    pub fn fill(&mut self, r: Rect, color: u32) {
        let r = r.intersect(&self.clip);
        if r.w <= 0 || r.h <= 0 {
            return;
        }
        for y in r.y..r.y + r.h {
            let row = (y * self.w) as usize;
            self.px[row + r.x as usize..row + (r.x + r.w) as usize].fill(color);
        }
    }

    /// A frame `width` pixels wide inside `r`.
    pub fn frame(&mut self, r: Rect, color: u32, width: i32) {
        let t = width.max(1);
        self.fill(Rect::new(r.x, r.y, r.w, t), color);
        self.fill(Rect::new(r.x, r.y + r.h - t, r.w, t), color);
        self.fill(Rect::new(r.x, r.y, t, r.h), color);
        self.fill(Rect::new(r.x + r.w - t, r.y, t, r.h), color);
    }

    /// How far row `i` of a corner of radius `rad` is cut in.
    fn corner_inset(rad: i32, i: i32) -> i32 {
        let d = (rad - i) as f32 - 0.5;
        let r = rad as f32;
        (r - (r * r - d * d).max(0.0).sqrt()).round() as i32
    }

    /// A filled rectangle with rounded corners.
    pub fn round_fill(&mut self, r: Rect, rad: i32, color: u32) {
        let rad = rad.min(r.h / 2).min(r.w / 2).max(0);
        if rad == 0 {
            return self.fill(r, color);
        }
        for i in 0..rad {
            let inset = Self::corner_inset(rad, i);
            self.fill(Rect::new(r.x + inset, r.y + i, r.w - 2 * inset, 1), color);
            self.fill(
                Rect::new(r.x + inset, r.y + r.h - 1 - i, r.w - 2 * inset, 1),
                color,
            );
        }
        self.fill(Rect::new(r.x, r.y + rad, r.w, r.h - 2 * rad), color);
    }

    /// A rounded outline `width` pixels wide.
    pub fn round_frame(&mut self, r: Rect, rad: i32, color: u32, width: i32) {
        let rad = rad.min(r.h / 2).min(r.w / 2).max(0);
        let t = width.max(1);
        if rad == 0 {
            return self.frame(r, color, t);
        }
        for i in 0..rad {
            let inset = Self::corner_inset(rad, i);
            let next = if i + 1 < rad {
                Self::corner_inset(rad, i + 1)
            } else {
                0
            };
            let span = (inset - next).max(t);
            for y in [r.y + i, r.y + r.h - 1 - i] {
                self.fill(Rect::new(r.x + inset, y, span, 1), color);
                self.fill(Rect::new(r.x + r.w - inset - span, y, span, 1), color);
            }
            if i < t {
                for y in [r.y + i, r.y + r.h - 1 - i] {
                    self.fill(Rect::new(r.x + inset, y, r.w - 2 * inset, 1), color);
                }
            }
        }
        self.fill(Rect::new(r.x, r.y + rad, t, r.h - 2 * rad), color);
        self.fill(Rect::new(r.x + r.w - t, r.y + rad, t, r.h - 2 * rad), color);
    }

    /// Blend `color` with coverage 0..=255 at one pixel (already clipped).
    #[inline]
    fn blend_at(&mut self, i: usize, color: u32, a: u32) {
        if a == 0 {
            return;
        }
        if a >= 255 {
            self.px[i] = color;
            return;
        }
        let d = self.px[i];
        let inv = 255 - a;
        let ch = |s: u32, d: u32| (s * a + d * inv + 127) / 255;
        self.px[i] = (ch((color >> 16) & 0xff, (d >> 16) & 0xff) << 16)
            | (ch((color >> 8) & 0xff, (d >> 8) & 0xff) << 8)
            | ch(color & 0xff, d & 0xff);
    }

    /// Draw a coverage mask (one byte per pixel) in `color` at (x, y).
    pub fn mask(&mut self, x: i32, y: i32, w: i32, h: i32, coverage: &[u8], color: u32) {
        let area = Rect::new(x, y, w, h).intersect(&self.clip);
        for py in area.y..area.y + area.h {
            let src_row = ((py - y) * w) as usize;
            let dst_row = (py * self.w) as usize;
            for px in area.x..area.x + area.w {
                let a = coverage[src_row + (px - x) as usize] as u32;
                self.blend_at(dst_row + px as usize, color, a);
            }
        }
    }

    /// Blend a translucent rectangle (hover, scanlines).
    pub fn tint(&mut self, r: Rect, color: u32, a: u32) {
        let r = r.intersect(&self.clip);
        for py in r.y..r.y + r.h {
            let row = (py * self.w) as usize;
            for px in r.x..r.x + r.w {
                self.blend_at(row + px as usize, color, a);
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: u32 has no padding; the slice covers exactly the pixels.
        unsafe { std::slice::from_raw_parts(self.px.as_ptr() as *const u8, self.px.len() * 4) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_is_clipped_to_the_canvas_and_the_clip_rect() {
        let mut c = Canvas::new(10, 10);
        c.fill(Rect::new(-5, -5, 8, 8), 0xffffff);
        assert_eq!(c.px[0], 0xffffff);
        assert_eq!(c.px[3], 0);
        c.set_clip(Rect::new(5, 5, 5, 5));
        c.fill(Rect::new(0, 0, 10, 10), 0x123456);
        assert_eq!(c.px[4 * 10 + 4], 0);
        assert_eq!(c.px[5 * 10 + 5], 0x123456);
    }

    #[test]
    fn rounded_corners_leave_the_corner_pixel_untouched() {
        let mut c = Canvas::new(20, 20);
        c.round_fill(Rect::new(0, 0, 20, 20), 6, 0xffffff);
        assert_eq!(c.px[0], 0);
        assert_eq!(c.px[10 * 20 + 10], 0xffffff);
        assert_eq!(c.px[10], 0xffffff);
    }

    #[test]
    fn half_coverage_blends_halfway() {
        let mut c = Canvas::new(1, 1);
        c.mask(0, 0, 1, 1, &[128], 0xffffff);
        let v = c.px[0] & 0xff;
        assert!((126..=130).contains(&v), "{v}");
    }
}
