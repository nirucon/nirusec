//! A small immediate-mode widget layer on the software canvas: labels with
//! word wrap, buttons, check boxes, radio buttons, drop-down lists, one-line
//! text fields, collapsible sections, frames, columns, scroll regions,
//! tooltips and a modal layer. Each frame the program describes its whole
//! window; widgets report clicks and key activation straight away, and the
//! frame is drawn from one display list at the end.
//!
//! Keyboard: Tab and Shift+Tab move the focus, Enter or Space press the
//! focused control, Up/Down change a focused drop-down, Esc closes an open
//! drop-down. Text fields edit with the usual keys and Ctrl+V pastes.
use super::canvas::{Canvas, Rect};
use super::text::{Size, Text};
use super::theme::{blend, luminance, Palette, Theme};
use super::x::Pointer;
use std::collections::HashMap;

pub type Id = u64;

fn hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub mod keys {
    pub const TAB: u32 = 0xff09;
    pub const ISO_LEFT_TAB: u32 = 0xfe20;
    pub const RETURN: u32 = 0xff0d;
    pub const KP_ENTER: u32 = 0xff8d;
    pub const ESCAPE: u32 = 0xff1b;
    pub const BACKSPACE: u32 = 0xff08;
    pub const DELETE: u32 = 0xffff;
    pub const LEFT: u32 = 0xff51;
    pub const UP: u32 = 0xff52;
    pub const RIGHT: u32 = 0xff53;
    pub const DOWN: u32 = 0xff54;
    pub const HOME: u32 = 0xff50;
    pub const END: u32 = 0xff57;
    pub const PAGE_UP: u32 = 0xff55;
    pub const PAGE_DOWN: u32 = 0xff56;
    pub const SPACE: u32 = 0x20;
    pub const F5: u32 = 0xffc2;
}

/// One key press, already translated.
#[derive(Clone, Debug)]
pub struct KeyEv {
    pub ks: u32,
    pub ctrl: bool,
    pub shift: bool,
    pub alt: bool,
    pub ch: Option<char>,
}

impl KeyEv {
    pub fn new(ks: u32, ctrl: bool, shift: bool, alt: bool) -> Self {
        let ch = match ks {
            0x20..=0x7e | 0xa0..=0xff => char::from_u32(ks),
            0x0100_0000..=0x0110_ffff => char::from_u32(ks - 0x0100_0000),
            _ => None,
        };
        Self {
            ks,
            ctrl,
            shift,
            alt,
            ch,
        }
    }
    pub fn is(&self, ks: u32) -> bool {
        self.ks == ks && !self.ctrl && !self.alt
    }
    pub fn enter(&self) -> bool {
        (self.ks == keys::RETURN || self.ks == keys::KP_ENTER) && !self.ctrl && !self.alt
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Button,
    Text,
    Combo,
    Area,
    Tip,
}

#[derive(Clone, Debug)]
enum Edit {
    Char(char),
    Back,
    Del,
    Left,
    Right,
    Home,
    End,
    Clear,
    Paste(String),
}

#[derive(Clone, Debug)]
struct Hit {
    name: String,
    id: Id,
    rect: Rect,
    full: Rect,
    layer: u8,
    kind: Kind,
    enabled: bool,
    scroll: Option<u64>,
    tip: Option<String>,
}

/// `NIRU_UI_TRACE=1` prints every control and its centre after each frame
/// ("ui|NAME|X|Y|ENABLED"), for the end-to-end tests.
fn trace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NIRU_UI_TRACE").is_some())
}

/// What a key press did inside the widgets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUse {
    Ignored,
    Used,
    /// Ctrl+V in a text field: the caller asks the clipboard owner.
    Paste,
}

/// Widget state that outlives a frame.
#[derive(Default)]
pub struct State {
    pub focus: Option<Id>,
    focus_visible: bool,
    hits: Vec<Hit>,
    hot: Option<Id>,
    mouse: (i32, i32),
    click: Option<(i32, i32)>,
    edits: Vec<Edit>,
    activate: bool,
    combo_step: i32,
    popup: Option<Id>,
    popup_rect: Rect,
    popup_hl: usize,
    popup_choose: bool,
    scroll: HashMap<u64, i32>,
    regions: Vec<(u64, Rect, i32)>,
    content_h: HashMap<u64, i32>,
    open: HashMap<u64, bool>,
    cursor: usize,
    scroll_to_focus: bool,
    /// The program shows a modal layer: only it takes input.
    pub modal: bool,
    /// Something changed during the frame: build it once more.
    pub again: bool,
    pub quit: bool,
    /// Text to put on the CLIPBOARD after the frame.
    pub copy: Option<String>,
}

impl State {
    fn top_layer(&self) -> u8 {
        if self.popup.is_some() {
            2
        } else if self.modal {
            1
        } else {
            0
        }
    }

    fn input_layer_ok(&self, layer: u8) -> bool {
        layer >= self.top_layer()
    }

    /// A text field has the keyboard.
    pub fn typing(&self) -> bool {
        self.focus_kind() == Some(Kind::Text)
    }

    pub fn popup_open(&self) -> bool {
        self.popup.is_some()
    }

    fn focus_kind(&self) -> Option<Kind> {
        let f = self.focus?;
        self.hits.iter().find(|h| h.id == f).map(|h| h.kind)
    }

    pub fn blur(&mut self) {
        self.focus = None;
        self.popup = None;
    }

    /// The pointer moved: returns true when the hovered widget changed.
    pub fn motion(&mut self, x: i32, y: i32) -> bool {
        self.mouse = (x, y);
        let hot = self
            .hits
            .iter()
            .rev()
            .find(|h| self.input_layer_ok(h.layer) && h.rect.contains(x, y))
            .map(|h| h.id);
        let changed = hot != self.hot;
        self.hot = hot;
        changed
    }

    pub fn leave(&mut self) -> bool {
        self.mouse = (-1, -1);
        let changed = self.hot.is_some();
        self.hot = None;
        changed
    }

    pub fn pointer(&self) -> Pointer {
        let Some(h) = self
            .hot
            .and_then(|id| self.hits.iter().find(|h| h.id == id))
        else {
            return Pointer::Arrow;
        };
        match h.kind {
            Kind::Text => Pointer::Text,
            Kind::Tip => Pointer::Arrow,
            _ if h.enabled => Pointer::Hand,
            _ => Pointer::Arrow,
        }
    }

    /// A mouse button: 1 clicks, 4/5 scroll the region under the pointer.
    pub fn press(&mut self, x: i32, y: i32, button: u8) -> bool {
        self.mouse = (x, y);
        match button {
            1 => {
                self.click = Some((x, y));
                true
            }
            4 | 5 => {
                let step = if button == 4 { -48 } else { 48 };
                let region = self
                    .regions
                    .iter()
                    .rev()
                    .find(|(_, r, max)| *max > 0 && r.contains(x, y))
                    .map(|(id, _, max)| (*id, *max));
                if let Some((id, max)) = region {
                    let off = self.scroll.entry(id).or_insert(0);
                    let new = (*off + step).clamp(0, max);
                    let changed = new != *off;
                    *off = new;
                    return changed;
                }
                false
            }
            _ => false,
        }
    }

    /// Scroll a region by `delta` pixels (Page Up/Down); true when it moved.
    pub fn scroll_by(&mut self, key: &str, delta: i32) -> bool {
        let id = hash(key);
        let max = self
            .regions
            .iter()
            .find(|(i, ..)| *i == id)
            .map(|r| r.2)
            .unwrap_or(0);
        let off = self.scroll.entry(id).or_insert(0);
        let new = (*off + delta).clamp(0, max);
        let changed = new != *off;
        *off = new;
        changed
    }

    pub fn scroll_view_height(&self, key: &str) -> i32 {
        let id = hash(key);
        self.regions
            .iter()
            .find(|(i, ..)| *i == id)
            .map(|r| r.1.h)
            .unwrap_or(400)
    }

    pub fn reset_scroll(&mut self, key: &str) {
        self.scroll.remove(&hash(key));
    }

    /// Give the keyboard to the text field `key` (as named in `text_edit`).
    pub fn focus_field(&mut self, key: &str) {
        self.focus = Some(hash(key).wrapping_add(0x9e37_79b9_7f4a_7c15));
        self.focus_visible = false;
        self.cursor = usize::MAX;
    }

    /// Text arrived from the clipboard for the focused field.
    pub fn paste(&mut self, text: &str) {
        let line: String = text
            .chars()
            .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
            .filter(|c| !c.is_control())
            .collect();
        self.edits.push(Edit::Paste(line));
    }

    fn move_focus(&mut self, back: bool) {
        let layer = self.top_layer().min(1);
        let order: Vec<Id> = self
            .hits
            .iter()
            .filter(|h| h.layer == layer && h.enabled && h.kind != Kind::Tip)
            .map(|h| h.id)
            .collect();
        if order.is_empty() {
            return;
        }
        let pos = self.focus.and_then(|f| order.iter().position(|i| *i == f));
        let next = match (pos, back) {
            (None, false) => 0,
            (None, true) => order.len() - 1,
            (Some(p), false) => (p + 1) % order.len(),
            (Some(p), true) => (p + order.len() - 1) % order.len(),
        };
        self.focus = Some(order[next]);
        self.focus_visible = true;
        self.scroll_to_focus = true;
        self.cursor = usize::MAX;
    }

    /// Give a key to the widgets first.
    pub fn key(&mut self, k: &KeyEv) -> KeyUse {
        use keys::*;
        if self.popup.is_some() {
            match k.ks {
                UP => self.combo_step -= 1,
                DOWN => self.combo_step += 1,
                RETURN | KP_ENTER | SPACE => self.popup_choose = true,
                ESCAPE | TAB | ISO_LEFT_TAB => self.popup = None,
                _ => return KeyUse::Used,
            }
            return KeyUse::Used;
        }
        if k.ks == TAB || k.ks == ISO_LEFT_TAB {
            if k.ctrl || k.alt {
                return KeyUse::Ignored;
            }
            self.move_focus(k.shift || k.ks == ISO_LEFT_TAB);
            return KeyUse::Used;
        }
        match self.focus_kind() {
            Some(Kind::Text) => {
                let e = match k.ks {
                    BACKSPACE if k.ctrl => Edit::Clear,
                    BACKSPACE => Edit::Back,
                    DELETE => Edit::Del,
                    LEFT => Edit::Left,
                    RIGHT => Edit::Right,
                    HOME => Edit::Home,
                    END => Edit::End,
                    _ if k.ctrl && matches!(k.ch, Some('v') | Some('V')) => {
                        return KeyUse::Paste;
                    }
                    _ if k.ctrl && matches!(k.ch, Some('u') | Some('U')) => Edit::Clear,
                    _ if !k.ctrl && !k.alt && k.ch.is_some() => Edit::Char(k.ch.unwrap()),
                    ESCAPE => {
                        self.focus = None;
                        return KeyUse::Used;
                    }
                    _ => return KeyUse::Ignored,
                };
                self.edits.push(e);
                KeyUse::Used
            }
            Some(kind) if !k.ctrl && !k.alt => match k.ks {
                RETURN | KP_ENTER | SPACE => {
                    self.activate = true;
                    KeyUse::Used
                }
                UP | DOWN if kind == Kind::Combo => {
                    self.combo_step += if k.ks == UP { -1 } else { 1 };
                    KeyUse::Used
                }
                ESCAPE if self.focus_visible => {
                    self.focus = None;
                    KeyUse::Used
                }
                _ => KeyUse::Ignored,
            },
            _ => KeyUse::Ignored,
        }
    }

    /// Start a frame on a canvas of `w` x `h` pixels.
    pub fn begin<'a>(&'a mut self, text: &'a mut Text, theme: &'a Theme, w: i32, h: i32) -> Ui<'a> {
        let click = self.click.take();
        let click_layer = match click {
            Some(p) if self.popup.is_some() => {
                if self.popup_rect.contains(p.0, p.1) {
                    Some(2)
                } else {
                    self.popup = None;
                    self.again = true;
                    None
                }
            }
            Some(_) if self.modal => Some(1),
            Some(_) => Some(0),
            None => None,
        };
        self.again = self.again || click.is_some();
        let sizes = Sizes::new(text, theme.font_px);
        let screen = Rect::new(0, 0, w, h);
        Ui {
            st: self,
            tx: text,
            pal: &theme.palette,
            theme,
            sz: sizes,
            lists: [Vec::new(), Vec::new(), Vec::new()],
            layer: 0,
            x: 0,
            w,
            y: 0,
            flow: None,
            items: Vec::new(),
            clip: screen,
            screen,
            scroll_id: None,
            click,
            click_layer,
            claimed: false,
            hits: Vec::new(),
            regions: Vec::new(),
            seen: HashMap::new(),
            spacing: 6,
            popup_rect: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Sz {
    Tiny,
    Small,
    Body,
    Big,
    Heading,
    Title,
}

#[derive(Clone, Copy)]
pub struct Sizes {
    pub tiny: Size,
    pub small: Size,
    pub body: Size,
    pub big: Size,
    pub heading: Size,
    pub title: Size,
}

impl Sizes {
    fn new(t: &Text, px: f32) -> Self {
        let s = |f: f32| t.size((px * f).round().max(8.0));
        Self {
            tiny: s(0.72),
            small: s(0.8),
            body: s(1.0),
            big: s(1.1),
            heading: s(1.3),
            title: s(1.45),
        }
    }
    pub fn get(&self, sz: Sz) -> Size {
        match sz {
            Sz::Tiny => self.tiny,
            Sz::Small => self.small,
            Sz::Body => self.body,
            Sz::Big => self.big,
            Sz::Heading => self.heading,
            Sz::Title => self.title,
        }
    }
}

enum Cmd {
    Nop,
    Clip(Rect),
    /// Restores an outer clip; never moved with a flow item.
    Unclip(Rect),
    Fill(Rect, u32),
    Tint(Rect, u32, u32),
    Box {
        r: Rect,
        rad: i32,
        fill: Option<u32>,
        stroke: u32,
        width: i32,
    },
    Text {
        x: i32,
        y: i32,
        s: String,
        size: Size,
        color: u32,
        bold: bool,
    },
}

/// Options of a button.
#[derive(Clone, Copy, Debug)]
pub struct Btn {
    pub fill: Option<u32>,
    pub enabled: bool,
    pub small: bool,
    pub selected: bool,
    pub strong: bool,
    pub width: Option<i32>,
}

impl Default for Btn {
    fn default() -> Self {
        Self {
            fill: None,
            enabled: true,
            small: false,
            selected: false,
            strong: false,
            width: None,
        }
    }
}

impl Btn {
    pub fn enabled(mut self, on: bool) -> Self {
        self.enabled = on;
        self
    }
    pub fn fill(mut self, c: u32) -> Self {
        self.fill = Some(c);
        self
    }
    pub fn small(mut self) -> Self {
        self.small = true;
        self
    }
    pub fn selected(mut self, on: bool) -> Self {
        self.selected = on;
        self
    }
    pub fn strong(mut self) -> Self {
        self.strong = true;
        self
    }
    pub fn width(mut self, w: i32) -> Self {
        self.width = Some(w);
        self
    }
}

/// A frame around a group of widgets.
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    pub fill: Option<u32>,
    pub stroke: u32,
    pub width: i32,
    pub pad: i32,
    pub rad: i32,
}

/// The face of a button or drop-down: a step lighter than a card.
fn control(p: &Palette) -> u32 {
    blend(p.surface, p.foreground, 0.07)
}

/// The outline of a control, visible on a card.
fn edge(p: &Palette) -> u32 {
    blend(p.border, p.muted, 0.3)
}

/// Readable text on a coloured fill.
pub fn on(fill: u32) -> u32 {
    if luminance(fill) > 0.5 {
        0x141414
    } else {
        0xf4f4f4
    }
}

pub struct Ui<'a> {
    pub st: &'a mut State,
    pub tx: &'a mut Text,
    pub pal: &'a Palette,
    pub theme: &'a Theme,
    pub sz: Sizes,
    lists: [Vec<Cmd>; 3],
    layer: u8,
    x: i32,
    w: i32,
    y: i32,
    flow: Option<(i32, i32, i32)>,
    items: Vec<(i32, i32, usize, usize)>,
    clip: Rect,
    pub screen: Rect,
    scroll_id: Option<u64>,
    click: Option<(i32, i32)>,
    click_layer: Option<u8>,
    claimed: bool,
    hits: Vec<Hit>,
    regions: Vec<(u64, Rect, i32)>,
    seen: HashMap<u64, u64>,
    pub spacing: i32,
    popup_rect: Option<Rect>,
}

impl Ui<'_> {
    // ----------------------------------------------------------- layout

    pub fn width(&self) -> i32 {
        self.w
    }
    pub fn cursor_y(&self) -> i32 {
        self.y
    }
    pub fn left(&self) -> i32 {
        self.x
    }

    /// Place the following widgets in `r` (absolute), vertically.
    pub fn set_area(&mut self, r: Rect) {
        self.flow = None;
        self.x = r.x;
        self.w = r.w;
        self.y = r.y;
    }

    fn out(&mut self) -> &mut Vec<Cmd> {
        &mut self.lists[self.layer as usize]
    }

    fn id(&mut self, key: &str) -> Id {
        let h = hash(key) ^ ((self.layer as u64) << 56);
        let n = self.seen.entry(h).or_insert(0);
        *n += 1;
        h.wrapping_add(n.wrapping_mul(0x9e37_79b9_7f4a_7c15))
    }

    /// Reserve `w` x `h` pixels: below the previous widget, or to its right
    /// inside a `flow`, wrapping to a new line when the row is full.
    pub fn alloc(&mut self, w: i32, h: i32) -> Rect {
        if let Some((fx, top, lh)) = self.flow {
            let gap = if fx > self.x { 8 } else { 0 };
            let (mut x, mut top, mut lh) = (fx + gap, top, lh);
            if x + w > self.x + self.w && fx > self.x {
                top += lh + 4;
                x = self.x;
                lh = 0;
            }
            self.flow = Some((x + w, top, lh.max(h)));
            let start = self.lists[self.layer as usize].len();
            self.items.push((top, h, start, self.hits.len()));
            Rect::new(x, top, w, h)
        } else {
            let r = Rect::new(self.x, self.y, w, h);
            self.y += h + self.spacing;
            r
        }
    }

    /// Widgets side by side, wrapping like words.
    pub fn flow<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let saved = self.flow.take();
        let saved_items = std::mem::take(&mut self.items);
        self.flow = Some((self.x, self.y, 0));
        let r = f(self);
        self.align_items();
        self.items = saved_items;
        let (_, top, lh) = self.flow.take().unwrap_or((0, self.y, 0));
        self.y = top + lh + self.spacing;
        self.flow = saved;
        r
    }

    /// Centre the items of each finished flow line vertically.
    fn align_items(&mut self) {
        let items = std::mem::take(&mut self.items);
        let layer = self.layer as usize;
        let (cmd_end, hit_end) = (self.lists[layer].len(), self.hits.len());
        for (i, &(top, h, cs, hs)) in items.iter().enumerate() {
            let line_h = items
                .iter()
                .filter(|it| it.0 == top)
                .map(|it| it.1)
                .max()
                .unwrap_or(h);
            let dy = (line_h - h) / 2;
            if dy <= 0 {
                continue;
            }
            let (ce, he) = items
                .get(i + 1)
                .map(|n| (n.2, n.3))
                .unwrap_or((cmd_end, hit_end));
            for c in &mut self.lists[layer][cs..ce.max(cs)] {
                match c {
                    Cmd::Clip(r) | Cmd::Fill(r, _) | Cmd::Tint(r, ..) | Cmd::Box { r, .. } => {
                        r.y += dy
                    }
                    Cmd::Text { y, .. } => *y += dy,
                    Cmd::Nop | Cmd::Unclip(_) => {}
                }
            }
            for hit in &mut self.hits[hs..he.max(hs)] {
                hit.rect.y += dy;
                hit.full.y += dy;
            }
        }
    }

    fn break_flow(&mut self) {
        self.align_items();
        if let Some((fx, top, lh)) = self.flow {
            if fx > self.x {
                self.flow = Some((self.x, top + lh + 4, 0));
            }
        }
    }

    pub fn space(&mut self, h: i32) {
        match self.flow {
            Some((fx, top, lh)) => self.flow = Some((fx + h, top, lh)),
            None => self.y += h,
        }
    }

    /// `n` equal columns from the current line; continues below the tallest.
    pub fn columns(&mut self, n: usize, gap: i32, mut f: impl FnMut(&mut Self, usize)) {
        let n = n.max(1) as i32;
        let cw = ((self.w - gap * (n - 1)) / n).max(1);
        let (x0, w0, y0) = (self.x, self.w, self.y);
        let mut bottom = y0;
        for i in 0..n {
            self.x = x0 + i * (cw + gap);
            self.w = cw;
            self.y = y0;
            f(self, i as usize);
            bottom = bottom.max(self.y);
        }
        self.x = x0;
        self.w = w0;
        self.y = bottom;
    }

    /// Widgets inside a frame as wide as the column.
    pub fn frame<R>(&mut self, fr: Frame, f: impl FnOnce(&mut Self) -> R) -> (R, Rect) {
        self.break_flow();
        let saved_flow = self.flow.take();
        let (x0, w0) = (self.x, self.w);
        let top = match saved_flow {
            Some((_, t, _)) => t,
            None => self.y,
        };
        let idx = self.out().len();
        self.out().push(Cmd::Nop);
        self.x += fr.pad;
        self.w = (self.w - 2 * fr.pad).max(1);
        self.y = top + fr.pad;
        let r = f(self);
        let bottom = self.y - self.spacing + fr.pad;
        let rect = Rect::new(x0, top, w0, (bottom - top).max(2 * fr.pad));
        self.lists[self.layer as usize][idx] = Cmd::Box {
            r: rect,
            rad: fr.rad,
            fill: fr.fill,
            stroke: fr.stroke,
            width: fr.width,
        };
        self.x = x0;
        self.w = w0;
        self.y = rect.bottom() + self.spacing;
        if saved_flow.is_some() {
            self.flow = Some((x0, self.y, 0));
        }
        (r, rect)
    }

    /// A scroll region filling `view`; its widgets move with the offset.
    pub fn scroll<R>(&mut self, key: &str, view: Rect, f: impl FnOnce(&mut Self) -> R) -> R {
        let id = hash(key);
        let off = self.st.scroll.get(&id).copied().unwrap_or(0);
        let (x0, w0, y0, clip0, flow0, sid0) = (
            self.x,
            self.w,
            self.y,
            self.clip,
            self.flow.take(),
            self.scroll_id,
        );
        let inner = view.intersect(&clip0);
        self.clip = inner;
        self.out().push(Cmd::Clip(inner));
        self.scroll_id = Some(id);
        self.x = view.x;
        self.w = (view.w - 12).max(1);
        self.y = view.y - off;
        let r = f(self);
        let content = self.y - self.spacing - (view.y - off);
        let max = (content - view.h).max(0);
        if off > max {
            self.st.scroll.insert(id, max);
            self.st.again = true;
        }
        if max > 0 {
            let track = Rect::new(view.right() - 6, view.y + 2, 4, view.h - 4);
            let th = ((track.h as i64 * view.h as i64) / content.max(1) as i64).max(24) as i32;
            let ty = track.y + ((track.h - th) as i64 * off.min(max) as i64 / max as i64) as i32;
            let c = blend(self.pal.background, self.pal.muted, 0.35);
            self.out().push(Cmd::Box {
                r: Rect::new(track.x, ty, track.w, th),
                rad: 2,
                fill: Some(c),
                stroke: c,
                width: 0,
            });
        }
        self.st.content_h.insert(id, content);
        self.regions.push((id, inner, max));
        self.clip = clip0;
        self.out().push(Cmd::Unclip(clip0));
        self.x = x0;
        self.w = w0;
        self.y = y0;
        self.flow = flow0;
        self.scroll_id = sid0;
        r
    }

    /// A scroll region in the column at most `max_h` high, as tall as its
    /// content otherwise.
    pub fn scroll_max<R>(&mut self, key: &str, max_h: i32, f: impl FnOnce(&mut Self) -> R) -> R {
        let id = hash(key);
        let known = self.st.content_h.get(&id).copied().unwrap_or(max_h);
        let h = known.clamp(1, max_h);
        let view = self.alloc(self.w, h);
        let r = self.scroll(key, view, f);
        let now = self.st.content_h.get(&id).copied().unwrap_or(h);
        if now.clamp(1, max_h) != h {
            self.st.again = true;
        }
        r
    }

    /// The following widgets belong to the modal layer.
    pub fn modal<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let (layer, clip, flow, sid) = (self.layer, self.clip, self.flow.take(), self.scroll_id);
        self.layer = 1;
        self.clip = self.screen;
        self.scroll_id = None;
        let screen = self.screen;
        self.out().push(Cmd::Clip(screen));
        let r = f(self);
        self.layer = layer;
        self.clip = clip;
        self.flow = flow;
        self.scroll_id = sid;
        r
    }

    // ----------------------------------------------------------- painting

    pub fn paint_fill(&mut self, r: Rect, color: u32) {
        self.out().push(Cmd::Fill(r, color));
    }

    pub fn paint_tint(&mut self, r: Rect, color: u32, a: u32) {
        self.out().push(Cmd::Tint(r, color, a));
    }

    pub fn paint_box(&mut self, r: Rect, rad: i32, fill: Option<u32>, stroke: u32, width: i32) {
        self.out().push(Cmd::Box {
            r,
            rad,
            fill,
            stroke,
            width,
        });
    }

    pub fn paint_text(&mut self, x: i32, y: i32, s: &str, sz: Sz, color: u32, bold: bool) -> i32 {
        let size = self.sz.get(sz);
        let w = self.tx.width(s, size) + i32::from(bold);
        self.out().push(Cmd::Text {
            x,
            y,
            s: s.to_string(),
            size,
            color,
            bold,
        });
        w
    }

    pub fn text_width(&mut self, s: &str, sz: Sz) -> i32 {
        let size = self.sz.get(sz);
        self.tx.width(s, size)
    }

    pub fn line_h(&self, sz: Sz) -> i32 {
        self.sz.get(sz).height
    }

    pub fn ellipsize(&mut self, s: &str, sz: Sz, max: i32) -> String {
        let size = self.sz.get(sz);
        self.tx.ellipsize(s, size, max)
    }

    pub fn wrap(&mut self, s: &str, sz: Sz, max: i32) -> Vec<String> {
        let size = self.sz.get(sz);
        self.tx.wrap(s, size, max)
    }

    // ----------------------------------------------------------- input

    fn visible(&self, r: Rect) -> Rect {
        r.intersect(&self.clip)
    }

    /// A click on widget `id`: tested against the place it had on screen
    /// in the previous frame (what the user saw), else against `r`.
    fn clicked_id(&mut self, id: Id, r: Rect) -> bool {
        let seen = self.st.hits.iter().find(|h| h.id == id).map(|h| h.rect);
        match seen {
            Some(v) => self.clicked_at(v),
            None => self.clicked(r),
        }
    }

    fn clicked(&mut self, r: Rect) -> bool {
        let v = self.visible(r);
        self.clicked_at(v)
    }

    fn clicked_at(&mut self, v: Rect) -> bool {
        let Some((x, y)) = self.click else {
            return false;
        };
        if self.claimed || self.click_layer != Some(self.layer) {
            return false;
        }
        if v.contains(x, y) {
            self.claimed = true;
            self.st.again = true;
            return true;
        }
        false
    }

    fn activated(&mut self, id: Id) -> bool {
        if self.st.activate && self.st.focus == Some(id) && self.layer >= self.st.top_layer().min(1)
        {
            self.st.activate = false;
            self.st.again = true;
            return true;
        }
        false
    }

    fn hit(&mut self, id: Id, name: &str, r: Rect, kind: Kind, enabled: bool) {
        let rect = self.visible(r);
        self.hits.push(Hit {
            name: if trace() {
                name.to_string()
            } else {
                String::new()
            },
            id,
            rect,
            full: r,
            layer: self.layer,
            kind,
            enabled,
            scroll: self.scroll_id,
            tip: None,
        });
    }

    fn hovered(&self, id: Id) -> bool {
        self.st.hot == Some(id)
    }

    fn focus_ring(&mut self, id: Id, r: Rect) {
        if self.st.focus == Some(id) && self.st.focus_visible {
            let c = self.pal.accent;
            self.out().push(Cmd::Box {
                r: Rect::new(r.x - 2, r.y - 2, r.w + 4, r.h + 4),
                rad: 5,
                fill: None,
                stroke: c,
                width: 2,
            });
        }
    }

    /// Show `tip` while the pointer rests on the last widget.
    pub fn tooltip(&mut self, tip: &str) {
        if let Some(h) = self.hits.last_mut() {
            h.tip = Some(tip.to_string());
        }
    }

    // ----------------------------------------------------------- widgets

    fn text_cmd(&mut self, x: i32, y: i32, s: &str, size: Size, color: u32, bold: bool) {
        self.out().push(Cmd::Text {
            x,
            y,
            s: s.to_string(),
            size,
            color,
            bold,
        });
    }

    /// Text in the column, wrapped at word boundaries.
    pub fn label(&mut self, s: &str, sz: Sz, color: u32) -> Rect {
        self.label_ex(s, sz, color, false)
    }

    pub fn strong(&mut self, s: &str, sz: Sz, color: u32) -> Rect {
        self.label_ex(s, sz, color, true)
    }

    pub fn label_ex(&mut self, s: &str, sz: Sz, color: u32, bold: bool) -> Rect {
        let size = self.sz.get(sz);
        let tw = self.tx.width(s, size) + i32::from(bold);
        if !s.contains('\n') && tw <= self.w {
            let r = self.alloc(tw, size.height);
            self.text_cmd(r.x, r.y, s, size, color, bold);
            return r;
        }
        let lines = self.tx.wrap(s, size, self.w - i32::from(bold));
        let lh = size.height + 2;
        self.break_flow();
        let h = lines.len() as i32 * lh;
        let r = if let Some((_, top, _)) = self.flow {
            self.flow = Some((self.x, top + h + 4, 0));
            Rect::new(self.x, top, self.w, h)
        } else {
            self.alloc(self.w, h)
        };
        for (i, line) in lines.iter().enumerate() {
            self.text_cmd(r.x, r.y + i as i32 * lh, line, size, color, bold);
        }
        r
    }

    /// A label with a tooltip.
    pub fn label_tip(&mut self, s: &str, sz: Sz, color: u32, tip: &str) -> Rect {
        let r = self.label(s, sz, color);
        let id = self.id(tip);
        self.hit(id, tip, r, Kind::Tip, true);
        self.tooltip(tip);
        r
    }

    pub fn heading(&mut self, s: &str) -> Rect {
        let c = self.pal.foreground;
        self.strong(s, Sz::Heading, c)
    }

    pub fn separator(&mut self) {
        self.break_flow();
        let y = match self.flow {
            Some((_, top, _)) => top,
            None => self.y,
        };
        let r = Rect::new(self.x, y + 2, self.w, 1);
        let c = self.pal.border;
        self.out().push(Cmd::Fill(r, c));
        match self.flow {
            Some((_, top, _)) => self.flow = Some((self.x, top + 6, 0)),
            None => self.y += 5 + self.spacing,
        }
    }

    pub fn button(&mut self, label: &str) -> bool {
        self.button_ex(label, Btn::default())
    }

    pub fn button_ex(&mut self, label: &str, b: Btn) -> bool {
        let size = if b.small { self.sz.small } else { self.sz.body };
        let pad = if b.small { 7 } else { 11 };
        let tw = self.tx.width(label, size) + i32::from(b.strong);
        let h = size.height + if b.small { 6 } else { 10 };
        let w = b.width.unwrap_or(tw + 2 * pad).min(self.w.max(24));
        let r = self.alloc(w, h);
        let id = self.id(label);
        let p = self.pal;
        let base = match (b.fill, b.selected) {
            (Some(c), _) => c,
            (None, true) => p.accent,
            _ => control(p),
        };
        let hover = b.enabled && self.hovered(id);
        let mut bg = if hover {
            if b.fill.is_some() || b.selected {
                blend(base, p.foreground, 0.15)
            } else {
                blend(control(p), p.accent, 0.22)
            }
        } else {
            base
        };
        let mut fg = if b.fill.is_some() || b.selected {
            on(bg)
        } else {
            p.foreground
        };
        let stroke = if hover { p.accent } else { edge(p) };
        if !b.enabled {
            bg = blend(bg, p.background, 0.45);
            fg = p.disabled;
        }
        self.out().push(Cmd::Box {
            r,
            rad: 4,
            fill: Some(bg),
            stroke,
            width: 1,
        });
        let text = self.tx.ellipsize(label, size, r.w - 2 * pad + 4);
        let tw = self.tx.width(&text, size);
        self.text_cmd(
            r.x + (r.w - tw) / 2,
            r.y + (r.h - size.height) / 2,
            &text,
            size,
            fg,
            b.strong,
        );
        self.focus_ring(id, r);
        self.hit(id, label, r, Kind::Button, b.enabled);
        b.enabled && (self.clicked_id(id, r) || self.activated(id))
    }

    pub fn checkbox(&mut self, on_: &mut bool, label: &str) -> bool {
        let size = self.sz.body;
        let tw = self.tx.width(label, size);
        let bx = size.height.max(14);
        let r = self.alloc((bx + 8 + tw).min(self.w), bx);
        let id = self.id(label);
        let p = self.pal;
        let b = Rect::new(r.x, r.y, bx, bx);
        let stroke = if self.hovered(id) { p.accent } else { edge(p) };
        self.out().push(Cmd::Box {
            r: b,
            rad: 3,
            fill: Some(p.panel),
            stroke,
            width: 1,
        });
        if *on_ {
            let inner = Rect::new(b.x + 4, b.y + 4, b.w - 8, b.h - 8);
            let c = p.accent;
            self.out().push(Cmd::Box {
                r: inner,
                rad: 2,
                fill: Some(c),
                stroke: c,
                width: 1,
            });
        }
        let lw = r.w - bx - 8;
        let text = self.tx.ellipsize(label, size, lw);
        self.text_cmd(
            r.x + bx + 8,
            r.y + (bx - size.height) / 2,
            &text,
            size,
            p.foreground,
            false,
        );
        self.focus_ring(id, r);
        self.hit(id, label, r, Kind::Button, true);
        if self.clicked_id(id, r) || self.activated(id) {
            *on_ = !*on_;
            return true;
        }
        false
    }

    pub fn radio(&mut self, selected: bool, label: &str) -> bool {
        let size = self.sz.body;
        let tw = self.tx.width(label, size);
        let bx = size.height.max(14);
        let r = self.alloc((bx + 8 + tw).min(self.w), bx);
        let id = self.id(label);
        let p = self.pal;
        let b = Rect::new(r.x, r.y, bx, bx);
        let stroke = if self.hovered(id) { p.accent } else { edge(p) };
        self.out().push(Cmd::Box {
            r: b,
            rad: bx / 2,
            fill: Some(p.panel),
            stroke,
            width: 1,
        });
        if selected {
            let inner = Rect::new(b.x + 4, b.y + 4, b.w - 8, b.h - 8);
            let c = p.accent;
            self.out().push(Cmd::Box {
                r: inner,
                rad: inner.w / 2,
                fill: Some(c),
                stroke: c,
                width: 1,
            });
        }
        let text = self.tx.ellipsize(label, size, r.w - bx - 8);
        self.text_cmd(
            r.x + bx + 8,
            r.y + (bx - size.height) / 2,
            &text,
            size,
            p.foreground,
            false,
        );
        self.focus_ring(id, r);
        self.hit(id, label, r, Kind::Button, true);
        self.clicked_id(id, r) || self.activated(id)
    }

    /// A drop-down list; returns the newly chosen index.
    pub fn combo(
        &mut self,
        key: &str,
        options: &[&str],
        current: usize,
        width: i32,
    ) -> Option<usize> {
        let size = self.sz.body;
        let h = size.height + 10;
        let r = self.alloc(width.min(self.w), h);
        let id = self.id(key);
        let p = self.pal;
        let open = self.st.popup == Some(id);
        let stroke = if self.hovered(id) || open {
            p.accent
        } else {
            edge(p)
        };
        self.out().push(Cmd::Box {
            r,
            rad: 4,
            fill: Some(control(p)),
            stroke,
            width: 1,
        });
        let cur = options.get(current).copied().unwrap_or("");
        let text = self.tx.ellipsize(cur, size, r.w - 34);
        self.text_cmd(r.x + 9, r.y + 5, &text, size, p.foreground, false);
        self.text_cmd(r.right() - 20, r.y + 5, "▾", size, p.muted, false);
        self.focus_ring(id, r);
        self.hit(id, key, r, Kind::Combo, true);
        let mut result = None;
        if self.clicked_id(id, r) || self.activated(id) {
            if open {
                self.st.popup = None;
            } else {
                self.st.popup = Some(id);
                self.st.popup_hl = current;
                self.st.focus = Some(id);
            }
            self.st.combo_step = 0;
            self.st.popup_choose = false;
        } else if self.st.focus == Some(id) && self.st.combo_step != 0 && !open {
            let n = options.len() as i32;
            if n > 0 {
                let next = (current as i32 + self.st.combo_step).clamp(0, n - 1) as usize;
                if next != current {
                    result = Some(next);
                }
            }
            self.st.combo_step = 0;
            self.st.again = true;
        }
        if self.st.popup == Some(id) {
            let n = options.len();
            if self.st.combo_step != 0 && n > 0 {
                let hl = (self.st.popup_hl as i32 + self.st.combo_step).clamp(0, n as i32 - 1);
                self.st.popup_hl = hl as usize;
                self.st.combo_step = 0;
            }
            let ih = size.height + 10;
            let widest = options
                .iter()
                .map(|o| self.tx.width(o, size))
                .max()
                .unwrap_or(0);
            let pw = (widest + 24).max(r.w).min(self.screen.w - 8);
            let ph = n as i32 * ih + 4;
            let mut py = r.bottom() + 2;
            if py + ph > self.screen.h && r.y - ph - 2 >= 0 {
                py = r.y - ph - 2;
            }
            let px = r.x.min(self.screen.w - pw - 4).max(4);
            let pr = Rect::new(px, py, pw, ph);
            self.popup_rect = Some(pr);
            let saved = self.layer;
            self.layer = 2;
            let clip0 = self.clip;
            self.clip = self.screen;
            let screen = self.screen;
            self.out().push(Cmd::Clip(screen));
            self.out().push(Cmd::Box {
                r: pr,
                rad: 4,
                fill: Some(p.panel),
                stroke: p.accent,
                width: 1,
            });
            let mut chosen = None;
            for (i, o) in options.iter().enumerate() {
                let ir = Rect::new(pr.x + 2, pr.y + 2 + i as i32 * ih, pr.w - 4, ih);
                let hover = ir.contains(self.st.mouse.0, self.st.mouse.1);
                if hover {
                    self.st.popup_hl = i;
                }
                if i == self.st.popup_hl {
                    let c = blend(p.panel, p.accent, 0.35);
                    self.out().push(Cmd::Fill(ir, c));
                }
                let color = if i == current { p.accent } else { p.foreground };
                let t = self.tx.ellipsize(o, size, ir.w - 16);
                self.text_cmd(ir.x + 8, ir.y + 5, &t, size, color, i == current);
                if self.clicked(ir) {
                    chosen = Some(i);
                }
            }
            if self.st.popup_choose {
                chosen = Some(self.st.popup_hl.min(n.saturating_sub(1)));
                self.st.popup_choose = false;
            }
            self.out().push(Cmd::Unclip(clip0));
            self.clip = clip0;
            self.layer = saved;
            if let Some(i) = chosen {
                self.st.popup = None;
                self.st.again = true;
                if i != current {
                    result = Some(i);
                }
            }
        }
        result
    }

    /// A one-line text field; returns true when the text changed.
    pub fn text_edit(&mut self, key: &str, buf: &mut String, hint: &str, width: i32) -> bool {
        let size = self.sz.body;
        let h = size.height + 10;
        let r = self.alloc(width.min(self.w), h);
        let id = self.id(key);
        let p = self.pal;
        let mut changed = false;
        if self.clicked_id(id, r) {
            self.st.focus = Some(id);
            self.st.focus_visible = false;
            // Put the cursor where the click was.
            let mut x = r.x + 8;
            let mut idx = 0;
            let cx = self.click.map(|c| c.0).unwrap_or(0);
            for c in buf.chars() {
                let a = self.tx.advance(c, size).round() as i32;
                if x + a / 2 > cx {
                    break;
                }
                x += a;
                idx += 1;
            }
            self.st.cursor = idx;
        }
        let focused = self.st.focus == Some(id);
        if focused {
            let mut chars: Vec<char> = buf.chars().collect();
            let mut cur = self.st.cursor.min(chars.len());
            for e in std::mem::take(&mut self.st.edits) {
                match e {
                    Edit::Char(c) => {
                        chars.insert(cur, c);
                        cur += 1;
                    }
                    Edit::Paste(s) => {
                        for c in s.chars() {
                            chars.insert(cur, c);
                            cur += 1;
                        }
                    }
                    Edit::Back if cur > 0 => {
                        cur -= 1;
                        chars.remove(cur);
                    }
                    Edit::Del if cur < chars.len() => {
                        chars.remove(cur);
                    }
                    Edit::Left => cur = cur.saturating_sub(1),
                    Edit::Right => cur = (cur + 1).min(chars.len()),
                    Edit::Home => cur = 0,
                    Edit::End => cur = chars.len(),
                    Edit::Clear => {
                        chars.clear();
                        cur = 0;
                    }
                    _ => {}
                }
            }
            let new: String = chars.iter().collect();
            if new != *buf {
                *buf = new;
                changed = true;
                self.st.again = true;
            }
            self.st.cursor = cur;
        }
        let stroke = if focused {
            p.accent
        } else if self.hovered(id) {
            blend(p.border, p.accent, 0.5)
        } else {
            p.border
        };
        self.out().push(Cmd::Box {
            r,
            rad: 4,
            fill: Some(p.panel),
            stroke,
            width: 1,
        });
        let inner = Rect::new(r.x + 8, r.y, r.w - 16, r.h);
        let clip0 = self.clip;
        let tclip = inner.intersect(&clip0);
        self.out().push(Cmd::Clip(tclip));
        if buf.is_empty() && !hint.is_empty() {
            let t = self.tx.ellipsize(hint, size, inner.w);
            self.text_cmd(inner.x, r.y + 5, &t, size, p.disabled, false);
        }
        let before: String = buf
            .chars()
            .take(self.st.cursor.min(buf.chars().count()))
            .collect();
        let cx = self.tx.width(&before, size);
        let shift = if focused {
            (cx - inner.w + 2).max(0)
        } else {
            0
        };
        if !buf.is_empty() {
            self.text_cmd(inner.x - shift, r.y + 5, buf, size, p.foreground, false);
        }
        if focused {
            let c = p.foreground;
            self.out().push(Cmd::Fill(
                Rect::new(inner.x - shift + cx, r.y + 4, 1, r.h - 8),
                c,
            ));
        }
        self.out().push(Cmd::Unclip(clip0));
        self.focus_ring(id, r);
        self.hit(id, key, r, Kind::Text, true);
        changed
    }

    /// A section header that opens and closes; returns whether it is open.
    pub fn collapsing(&mut self, key: &str, title: &str, default_open: bool) -> bool {
        let kid = hash(key);
        let open = *self.st.open.get(&kid).unwrap_or(&default_open);
        let size = self.sz.body;
        let label = format!("{} {title}", if open { "▾" } else { "▸" });
        let tw = self.tx.width(&label, size);
        let r = self.alloc((tw + 8).min(self.w), size.height + 4);
        let id = self.id(key);
        let p = self.pal;
        let color = if self.hovered(id) {
            p.accent
        } else {
            p.foreground
        };
        self.text_cmd(r.x, r.y + 2, &label, size, color, false);
        self.focus_ring(id, r);
        self.hit(id, key, r, Kind::Button, true);
        if self.clicked_id(id, r) || self.activated(id) {
            self.st.open.insert(kid, !open);
            return !open;
        }
        open
    }

    /// Make `r` clickable (a card); returns true when clicked or activated.
    pub fn click_area(&mut self, key: &str, r: Rect) -> bool {
        let id = self.id(key);
        self.focus_ring(id, r);
        self.hit(id, key, r, Kind::Area, true);
        self.clicked_id(id, r) || self.activated(id)
    }

    // ----------------------------------------------------------- finish

    /// Draw the frame and keep what the next frame needs.
    pub fn finish(mut self, cv: &mut Canvas) {
        // Tooltip of the hovered widget, on top of everything.
        let hot_tip = self.st.hot.and_then(|id| {
            self.hits
                .iter()
                .find(|h| h.id == id && h.tip.is_some())
                .and_then(|h| h.tip.clone())
        });
        if let Some(tip) = hot_tip {
            let size = self.sz.small;
            let maxw = (self.screen.w - 24).clamp(80, 460);
            let lines = self.tx.wrap(&tip, size, maxw - 16);
            let tw = lines
                .iter()
                .map(|l| self.tx.width(l, size))
                .max()
                .unwrap_or(0);
            let lh = size.height + 2;
            let (w, h) = (tw + 16, lines.len() as i32 * lh + 10);
            let (mx, my) = self.st.mouse;
            let x = (mx + 12).min(self.screen.w - w - 4).max(2);
            let y = if my + 20 + h > self.screen.h {
                (my - h - 6).max(2)
            } else {
                my + 20
            };
            self.layer = 2;
            let p = self.pal;
            let screen = self.screen;
            self.out().push(Cmd::Clip(screen));
            self.out().push(Cmd::Box {
                r: Rect::new(x, y, w, h),
                rad: 4,
                fill: Some(p.panel),
                stroke: p.border,
                width: 1,
            });
            for (i, l) in lines.iter().enumerate() {
                let fg = p.foreground;
                self.text_cmd(x + 8, y + 5 + i as i32 * lh, l, size, fg, false);
            }
        }
        // A click that hit nothing takes the focus away from a text field.
        if self.click.is_some() && !self.claimed && self.st.typing() {
            self.st.focus = None;
        }
        cv.set_clip(self.screen);
        for list in &self.lists {
            for c in list {
                match c {
                    Cmd::Nop => {}
                    Cmd::Clip(r) | Cmd::Unclip(r) => cv.set_clip(*r),
                    Cmd::Fill(r, c) => cv.fill(*r, *c),
                    Cmd::Tint(r, c, a) => cv.tint(*r, *c, *a),
                    Cmd::Box {
                        r,
                        rad,
                        fill,
                        stroke,
                        width,
                    } => {
                        if let Some(f) = fill {
                            cv.round_fill(*r, *rad, *f);
                        }
                        if *width > 0 {
                            cv.round_frame(*r, *rad, *stroke, *width);
                        }
                    }
                    Cmd::Text {
                        x,
                        y,
                        s,
                        size,
                        color,
                        bold,
                    } => {
                        self.tx.draw(cv, *x, *y, s, *size, *color);
                        if *bold {
                            self.tx.draw(cv, *x + 1, *y, s, *size, *color);
                        }
                    }
                }
            }
            cv.set_clip(self.screen);
        }
        // Keep the keyboard focus visible inside its scroll region.
        if self.st.scroll_to_focus {
            self.st.scroll_to_focus = false;
            if let Some(h) = self
                .st
                .focus
                .and_then(|f| self.hits.iter().find(|h| h.id == f))
            {
                if let Some(sid) = h.scroll {
                    if let Some((_, view, max)) = self.regions.iter().find(|r| r.0 == sid) {
                        let off = self.st.scroll.get(&sid).copied().unwrap_or(0);
                        let mut new = off;
                        if h.full.y < view.y + 4 {
                            new = off - (view.y + 4 - h.full.y);
                        } else if h.full.bottom() > view.bottom() - 4 {
                            new = off + (h.full.bottom() - view.bottom() + 4);
                        }
                        let new = new.clamp(0, *max);
                        if new != off {
                            self.st.scroll.insert(sid, new);
                            self.st.again = true;
                        }
                    }
                }
            }
        }
        if self.st.popup.is_some() && self.popup_rect.is_none() {
            // The drop-down was not drawn this frame (its widget is gone).
            self.st.popup = None;
            self.st.again = true;
        }
        if let Some(r) = self.popup_rect {
            self.st.popup_rect = r;
        }
        if self
            .st
            .focus
            .is_some_and(|f| !self.hits.iter().any(|h| h.id == f))
        {
            self.st.focus = None;
        }
        if trace() {
            eprintln!("ui-frame");
            for h in &self.hits {
                if h.kind != Kind::Tip && h.rect.w > 0 && h.rect.h > 0 {
                    eprintln!(
                        "ui|{}|{}|{}|{}",
                        h.name,
                        h.rect.x + h.rect.w / 2,
                        h.rect.y + h.rect.h / 2,
                        u8::from(h.enabled)
                    );
                }
            }
        }
        self.st.activate = false;
        self.st.combo_step = 0;
        self.st.edits.clear();
        self.st.hits = std::mem::take(&mut self.hits);
        self.st.regions = std::mem::take(&mut self.regions);
        let (mx, my) = self.st.mouse;
        self.st.motion(mx, my);
    }
}
