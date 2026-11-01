//! NIRUX palette resolution for NIRUSEC.
//!
//! A custom user theme wins, then a built-in theme, then sparse appearance
//! overrides. The live watcher only asks for a repaint when a file changes.

use egui::{Color32, Context, Rounding, Stroke};
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Palette {
    pub background: Color32,
    pub surface: Color32,
    pub panel: Color32,
    pub foreground: Color32,
    pub muted: Color32,
    pub border: Color32,
    pub accent: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub error: Color32,
    pub disabled: Color32,
    pub light: bool,
}

#[derive(Clone, Debug)]
pub struct Theme {
    pub name: String,
    pub palette: Palette,
}

const BUILTINS: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "niru-noir",
        "0f0f10",
        "e5e5e5",
        "a8a8a8",
        "2a2a2d",
        "5a5a60",
    ),
    (
        "niru-nord",
        "2e3440",
        "eceff4",
        "9aa5b1",
        "3b4252",
        "88c0d0",
    ),
    (
        "niru-satie",
        "141414",
        "dedad4",
        "8f8b86",
        "2a2724",
        "b08d7d",
    ),
    (
        "niru-carl-larsson",
        "f3ece0",
        "3b3228",
        "7d6f5f",
        "d8cdbb",
        "a63d2f",
    ),
    (
        "niru-forest-vigil",
        "0b100c",
        "d8ded2",
        "96a292",
        "2b362c",
        "8aa87e",
    ),
    (
        "niru-blood-of-urdr",
        "120808",
        "e8d6cf",
        "b09a92",
        "3a1d1b",
        "c96050",
    ),
    (
        "niru-root-and-stone",
        "17100b",
        "eadfd2",
        "b5a08c",
        "3a2a1e",
        "c19768",
    ),
    (
        "niru-blue-horizon",
        "0b1821",
        "dce6eb",
        "93a6b2",
        "243846",
        "86aec8",
    ),
    (
        "niru-the-norns",
        "111110",
        "ece9e4",
        "a6a19b",
        "3b3936",
        "c9c2b9",
    ),
    (
        "niru-winter-nights",
        "1f232b",
        "ead9c3",
        "b9aa9a",
        "4e5157",
        "d8c4aa",
    ),
];

fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        })
}

fn parse_hex(value: &str) -> Option<Color32> {
    let value = value.trim();
    if value.len() != 6 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let n = u32::from_str_radix(value, 16).ok()?;
    Some(Color32::from_rgb(
        ((n >> 16) & 255) as u8,
        ((n >> 8) & 255) as u8,
        (n & 255) as u8,
    ))
}

fn blend(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |a: u8, b: u8| ((a as f32 * (1.0 - t) + b as f32 * t).round()) as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

fn darken(c: Color32, t: f32) -> Color32 {
    blend(c, Color32::BLACK, t)
}

fn build(name: &str, bg: &str, fg: &str, muted: &str, border: &str, focus: &str) -> Theme {
    let background = parse_hex(bg).unwrap_or(Color32::from_rgb(15, 15, 16));
    let foreground = parse_hex(fg).unwrap_or(Color32::from_rgb(229, 229, 229));
    let muted = parse_hex(muted).unwrap_or(Color32::from_rgb(168, 168, 168));
    let border = parse_hex(border).unwrap_or(Color32::from_rgb(42, 42, 45));
    let focus = parse_hex(focus).unwrap_or(Color32::from_rgb(90, 90, 96));
    let light = (0.2126 * background.r() as f32
        + 0.7152 * background.g() as f32
        + 0.0722 * background.b() as f32)
        / 255.0
        > 0.55;
    let surface = blend(background, foreground, if light { 0.055 } else { 0.065 });
    let panel = if light {
        blend(background, Color32::WHITE, 0.22)
    } else {
        darken(background, 0.16)
    };
    let accent = focus;
    Theme {
        name: name.into(),
        palette: Palette {
            background,
            surface,
            panel,
            foreground,
            muted,
            border,
            accent,
            success: if light {
                Color32::from_rgb(47, 111, 65)
            } else {
                Color32::from_rgb(143, 191, 127)
            },
            warning: if light {
                Color32::from_rgb(140, 92, 26)
            } else {
                Color32::from_rgb(215, 179, 106)
            },
            error: if light {
                Color32::from_rgb(155, 55, 55)
            } else {
                Color32::from_rgb(215, 122, 122)
            },
            disabled: blend(muted, background, 0.55),
            light,
        },
    }
}

pub fn load() -> Theme {
    let base = config_home();
    let config = fs::read_to_string(base.join("niruwm/config.toml")).unwrap_or_default();
    let value: toml::Value = config
        .parse()
        .unwrap_or_else(|_| toml::Value::Table(Default::default()));
    let name = value
        .get("theme")
        .and_then(|v| v.as_str())
        .unwrap_or("niru-noir");
    let mut theme = BUILTINS
        .iter()
        .find(|(builtin, ..)| *builtin == name)
        .map(|(name, bg, fg, muted, border, focus)| build(name, bg, fg, muted, border, focus))
        .unwrap_or_else(|| {
            build(
                "niru-noir",
                "0f0f10",
                "e5e5e5",
                "a8a8a8",
                "2a2a2d",
                "5a5a60",
            )
        });
    theme.name = name.into();
    let theme_path = base.join("niruwm/themes").join(format!("{name}.toml"));
    if let Ok(text) = fs::read_to_string(&theme_path) {
        if let Ok(file) = text.parse::<toml::Value>() {
            let get = |key: &str| file.get(key).and_then(|v| v.as_str()).and_then(parse_hex);
            if let Some(c) = get("background") {
                theme.palette.background = c;
            }
            if let Some(c) = get("foreground") {
                theme.palette.foreground = c;
            }
            if let Some(c) = get("muted") {
                theme.palette.muted = c;
            }
            if let Some(c) = get("border") {
                theme.palette.border = c;
            }
            if let Some(c) = get("focus") {
                theme.palette.accent = c;
            }
            let p = &mut theme.palette;
            p.surface = blend(
                p.background,
                p.foreground,
                if p.light { 0.055 } else { 0.065 },
            );
            p.panel = if p.light {
                blend(p.background, Color32::WHITE, 0.22)
            } else {
                darken(p.background, 0.16)
            };
        }
    }
    let appearance_path = base.join("niruwm/appearance.toml");
    if let Ok(text) = fs::read_to_string(&appearance_path) {
        if let Ok(file) = text.parse::<toml::Value>() {
            if let Some(colors) = file.get("colors").and_then(|v| v.as_table()) {
                for (role, value) in colors {
                    let Some(color) = value.as_str().and_then(parse_hex) else {
                        continue;
                    };
                    match role.as_str() {
                        "background" => theme.palette.background = color,
                        "foreground" => theme.palette.foreground = color,
                        "muted" => theme.palette.muted = color,
                        "border" => theme.palette.border = color,
                        "focus" | "accent" => theme.palette.accent = color,
                        "success" => theme.palette.success = color,
                        "warning" => theme.palette.warning = color,
                        "error" => theme.palette.error = color,
                        _ => {}
                    }
                }
            }
        }
    }
    let p = &mut theme.palette;
    p.surface = blend(
        p.background,
        p.foreground,
        if p.light { 0.055 } else { 0.065 },
    );
    p.panel = if p.light {
        blend(p.background, Color32::WHITE, 0.22)
    } else {
        darken(p.background, 0.16)
    };
    p.disabled = blend(p.muted, p.background, 0.55);
    theme
}

pub fn apply(ctx: &Context, theme: &Theme) {
    let p = &theme.palette;
    let mut visuals = if p.light {
        egui::Visuals::light()
    } else {
        egui::Visuals::dark()
    };
    visuals.panel_fill = p.background;
    visuals.window_fill = p.background;
    visuals.extreme_bg_color = p.panel;
    visuals.faint_bg_color = p.surface;
    visuals.code_bg_color = p.panel;
    visuals.selection.bg_fill = p.accent;
    visuals.selection.stroke = Stroke::new(1.0_f32, p.foreground);
    visuals.widgets.noninteractive.bg_fill = p.panel;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.border);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, p.foreground);
    visuals.widgets.inactive.bg_fill = p.surface;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.border);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, p.foreground);
    visuals.widgets.hovered.bg_fill = blend(p.surface, p.accent, 0.22);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.accent);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, p.foreground);
    visuals.widgets.active.bg_fill = blend(p.surface, p.accent, 0.35);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, p.accent);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, p.foreground);
    visuals.window_rounding = Rounding::same(6.0);
    visuals.menu_rounding = Rounding::same(4.0);
    ctx.set_visuals(visuals);
}

fn signature() -> u64 {
    let base = config_home();
    let mut hash = 0u64;
    for path in [
        base.join("niruwm/config.toml"),
        base.join("niruwm/appearance.toml"),
        base.join("niruwm/themes"),
    ] {
        if let Ok(meta) = fs::metadata(&path) {
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            hash = hash.rotate_left(7) ^ modified;
        }
    }
    hash
}

pub struct Watcher {
    rx: Receiver<Theme>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Watcher {
    pub fn start(ctx: Context) -> Self {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("nirusec-theme".into())
            .spawn(move || {
                let mut last = signature();
                while !thread_stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(2));
                    let now = signature();
                    if now != last {
                        last = now;
                        if tx.send(load()).is_err() {
                            break;
                        }
                        ctx.request_repaint();
                    }
                }
            })
            .ok();
        Self { rx, stop, handle }
    }

    pub fn poll(&self) -> Option<Theme> {
        self.rx.try_recv().ok()
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
