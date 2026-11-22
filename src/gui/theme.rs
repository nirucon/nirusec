//! NIRUX palette resolution.
//!
//! The same contract as before the port and as the other NIRU components:
//! the theme NIRUWM publishes as `_NIRUWM_THEME` on the root window (else
//! `theme` in `~/.config/niruwm/config.toml`), a user theme file
//! `~/.config/niruwm/themes/NAME.toml` (top-level keys or a `[colors]`
//! table) over the built-in palette, then the `[colors]` overrides of
//! `~/.config/niruwm/appearance.toml`. The caller reloads it when inotify
//! reports a change in `~/.config/niruwm` or the root property changes.
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub struct Palette {
    pub background: u32,
    pub surface: u32,
    pub panel: u32,
    pub foreground: u32,
    pub muted: u32,
    pub border: u32,
    pub accent: u32,
    pub success: u32,
    pub warning: u32,
    pub error: u32,
    pub disabled: u32,
    pub light: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Theme {
    pub name: String,
    pub palette: Palette,
    pub font_px: f32,
    pub font_path: Option<String>,
}

const BUILTINS: &[(&str, u32, u32, u32, u32, u32)] = &[
    (
        "niru-noir",
        0x0f0f10,
        0xe5e5e5,
        0xa8a8a8,
        0x2a2a2d,
        0x5a5a60,
    ),
    (
        "niru-nord",
        0x2e3440,
        0xeceff4,
        0x9aa5b1,
        0x3b4252,
        0x88c0d0,
    ),
    (
        "niru-satie",
        0x141414,
        0xdedad4,
        0x8f8b86,
        0x2a2724,
        0xb08d7d,
    ),
    (
        "niru-carl-larsson",
        0xf3ece0,
        0x3b3228,
        0x7d6f5f,
        0xd8cdbb,
        0xa63d2f,
    ),
    (
        "niru-forest-vigil",
        0x0b100c,
        0xd8ded2,
        0x96a292,
        0x2b362c,
        0x8aa87e,
    ),
    (
        "niru-blood-of-urdr",
        0x120808,
        0xe8d6cf,
        0xb09a92,
        0x3a1d1b,
        0xc96050,
    ),
    (
        "niru-root-and-stone",
        0x17100b,
        0xeadfd2,
        0xb5a08c,
        0x3a2a1e,
        0xc19768,
    ),
    (
        "niru-blue-horizon",
        0x0b1821,
        0xdce6eb,
        0x93a6b2,
        0x243846,
        0x86aec8,
    ),
    (
        "niru-the-norns",
        0x111110,
        0xece9e4,
        0xa6a19b,
        0x3b3936,
        0xc9c2b9,
    ),
    (
        "niru-winter-nights",
        0x1f232b,
        0xead9c3,
        0xb9aa9a,
        0x4e5157,
        0xd8c4aa,
    ),
];

pub fn blend(a: u32, b: u32, t: f32) -> u32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u32, y: u32| {
        let x = (x & 0xff) as f32;
        let y = (y & 0xff) as f32;
        (x * (1.0 - t) + y * t).round().clamp(0.0, 255.0) as u32
    };
    (mix(a >> 16, b >> 16) << 16) | (mix(a >> 8, b >> 8) << 8) | mix(a, b)
}

pub fn luminance(c: u32) -> f32 {
    let r = ((c >> 16) & 0xff) as f32 / 255.0;
    let g = ((c >> 8) & 0xff) as f32 / 255.0;
    let b = (c & 0xff) as f32 / 255.0;
    0.2126 * r + 0.7152 * g + 0.0722 * b
}

fn derive(p: &mut Palette) {
    p.light = luminance(p.background) > 0.55;
    p.surface = blend(
        p.background,
        p.foreground,
        if p.light { 0.055 } else { 0.065 },
    );
    p.panel = if p.light {
        blend(p.background, 0xffffff, 0.22)
    } else {
        blend(p.background, 0x000000, 0.16)
    };
    p.disabled = blend(p.muted, p.background, 0.55);
}

fn build(bg: u32, fg: u32, muted: u32, border: u32, focus: u32) -> Palette {
    let light = luminance(bg) > 0.55;
    let mut p = Palette {
        background: bg,
        surface: 0,
        panel: 0,
        foreground: fg,
        muted,
        border,
        accent: focus,
        success: if light { 0x2f6f41 } else { 0x8fbf7f },
        warning: if light { 0x8c5c1a } else { 0xd7b36a },
        error: if light { 0x9b3737 } else { 0xd77a7a },
        disabled: 0,
        light,
    };
    derive(&mut p);
    p
}

pub fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(".config"))
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn parse_hex(s: &str) -> Option<u32> {
    let s = s.trim().trim_start_matches('#');
    (s.len() == 6 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(s, 16).ok())
        .flatten()
}

fn read_toml(path: &Path) -> Option<toml::Value> {
    std::fs::read_to_string(path)
        .ok()?
        .parse::<toml::Value>()
        .ok()
}

/// The directory to watch for theme changes.
pub fn watch_dirs() -> Vec<PathBuf> {
    let base = config_home().join("niruwm");
    vec![base.join("themes"), base]
}

/// `root` is the theme NIRUWM publishes on the root window, if any.
pub fn load(root: Option<&str>) -> Theme {
    load_from(&config_home(), root)
}

pub fn load_from(base: &Path, root: Option<&str>) -> Theme {
    let config = read_toml(&base.join("niruwm/config.toml"));
    let name = root
        .map(str::to_string)
        .or_else(|| {
            config
                .as_ref()
                .and_then(|v| v.get("theme")?.as_str().map(str::to_string))
        })
        .unwrap_or_else(|| "niru-noir".to_string());
    let (_, bg, fg, muted, border, focus) = BUILTINS
        .iter()
        .find(|(n, ..)| *n == name)
        .copied()
        .unwrap_or(BUILTINS[0]);
    let mut palette = build(bg, fg, muted, border, focus);
    if let Some(file) = read_toml(&base.join("niruwm/themes").join(format!("{name}.toml"))) {
        let table = file.get("colors").unwrap_or(&file);
        let get = |key: &str| table.get(key).and_then(|v| v.as_str()).and_then(parse_hex);
        let p = &mut palette;
        if let Some(c) = get("background") {
            p.background = c;
        }
        if let Some(c) = get("foreground") {
            p.foreground = c;
        }
        if let Some(c) = get("muted") {
            p.muted = c;
        }
        if let Some(c) = get("border") {
            p.border = c;
        }
        if let Some(c) = get("focus").or_else(|| get("accent")) {
            p.accent = c;
        }
    }
    if let Some(file) = read_toml(&base.join("niruwm/appearance.toml")) {
        if let Some(colors) = file.get("colors").and_then(|v| v.as_table()) {
            for (role, value) in colors {
                let Some(color) = value.as_str().and_then(parse_hex) else {
                    continue;
                };
                let p = &mut palette;
                match role.as_str() {
                    "background" => p.background = color,
                    "foreground" => p.foreground = color,
                    "muted" => p.muted = color,
                    "border" => p.border = color,
                    "focus" | "accent" => p.accent = color,
                    "success" => p.success = color,
                    "warning" => p.warning = color,
                    "error" => p.error = color,
                    _ => {}
                }
            }
        }
    }
    derive(&mut palette);
    let font_size = config.as_ref().and_then(|v| {
        let s = v.get("font_size")?;
        s.as_float()
            .or_else(|| s.as_integer().map(|i| i as f64))
            .map(|f| f as f32)
            .filter(|f| (8.0..=40.0).contains(f))
    });
    let font_path = config.as_ref().and_then(|v| {
        let p = v.get("font_path")?.as_str()?;
        let p = p
            .strip_prefix("~/")
            .map_or_else(|| PathBuf::from(p), |rest| home().join(rest));
        p.is_file().then(|| p.to_string_lossy().into_owned())
    });
    Theme {
        name,
        palette,
        // NIRUWM's font_size is in points; the body text is a little larger
        // than the bar so forms stay readable.
        font_px: font_size.map(|s| (s * 1.25).round()).unwrap_or(14.0),
        font_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("niru-theme-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("niruwm/themes")).unwrap();
        d
    }

    #[test]
    fn builtins_load_and_carl_larsson_is_light() {
        let d = dir("builtin");
        std::fs::write(
            d.join("niruwm/config.toml"),
            "theme = \"niru-carl-larsson\"\n",
        )
        .unwrap();
        let t = load_from(&d, None);
        assert_eq!(t.name, "niru-carl-larsson");
        assert!(t.palette.light);
        assert_eq!(t.palette.background, 0xf3ece0);
        let t = load_from(&d, Some("niru-nord"));
        assert_eq!(t.palette.accent, 0x88c0d0);
        assert!(!t.palette.light);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn user_theme_and_appearance_overrides_apply() {
        let d = dir("user");
        std::fs::write(
            d.join("niruwm/config.toml"),
            "theme = \"mine\"\nfont_size = 12\n",
        )
        .unwrap();
        std::fs::write(
            d.join("niruwm/themes/mine.toml"),
            "background = \"101010\"\nfocus = \"ff8800\"\n",
        )
        .unwrap();
        std::fs::write(
            d.join("niruwm/appearance.toml"),
            "[colors]\nerror = \"#aa0000\"\n",
        )
        .unwrap();
        let t = load_from(&d, None);
        assert_eq!(t.palette.background, 0x101010);
        assert_eq!(t.palette.accent, 0xff8800);
        assert_eq!(t.palette.error, 0xaa0000);
        assert_eq!(t.font_px, 15.0);
        std::fs::remove_dir_all(d).unwrap();
    }
}
