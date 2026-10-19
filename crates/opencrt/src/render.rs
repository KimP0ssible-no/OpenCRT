//! CPU rasteriser for the terminal grid: a system monospace font through
//! fontdue, a glyph cache, and an RGBA pixel buffer as output.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::anyhow;
use fontdue::{Font, FontSettings, Metrics};

use crate::terminal::{CursorMark, Rgb, Terminal};

/// Font size in logical pixels before display scaling.
pub const FONT_PX: f32 = 15.0;

struct Glyph {
    metrics: Metrics,
    coverage: Vec<u8>,
}

pub struct Renderer {
    regular: Font,
    bold: Option<Font>,
    /// Searched in order for glyphs the main font lacks (CJK, symbols). Loaded on
    /// the first missing glyph: CJK fonts are large and slow to parse.
    fallbacks: Option<Vec<Font>>,
    px: f32,
    pub cell_w: usize,
    pub cell_h: usize,
    ascent: i32,
    cache: HashMap<(char, bool), Glyph>,
    /// Keyword sets by name ("" is the default set), and the ad hoc words
    /// highlighted on top of every set.
    keywords: HashMap<String, Vec<Keyword>>,
    adhoc: Vec<Keyword>,
    /// The Find bar's text and whether case must match, while it is open.
    find: Option<(Vec<char>, bool)>,
}

/// Keyword highlight colours: dark text on amber, readable on every scheme.
const HIGHLIGHT_FG: Rgb = [0x1a, 0x1a, 0x1a];
const HIGHLIGHT_BG: Rgb = [0xff, 0xc8, 0x3d];

/// Other keyword colours (`error = red`): name, text, background.
const KEYWORD_COLORS: [(&str, Rgb, Rgb); 5] = [
    ("red", [0xff, 0xff, 0xff], [0xd1, 0x34, 0x38]),
    ("orange", [0x1a, 0x1a, 0x1a], [0xf7, 0x8c, 0x30]),
    ("green", [0xff, 0xff, 0xff], [0x10, 0x7c, 0x10]),
    ("blue", [0xff, 0xff, 0xff], [0x00, 0x78, 0xd4]),
    ("purple", [0xff, 0xff, 0xff], [0x88, 0x17, 0x98]),
];

#[derive(Clone, Debug)]
enum Pattern {
    /// Lowercased; matched ignoring case.
    Word(Vec<char>),
    Regex(regex::Regex),
}

/// Something to highlight, its colours, and whether the whole line is marked.
#[derive(Clone, Debug)]
pub struct Keyword {
    pattern: Pattern,
    fg: Rgb,
    bg: Rgb,
    line: bool,
}

/// A keyword line: `word` or `/regex/` (both ignore case), optionally
/// followed by `= colour` (from KEYWORD_COLORS) and/or `line` to mark the
/// whole line: `/link (down|flap)/ = red line`. Invalid regexes are skipped.
fn parse_keyword(line: &str) -> Option<Keyword> {
    let colour = |w: &str| KEYWORD_COLORS.iter().find(|(n, ..)| n.eq_ignore_ascii_case(w));
    let (pattern, options) = match line.rsplit_once('=') {
        Some((p, o)) if !o.trim().is_empty() && o.split_whitespace().all(|w| w.eq_ignore_ascii_case("line") || colour(w).is_some()) => (p, o),
        _ => (line, ""),
    };
    let (fg, bg) = options.split_whitespace().find_map(colour).map_or((HIGHLIGHT_FG, HIGHLIGHT_BG), |(_, fg, bg)| (*fg, *bg));
    let pattern = pattern.trim();
    let pattern = match pattern.strip_prefix('/').and_then(|p| p.strip_suffix('/')) {
        Some(re) if !re.is_empty() => Pattern::Regex(regex::RegexBuilder::new(re).case_insensitive(true).build().ok()?),
        _ if pattern.is_empty() => return None,
        _ => Pattern::Word(pattern.chars().flat_map(char::to_lowercase).collect()),
    };
    let line = options.split_whitespace().any(|w| w.eq_ignore_ascii_case("line"));
    Some(Keyword { pattern, fg, bg, line })
}

/// Keyword list lines (see `parse_keyword`) by set: a `[name]` line starts a
/// named set; lines before any are the default set, "".
pub fn keyword_sets(lines: &[String]) -> HashMap<String, Vec<Keyword>> {
    let mut sets = HashMap::from([(String::new(), Vec::new())]);
    let mut current = String::new();
    for line in lines {
        match line.trim().strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            Some(name) => {
                current = name.trim().to_string();
                sets.entry(current.clone()).or_default();
            }
            None => sets.entry(current.clone()).or_default().extend(parse_keyword(line)),
        }
    }
    sets
}

/// The named keyword sets in `lines`, in order (for the session's choice).
pub fn keyword_set_names(lines: &[String]) -> Vec<String> {
    lines.iter().filter_map(|l| l.trim().strip_prefix('[')?.strip_suffix(']').map(|n| n.trim().to_string())).collect()
}

/// Find highlight colours: dark text on light blue, apart from keyword amber.
const FIND_FG: Rgb = [0x10, 0x10, 0x10];
const FIND_BG: Rgb = [0x8c, 0xc8, 0xff];

/// Column ranges in `line` where `needle` appears, ignoring case unless `exact`.
fn find_spans(line: &[char], needle: &[char], exact: bool) -> Vec<(usize, usize)> {
    let fold = |c: &char| if exact { *c } else { c.to_lowercase().next().unwrap_or(*c) };
    let (line, needle): (Vec<char>, Vec<char>) = (line.iter().map(fold).collect(), needle.iter().map(fold).collect());
    if needle.is_empty() {
        return Vec::new();
    }
    (0..line.len()).filter(|&i| line[i..].starts_with(&needle)).map(|i| (i, i + needle.len())).collect()
}

/// Column ranges in `line` where any keyword matches (case-insensitive), with
/// that keyword's colours; whole-line marks come first so matches show over them.
fn keyword_spans<'a>(line: &[char], keywords: impl IntoIterator<Item = &'a Keyword>) -> Vec<((usize, usize), Rgb, Rgb)> {
    let lower: Vec<char> = line.iter().map(|c| c.to_lowercase().next().unwrap_or(*c)).collect();
    let text: String = line.iter().collect();
    let (mut lines, mut spans) = (Vec::new(), Vec::new());
    for k in keywords {
        let found: Vec<(usize, usize)> = match &k.pattern {
            Pattern::Word(word) => {
                (0..lower.len()).filter(|&i| lower[i..].starts_with(word)).map(|i| (i, i + word.len())).collect()
            }
            Pattern::Regex(re) => re
                .find_iter(&text)
                .filter(|m| !m.is_empty())
                .map(|m| (text[..m.start()].chars().count(), text[..m.end()].chars().count()))
                .collect(),
        };
        if k.line && !found.is_empty() {
            lines.push(((0, line.len()), k.fg, k.bg));
        } else {
            spans.extend(found.into_iter().map(|s| (s, k.fg, k.bg)));
        }
    }
    spans.sort_by_key(|(s, ..)| *s);
    lines.extend(spans);
    lines
}

impl Renderer {
    /// Load the named system font (or the first one installed) at `px` physical pixels.
    pub fn new(font: &str, px: f32) -> anyhow::Result<Self> {
        let (regular, bold) = load_mono(font).ok_or_else(|| {
            let names: Vec<&str> = MONO_FONTS.iter().map(|f| f.name).collect();
            anyhow!("no monospace font found; looked for {}", names.join(", "))
        })?;
        let mut renderer = Self {
            regular,
            bold,
            fallbacks: None,
            keywords: HashMap::new(),
            adhoc: Vec::new(),
            find: None,
            px: 0.0,
            cell_w: 1,
            cell_h: 1,
            ascent: 0,
            cache: HashMap::new(),
        };
        renderer.set_px(px);
        Ok(renderer)
    }

    /// The keyword list (see `keyword_sets`); blank entries are ignored.
    pub fn set_keywords(&mut self, lines: &[String]) {
        self.keywords = keyword_sets(lines);
    }

    /// Words highlighted in blue over every keyword set.
    pub fn set_adhoc(&mut self, words: &[String]) {
        self.adhoc = words.iter().filter_map(|w| parse_keyword(&format!("{w} = blue"))).collect();
    }

    /// Highlight every visible match of the Find text; None turns it off.
    /// Returns whether anything changed (the screen then needs repainting).
    pub fn set_find(&mut self, find: Option<(&str, bool)>) -> bool {
        let find = find.filter(|(text, _)| !text.is_empty()).map(|(text, exact)| (text.chars().collect(), exact));
        std::mem::replace(&mut self.find, find.clone()) != find
    }

    /// Switch to another installed terminal font, keeping the size.
    pub fn set_font(&mut self, font: &str) {
        if let Some((regular, bold)) = load_mono(font) {
            (self.regular, self.bold) = (regular, bold);
            let px = std::mem::take(&mut self.px);
            self.set_px(px);
        }
    }

    /// Change the font size (e.g. on a DPI change); clears the glyph cache.
    pub fn set_px(&mut self, px: f32) {
        if px == self.px {
            return;
        }
        self.px = px;
        self.cache.clear();
        let line = self.regular.horizontal_line_metrics(px);
        let (ascent, descent, gap) = line.map_or((px * 0.8, -px * 0.2, 0.0), |l| (l.ascent, l.descent, l.line_gap));
        self.ascent = ascent.round() as i32;
        self.cell_h = (ascent - descent + gap).ceil().max(1.0) as usize;
        self.cell_w = self.regular.metrics('M', px).advance_width.round().max(1.0) as usize;
    }

    fn glyph(&mut self, c: char, bold: bool) -> &Glyph {
        let px = self.px;
        let in_regular = self.regular.lookup_glyph_index(c) != 0;
        if !in_regular && self.fallbacks.is_none() && !self.cache.contains_key(&(c, bold)) {
            self.fallbacks = Some(FALLBACKS.iter().filter_map(|name| load_first(&[name])).collect());
        }
        let font = if in_regular {
            match &self.bold {
                Some(b) if bold => b,
                _ => &self.regular,
            }
        } else {
            let fallbacks = self.fallbacks.as_deref().unwrap_or_default();
            fallbacks.iter().find(|f| f.lookup_glyph_index(c) != 0).unwrap_or(&self.regular)
        };
        self.cache.entry((c, bold)).or_insert_with(|| {
            let (metrics, coverage) = font.rasterize(c, px);
            Glyph { metrics, coverage }
        })
    }

    /// Paint `term` into `pixels` (RGBA, `width` x `height`). Cells outside the
    /// buffer are clipped; the area past the last cell is filled with the background.
    /// Draw `term`, highlighting the keyword set named `keyword_set` (the default set if unknown).
    pub fn render(&mut self, term: &Terminal, keyword_set: &str, focused: bool, pixels: &mut [u8], width: usize, height: usize) {
        let mut canvas = Canvas { pixels, width, height };
        let (fg, bg) = (term.colours().fg, term.colours().bg);
        canvas.fill(0, 0, width, height, bg);
        let (cw, ch) = (self.cell_w, self.cell_h);
        let has_synthetic_bold = self.bold.is_none();

        let mut cells = Vec::new();
        term.for_each_cell(focused, |cell| cells.push(cell.clone()));
        let keywords = self.keywords.get(keyword_set).or_else(|| self.keywords.get("")).map_or(&[][..], Vec::as_slice);
        if !keywords.is_empty() || !self.adhoc.is_empty() || self.find.is_some() {
            let width = term.size().0;
            let mut line = vec![' '; width];
            for row in cells.chunk_by_mut(|a, b| a.row == b.row) {
                line.fill(' ');
                for cell in row.iter().filter(|c| c.col < width) {
                    line[cell.col] = cell.c;
                }
                let found = self.find.as_ref().map(|(needle, exact)| find_spans(&line, needle, *exact)).unwrap_or_default();
                let marks = keyword_spans(&line, keywords.iter().chain(&self.adhoc));
                for ((start, end), fg, bg) in marks.into_iter().chain(found.into_iter().map(|s| (s, FIND_FG, FIND_BG))) {
                    // The selection (e.g. the current Find match) keeps its own colours.
                    for cell in row.iter_mut().filter(|c| (start..end).contains(&c.col) && !c.selected) {
                        (cell.fg, cell.bg) = (fg, bg);
                    }
                }
            }
        }

        for cell in &cells {
            let x = cell.col * cw;
            let y = cell.row * ch;
            let w = if cell.wide { cw * 2 } else { cw };
            if cell.bg != bg {
                canvas.fill(x, y, w, ch, cell.bg);
            }
            if cell.c != ' ' {
                let baseline = y as i32 + self.ascent;
                let glyph = self.glyph(cell.c, cell.bold);
                canvas.blit(glyph, x as i32, baseline, cell.fg, cell.italic);
                if cell.bold && has_synthetic_bold {
                    canvas.blit(glyph, x as i32 + 1, baseline, cell.fg, cell.italic);
                }
            }
            let line = (self.px / 14.0).round().max(1.0) as usize;
            if cell.underline {
                canvas.fill(x, (y + ch).saturating_sub(line + 1), w, line, cell.fg);
            }
            if cell.strike {
                canvas.fill(x, y + ch / 2, w, line, cell.fg);
            }
        }

        if let Some((row, col, mark)) = term.cursor_mark(focused) {
            let fg = term.colours().cursor.unwrap_or(fg);
            let (x, y) = (col * cw, row * ch);
            let t = (self.px / 8.0).round().max(1.0) as usize;
            match mark {
                CursorMark::Beam => canvas.fill(x, y, t, ch, fg),
                CursorMark::Underline => canvas.fill(x, y + ch - t, cw, t, fg),
                CursorMark::Hollow => {
                    canvas.fill(x, y, cw, 1, fg);
                    canvas.fill(x, y + ch - 1, cw, 1, fg);
                    canvas.fill(x, y, 1, ch, fg);
                    canvas.fill(x + cw - 1, y, 1, ch, fg);
                }
            }
        }
    }
}

struct Canvas<'a> {
    pixels: &'a mut [u8],
    width: usize,
    height: usize,
}

impl Canvas<'_> {
    fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, color: Rgb) {
        let x1 = (x + w).min(self.width);
        for row in y.min(self.height)..(y + h).min(self.height) {
            for col in x.min(x1)..x1 {
                let i = (row * self.width + col) * 4;
                self.pixels[i..i + 4].copy_from_slice(&[color[0], color[1], color[2], 255]);
            }
        }
    }

    /// Alpha-blend a glyph's coverage in `color`, origin at (`x`, `baseline`).
    /// `slant` fakes italics by shearing rows above the baseline to the right.
    fn blit(&mut self, glyph: &Glyph, x: i32, baseline: i32, color: Rgb, slant: bool) {
        let m = &glyph.metrics;
        let left = x + m.xmin;
        let top = baseline - m.ymin - m.height as i32;
        for gy in 0..m.height {
            let py = top + gy as i32;
            if py < 0 || py >= self.height as i32 {
                continue;
            }
            let shear = if slant { ((baseline - py) as f32 * 0.2).round() as i32 } else { 0 };
            for gx in 0..m.width {
                let px = left + gx as i32 + shear;
                let a = glyph.coverage[gy * m.width + gx] as u16;
                if a == 0 || px < 0 || px >= self.width as i32 {
                    continue;
                }
                let i = (py as usize * self.width + px as usize) * 4;
                for (dst, &src) in self.pixels[i..i + 3].iter_mut().zip(&color) {
                    *dst = ((src as u16 * a + *dst as u16 * (255 - a)) / 255) as u8;
                }
            }
        }
    }
}

/// A terminal font choice: its name and where its regular and bold faces live.
struct MonoFont {
    name: &'static str,
    regular: &'static [&'static str],
    bold: &'static [&'static str],
}

/// Terminal fonts offered in Global Options, in order of preference.
#[cfg(windows)]
const MONO_FONTS: &[MonoFont] = &[
    MonoFont { name: "Consolas", regular: &["consola.ttf"], bold: &["consolab.ttf"] },
    MonoFont { name: "Cascadia Mono", regular: &["CascadiaMono.ttf"], bold: &[] },
    MonoFont { name: "Lucida Console", regular: &["lucon.ttf"], bold: &[] },
    MonoFont { name: "Courier New", regular: &["cour.ttf"], bold: &["courbd.ttf"] },
];
#[cfg(windows)]
const FALLBACKS: &[&str] = &["msgothic.ttc", "msyh.ttc", "malgun.ttf", "seguisym.ttf", "segoeui.ttf"];

#[cfg(target_os = "macos")]
const MONO_FONTS: &[MonoFont] = &[
    MonoFont { name: "Menlo", regular: &["/System/Library/Fonts/Menlo.ttc"], bold: &[] },
    MonoFont { name: "Monaco", regular: &["/System/Library/Fonts/Monaco.ttf"], bold: &[] },
    MonoFont {
        name: "Courier New",
        regular: &["/System/Library/Fonts/Supplemental/Courier New.ttf"],
        bold: &["/System/Library/Fonts/Supplemental/Courier New Bold.ttf"],
    },
];
#[cfg(target_os = "macos")]
const FALLBACKS: &[&str] = &[
    "/System/Library/Fonts/Hiragino Sans GB.ttc",
    "/System/Library/Fonts/AppleSDGothicNeo.ttc",
    "/System/Library/Fonts/Apple Symbols.ttf",
];

#[cfg(all(unix, not(target_os = "macos")))]
const MONO_FONTS: &[MonoFont] = &[
    MonoFont {
        name: "DejaVu Sans Mono",
        regular: &[
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf",
            "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        ],
        bold: &[
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
            "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono-Bold.ttf",
            "/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf",
        ],
    },
    MonoFont {
        name: "Liberation Mono",
        regular: &[
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
            "/usr/share/fonts/liberation-mono/LiberationMono-Regular.ttf",
        ],
        bold: &[
            "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
            "/usr/share/fonts/liberation-mono/LiberationMono-Bold.ttf",
        ],
    },
    MonoFont {
        name: "Ubuntu Mono",
        regular: &["/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf"],
        bold: &["/usr/share/fonts/truetype/ubuntu/UbuntuMono-B.ttf"],
    },
];
#[cfg(all(unix, not(target_os = "macos")))]
const FALLBACKS: &[&str] = &[
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
];

#[cfg(windows)]
const UI_FONTS: &[&str] = &["segoeui.ttf", "tahoma.ttf", "arial.ttf"];
#[cfg(target_os = "macos")]
const UI_FONTS: &[&str] = &["/System/Library/Fonts/SFNS.ttf", "/System/Library/Fonts/Helvetica.ttc"];
#[cfg(all(unix, not(target_os = "macos")))]
const UI_FONTS: &[&str] = &[
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
];

/// Render `text` in the UI font rotated 90° clockwise (reading top to bottom),
/// as (width, height, RGBA) with a transparent background. The software renderer
/// cannot rotate text itself; this feeds the vertical dock tabs.
pub fn vertical_label(text: &str, px: f32, color: Rgb) -> Option<(usize, usize, Vec<u8>)> {
    let font = load_first(UI_FONTS)?;
    let line = font.horizontal_line_metrics(px)?;
    let ascent = line.ascent.round() as i32;
    let h = (line.ascent - line.descent).ceil() as usize;
    let glyphs: Vec<_> = text.chars().map(|c| font.rasterize(c, px)).collect();
    let w = glyphs.iter().map(|(m, _)| m.advance_width).sum::<f32>().ceil() as usize + 1;

    // Lay the text out horizontally as coverage, then rotate while colouring.
    let mut coverage = vec![0u8; w * h];
    let mut pen = 0.0f32;
    for (m, bitmap) in &glyphs {
        let left = pen.round() as i32 + m.xmin;
        let top = ascent - m.ymin - m.height as i32;
        for gy in 0..m.height {
            for gx in 0..m.width {
                let (x, y) = (left + gx as i32, top + gy as i32);
                if (0..w as i32).contains(&x) && (0..h as i32).contains(&y) {
                    let dst = &mut coverage[y as usize * w + x as usize];
                    *dst = (*dst).max(bitmap[gy * m.width + gx]);
                }
            }
        }
        pen += m.advance_width;
    }
    // Clockwise: output pixel (x, y) comes from input (y, h - 1 - x).
    let mut rgba = vec![0u8; w * h * 4];
    for y in 0..w {
        for x in 0..h {
            let a = coverage[(h - 1 - x) * w + y];
            let i = (y * h + x) * 4;
            rgba[i..i + 4].copy_from_slice(&[color[0], color[1], color[2], a]);
        }
    }
    Some((h, w, rgba))
}

/// Resolve a font name: absolute paths as-is, bare names in the Windows font folder.
fn font_path(name: &str) -> PathBuf {
    let path = PathBuf::from(name);
    if path.is_absolute() {
        return path;
    }
    let windir = std::env::var_os("WINDIR").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    windir.join("Fonts").join(name)
}

/// The default terminal font, built into OpenCRT (SIL OFL 1.1, see ui/fonts/OFL.txt).
const BUILT_IN_FONT: &str = "IBM Plex Mono";

fn built_in_font() -> Option<(Font, Option<Font>)> {
    let face = |bytes: &[u8]| Font::from_bytes(bytes, FontSettings::default()).ok();
    let regular = face(include_bytes!("../ui/fonts/IBMPlexMono-Regular.ttf"))?;
    Some((regular, face(include_bytes!("../ui/fonts/IBMPlexMono-Bold.ttf"))))
}

/// The built-in terminal font, then the ones installed on this machine.
pub fn available_fonts() -> Vec<&'static str> {
    let installed = MONO_FONTS.iter().filter(|f| f.regular.iter().any(|p| font_path(p).is_file())).map(|f| f.name);
    std::iter::once(BUILT_IN_FONT).chain(installed).collect()
}

/// The named installed terminal font (regular, bold), else the built-in one.
fn load_mono(name: &str) -> Option<(Font, Option<Font>)> {
    let named = MONO_FONTS.iter().filter(|f| f.name.eq_ignore_ascii_case(name));
    named.clone().find_map(|f| Some((load_first(f.regular)?, load_first(f.bold)))).or_else(built_in_font)
}

/// Load the first font in `names` that exists and parses (first face of a collection).
fn load_first(names: &[&str]) -> Option<Font> {
    names.iter().find_map(|name| {
        let bytes = std::fs::read(font_path(name)).ok()?;
        Font::from_bytes(bytes, FontSettings::default()).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(buf: &[u8], width: usize, x: usize, y: usize) -> [u8; 3] {
        let i = (y * width + x) * 4;
        [buf[i], buf[i + 1], buf[i + 2]]
    }

    #[test]
    fn switches_between_installed_fonts() {
        let fonts = available_fonts();
        // An unknown name falls back to the first installed font.
        assert_eq!(load_mono("No Such Font").is_some(), !fonts.is_empty());
        let Ok(mut r) = Renderer::new("No Such Font", 16.0) else {
            return; // no fonts on this machine
        };
        for font in &fonts {
            r.set_font(font);
            assert!(r.cell_w > 1 && r.cell_h > 1, "{font}");
            assert!(r.glyph('M', false).metrics.width > 0, "{font}");
        }
    }

    #[test]
    fn find_spans_honour_match_case() {
        let line: Vec<char> = "Error error ERROR".chars().collect();
        let needle: Vec<char> = "error".chars().collect();
        assert_eq!(find_spans(&line, &needle, false), [(0, 5), (6, 11), (12, 17)]);
        assert_eq!(find_spans(&line, &needle, true), [(6, 11)]);
        assert!(find_spans(&line, &[], false).is_empty());
    }

    fn spans(line: &str, keywords: &[&str]) -> Vec<((usize, usize), Rgb, Rgb)> {
        let line: Vec<char> = line.chars().collect();
        let keywords: Vec<Keyword> = keywords.iter().filter_map(|w| parse_keyword(w)).collect();
        keyword_spans(&line, &keywords)
    }

    #[test]
    fn finds_keywords_case_insensitively() {
        let line = "Link DOWN: error on Gi0/1, error again";
        let found = spans(line, &["error = red", "Down"]);
        let at: Vec<(usize, usize)> = found.iter().map(|(s, ..)| *s).collect();
        assert_eq!(at, [(5, 9), (11, 16), (27, 32)]);
        assert!(spans(line, &[]).is_empty());
        // "error = red" is red; a plain word keeps the default amber.
        assert_eq!((found[1].2, found[0].2), (KEYWORD_COLORS[0].2, HIGHLIGHT_BG));

        // Regexes and whole lines; the line mark comes first so words show over it.
        let found = spans("é Gi0/12 is down", &[r"/gi\d+/\d+/ = blue", "/DOWN$/ = red line", "/(/"]);
        assert_eq!(found.iter().map(|(s, ..)| *s).collect::<Vec<_>>(), [(0, 16), (2, 8)]);
        assert_eq!((found[0].2, found[1].2), (KEYWORD_COLORS[0].2, KEYWORD_COLORS[3].2));
    }

    #[test]
    fn keyword_lines_parse_with_optional_colour() {
        let k = parse_keyword("  Error ").unwrap();
        assert!(matches!(k.pattern, Pattern::Word(w) if w == "error".chars().collect::<Vec<_>>()));
        let k = parse_keyword("up = GREEN line").unwrap();
        assert_eq!((k.bg, k.line), (KEYWORD_COLORS[2].2, true));
        // An unknown colour is part of the word; blank lines are skipped.
        assert!(matches!(parse_keyword("a=b").unwrap().pattern, Pattern::Word(w) if w.len() == 3));
        assert!(parse_keyword("   ").is_none() && parse_keyword(" = red").is_none());
    }

    #[test]
    fn keyword_sets_by_name() {
        let lines: Vec<String> = ["error", "[Network]", "down = red", "up", "[ Empty ]"].map(String::from).to_vec();
        let sets = keyword_sets(&lines);
        assert_eq!((sets[""].len(), sets["Network"].len(), sets["Empty"].len()), (1, 2, 0));
        assert_eq!(keyword_set_names(&lines), ["Network", "Empty"]);
    }

    #[test]
    fn vertical_label_is_taller_than_wide() {
        let Some((w, h, rgba)) = vertical_label("Session Manager", 12.0, [0, 0, 0]) else {
            eprintln!("skipped: no UI font");
            return;
        };
        assert!(h > 3 * w, "rotated label should be tall and thin: {w}x{h}");
        assert_eq!(rgba.len(), w * h * 4);
        assert!(rgba.chunks(4).any(|p| p[3] > 128), "some glyph coverage");
    }

    #[test]
    fn the_built_in_font_is_always_there() {
        assert_eq!(available_fonts()[0], "IBM Plex Mono");
        assert!(Renderer::new("No Such Font", 16.0).is_ok());
    }

    #[test]
    fn renders_coloured_text_inside_its_cell() {
        // Environment-dependent: needs a system monospace font.
        let Ok(mut r) = Renderer::new("", 16.0) else {
            eprintln!("skipped: no system monospace font");
            return;
        };
        let mut t = Terminal::new(4, 2);
        t.scheme = crate::terminal::scheme_named("Light grey on black");
        t.feed(b"\x1b[31mH\x1b[0m\x1b[44m \x1b[0m");
        let (w, h) = (r.cell_w * 4, r.cell_h * 2);
        let mut buf = vec![0u8; w * h * 4];
        r.render(&t, "", false, &mut buf, w, h);

        // Some pixel of the first cell is reddish; nothing red leaks into row 2.
        let red = |p: [u8; 3]| p[0] > 100 && p[1] < 60 && p[2] < 60;
        let first_cell = (0..r.cell_h).flat_map(|y| (0..r.cell_w).map(move |x| (x, y)));
        assert!(first_cell.into_iter().any(|(x, y)| red(pixel(&buf, w, x, y))));
        assert!((r.cell_h..h).all(|y| (0..w).all(|x| !red(pixel(&buf, w, x, y)))));
        // The second cell has a blue background.
        let blue = pixel(&buf, w, r.cell_w + r.cell_w / 2, r.cell_h / 2);
        assert!(blue[2] > 100 && blue[0] < 80, "expected blue background, got {blue:?}");
    }
}
