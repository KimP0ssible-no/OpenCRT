//! Terminal emulation backed by `alacritty_terminal`; exposes resolved cells for rendering.

use std::cell::RefCell;
use std::rc::Rc;

use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Boundary, Column, Direction, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::search::RegexSearch;
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::color::Colors;
use alacritty_terminal::term::{Config, Term, TermMode};
pub use alacritty_terminal::vte::ansi::CursorShape;
use alacritty_terminal::vte::ansi::{Color, CursorStyle, NamedColor, Processor};

pub type Rgb = [u8; 3];

/// A colour scheme: default foreground/background and the 16 ANSI colours.
pub struct Scheme {
    pub name: &'static str,
    pub fg: Rgb,
    pub bg: Rgb,
    pub ansi: [Rgb; 16],
    /// The cursor's colour, and the selection's background; None to show
    /// them by swapping a cell's colours.
    pub cursor: Option<Rgb>,
    pub selection: Option<Rgb>,
}

/// Built-in schemes; the first is the default. The OpenCRT, phosphor and
/// Paper White colours come from the OpenCRT design pack; the others are
/// openly licensed schemes, credited in NOTICE (names stay as their authors
/// give them, which also lets the SecureCRT importer match them).
pub const SCHEMES: &[Scheme] = &[
    Scheme {
        name: "OpenCRT Dark",
        fg: [0xd9, 0xdc, 0xec],
        bg: [0x0a, 0x0d, 0x1f],
        ansi: [
            [0x1b, 0x20, 0x44], [0xf0, 0x5d, 0x5e], [0x4c, 0xcb, 0x7b], [0xf8, 0xb3, 0x32],
            [0x5a, 0xa9, 0xff], [0xc6, 0x7b, 0xf0], [0x4f, 0xd1, 0xd9], [0xc5, 0xc9, 0xe0],
            [0x4a, 0x52, 0x7f], [0xff, 0x7c, 0x7c], [0x72, 0xe3, 0x9b], [0xff, 0xd3, 0x6a],
            [0x86, 0xc2, 0xff], [0xdd, 0xa3, 0xff], [0x7f, 0xe4, 0xea], [0xf4, 0xf5, 0xfa],
        ],
        cursor: Some([0xf8, 0xb3, 0x32]),
        selection: Some([0x34, 0x3b, 0x66]),
    },
    Scheme {
        name: "OpenCRT Light",
        fg: [0x1c, 0x20, 0x40],
        bg: [0xfb, 0xfb, 0xfd],
        ansi: [
            [0x1c, 0x20, 0x40], [0xc7, 0x30, 0x3a], [0x1f, 0x8a, 0x4c], [0x9a, 0x5e, 0x08],
            [0x1f, 0x5f, 0xc4], [0x8a, 0x3b, 0xb8], [0x0e, 0x7f, 0x88], [0x9d, 0xa3, 0xbe],
            [0x5a, 0x60, 0x8a], [0xe0, 0x43, 0x4e], [0x2a, 0xa6, 0x61], [0xb8, 0x70, 0x0a],
            [0x3b, 0x7b, 0xe0], [0xa8, 0x5b, 0xd4], [0x19, 0xa1, 0xac], [0x6e, 0x74, 0x9a],
        ],
        cursor: Some([0xb8, 0x70, 0x0a]),
        selection: Some([0xdf, 0xe3, 0xf3]),
    },
    // Stands for OpenCRT Dark or Light, whichever suits the window (`Terminal::colours`).
    Scheme { name: FOLLOW_SYSTEM, fg: DEFAULT_FG, bg: DEFAULT_BG, ansi: ANSI16, cursor: None, selection: None },
    Scheme { name: "Light grey on black", fg: DEFAULT_FG, bg: DEFAULT_BG, ansi: ANSI16, cursor: None, selection: None },
    Scheme {
        name: "Black on white",
        fg: [0x00, 0x00, 0x00],
        bg: [0xff, 0xff, 0xff],
        ansi: {
            let mut a = ANSI16;
            // White and yellow text must stay readable on a white background.
            a[3] = [0x9a, 0x7a, 0x00];
            a[7] = [0x80, 0x80, 0x80];
            a[11] = [0xb0, 0x90, 0x00];
            a[15] = [0x50, 0x50, 0x50];
            a
        },
        cursor: None,
        selection: None,
    },
    // Solarized, Ethan Schoonover, MIT.
    Scheme {
        name: "Solarized dark",
        fg: [0x83, 0x94, 0x96],
        bg: [0x00, 0x2b, 0x36],
        ansi: [
            [0x07, 0x36, 0x42], [0xdc, 0x32, 0x2f], [0x85, 0x99, 0x00], [0xb5, 0x89, 0x00],
            [0x26, 0x8b, 0xd2], [0xd3, 0x36, 0x82], [0x2a, 0xa1, 0x98], [0xee, 0xe8, 0xd5],
            [0x00, 0x2b, 0x36], [0xcb, 0x4b, 0x16], [0x58, 0x6e, 0x75], [0x65, 0x7b, 0x83],
            [0x83, 0x94, 0x96], [0x6c, 0x71, 0xc4], [0x93, 0xa1, 0xa1], [0xfd, 0xf6, 0xe3],
        ],
        cursor: None,
        selection: None,
    },
    Scheme {
        name: "Green phosphor",
        fg: [0x5f, 0xe3, 0x8c],
        bg: [0x07, 0x10, 0x09],
        ansi: [
            [0x15, 0x30, 0x1c], [0x8c, 0xe8, 0x9a], [0x3f, 0xd4, 0x6d], [0xb8, 0xf0, 0x7a],
            [0x36, 0xb8, 0x74], [0x7b, 0xe0, 0xa3], [0x5c, 0xe0, 0xb8], [0x9f, 0xe8, 0xb5],
            [0x2e, 0x5a, 0x3a], [0xb5, 0xf5, 0xbf], [0x6c, 0xf2, 0x96], [0xd4, 0xff, 0x9c],
            [0x5a, 0xd4, 0x94], [0xa4, 0xf0, 0xc0], [0x86, 0xf0, 0xd0], [0xd6, 0xff, 0xe2],
        ],
        cursor: Some([0xa6, 0xff, 0xc4]),
        selection: Some([0x12, 0x3a, 0x20]),
    },
    Scheme {
        name: "Amber phosphor",
        fg: [0xf2, 0xa9, 0x3b],
        bg: [0x14, 0x10, 0x0a],
        ansi: [
            [0x2a, 0x20, 0x12], [0xff, 0x8a, 0x3d], [0xd9, 0xa4, 0x41], [0xff, 0xc2, 0x4b],
            [0xc9, 0x8a, 0x2a], [0xe9, 0xa3, 0x4a], [0xf0, 0xb8, 0x5c], [0xe6, 0xb3, 0x6a],
            [0x5a, 0x45, 0x20], [0xff, 0xa8, 0x66], [0xf2, 0xc0, 0x63], [0xff, 0xd9, 0x8a],
            [0xe0, 0xa6, 0x4a], [0xff, 0xc2, 0x7a], [0xff, 0xd0, 0x8a], [0xff, 0xe6, 0xb8],
        ],
        cursor: Some([0xff, 0xd3, 0x6a]),
        selection: Some([0x3a, 0x2b, 0x10]),
    },
    // Solarized, Ethan Schoonover, MIT.
    Scheme {
        name: "Solarized light",
        fg: [0x65, 0x7b, 0x83],
        bg: [0xfd, 0xf6, 0xe3],
        ansi: [
            [0x07, 0x36, 0x42], [0xdc, 0x32, 0x2f], [0x85, 0x99, 0x00], [0xb5, 0x89, 0x00],
            [0x26, 0x8b, 0xd2], [0xd3, 0x36, 0x82], [0x2a, 0xa1, 0x98], [0xee, 0xe8, 0xd5],
            [0x00, 0x2b, 0x36], [0xcb, 0x4b, 0x16], [0x58, 0x6e, 0x75], [0x65, 0x7b, 0x83],
            [0x83, 0x94, 0x96], [0x6c, 0x71, 0xc4], [0x93, 0xa1, 0xa1], [0xfd, 0xf6, 0xe3],
        ],
        cursor: None,
        selection: None,
    },
    // Gruvbox, Pavel Pertsev, MIT.
    Scheme {
        name: "Gruvbox dark",
        fg: [0xeb, 0xdb, 0xb2],
        bg: [0x28, 0x28, 0x28],
        ansi: [
            [0x28, 0x28, 0x28], [0xcc, 0x24, 0x1d], [0x98, 0x97, 0x1a], [0xd7, 0x99, 0x21],
            [0x45, 0x85, 0x88], [0xb1, 0x62, 0x86], [0x68, 0x9d, 0x6a], [0xa8, 0x99, 0x84],
            [0x92, 0x83, 0x74], [0xfb, 0x49, 0x34], [0xb8, 0xbb, 0x26], [0xfa, 0xbd, 0x2f],
            [0x83, 0xa5, 0x98], [0xd3, 0x86, 0x9b], [0x8e, 0xc0, 0x7c], [0xeb, 0xdb, 0xb2],
        ],
        cursor: None,
        selection: None,
    },
    Scheme {
        name: "Paper White",
        fg: [0xe6, 0xee, 0xf7],
        bg: [0x0c, 0x11, 0x18],
        ansi: [
            [0x1e, 0x27, 0x33], [0xff, 0x7b, 0x72], [0x7e, 0xe2, 0xa8], [0xf5, 0xd6, 0x7a],
            [0x7f, 0xb7, 0xff], [0xd7, 0xa6, 0xff], [0x7a, 0xd8, 0xe6], [0xc9, 0xd4, 0xe0],
            [0x4a, 0x56, 0x68], [0xff, 0xa1, 0x98], [0xa7, 0xf0, 0xc4], [0xff, 0xe5, 0x9a],
            [0xa8, 0xcc, 0xff], [0xe8, 0xc6, 0xff], [0xa3, 0xe8, 0xf0], [0xf6, 0xf9, 0xfc],
        ],
        cursor: Some([0xff, 0xff, 0xff]),
        selection: Some([0x27, 0x32, 0x3f]),
    },    // Gruvbox, Pavel Pertsev, MIT.
    Scheme {
        name: "Gruvbox light",
        fg: [0x3c, 0x38, 0x36],
        bg: [0xfb, 0xf1, 0xc7],
        ansi: [
            [0xfb, 0xf1, 0xc7], [0xcc, 0x24, 0x1d], [0x98, 0x97, 0x1a], [0xd7, 0x99, 0x21],
            [0x45, 0x85, 0x88], [0xb1, 0x62, 0x86], [0x68, 0x9d, 0x6a], [0x7c, 0x6f, 0x64],
            [0x92, 0x83, 0x74], [0x9d, 0x00, 0x06], [0x79, 0x74, 0x0e], [0xb5, 0x76, 0x14],
            [0x07, 0x66, 0x78], [0x8f, 0x3f, 0x71], [0x42, 0x7b, 0x58], [0x3c, 0x38, 0x36],
        ],
        cursor: None,
        selection: None,
    },
    // Tomorrow, Chris Kempson, MIT.
    Scheme {
        name: "Tomorrow",
        fg: [0x4d, 0x4d, 0x4c],
        bg: [0xff, 0xff, 0xff],
        ansi: [
            [0x4d, 0x4d, 0x4c], [0xc8, 0x28, 0x29], [0x71, 0x8c, 0x00], [0xea, 0xb7, 0x00],
            [0x42, 0x71, 0xae], [0x89, 0x59, 0xa8], [0x3e, 0x99, 0x9f], [0xd6, 0xd6, 0xd6],
            [0x8e, 0x90, 0x8c], [0xc8, 0x28, 0x29], [0x71, 0x8c, 0x00], [0xea, 0xb7, 0x00],
            [0x42, 0x71, 0xae], [0x89, 0x59, 0xa8], [0x3e, 0x99, 0x9f], [0xef, 0xef, 0xef],
        ],
        cursor: Some([0x4d, 0x4d, 0x4c]),
        selection: Some([0xd6, 0xd6, 0xd6]),
    },
    // Tomorrow, Chris Kempson, MIT.
    Scheme {
        name: "Tomorrow Night",
        fg: [0xc5, 0xc8, 0xc6],
        bg: [0x1d, 0x1f, 0x21],
        ansi: [
            [0x1d, 0x1f, 0x21], [0xcc, 0x66, 0x66], [0xb5, 0xbd, 0x68], [0xf0, 0xc6, 0x74],
            [0x81, 0xa2, 0xbe], [0xb2, 0x94, 0xbb], [0x8a, 0xbe, 0xb7], [0xc5, 0xc8, 0xc6],
            [0x96, 0x98, 0x96], [0xcc, 0x66, 0x66], [0xb5, 0xbd, 0x68], [0xf0, 0xc6, 0x74],
            [0x81, 0xa2, 0xbe], [0xb2, 0x94, 0xbb], [0x8a, 0xbe, 0xb7], [0xff, 0xff, 0xff],
        ],
        cursor: Some([0xc5, 0xc8, 0xc6]),
        selection: Some([0x37, 0x3b, 0x41]),
    },
    // Dracula, Zeno Rocha, MIT.
    Scheme {
        name: "Dracula",
        fg: [0xf8, 0xf8, 0xf2],
        bg: [0x28, 0x2a, 0x36],
        ansi: [
            [0x21, 0x22, 0x2c], [0xff, 0x55, 0x55], [0x50, 0xfa, 0x7b], [0xf1, 0xfa, 0x8c],
            [0xbd, 0x93, 0xf9], [0xff, 0x79, 0xc6], [0x8b, 0xe9, 0xfd], [0xf8, 0xf8, 0xf2],
            [0x62, 0x72, 0xa4], [0xff, 0x6e, 0x6e], [0x69, 0xff, 0x94], [0xff, 0xff, 0xa5],
            [0xd6, 0xac, 0xff], [0xff, 0x92, 0xdf], [0xa4, 0xff, 0xff], [0xff, 0xff, 0xff],
        ],
        cursor: Some([0xf8, 0xf8, 0xf2]),
        selection: Some([0x44, 0x47, 0x5a]),
    },
    // Nord, Arctic Ice Studio and Sven Greb, MIT.
    Scheme {
        name: "Nord",
        fg: [0xd8, 0xde, 0xe9],
        bg: [0x2e, 0x34, 0x40],
        ansi: [
            [0x3b, 0x42, 0x52], [0xbf, 0x61, 0x6a], [0xa3, 0xbe, 0x8c], [0xeb, 0xcb, 0x8b],
            [0x81, 0xa1, 0xc1], [0xb4, 0x8e, 0xad], [0x88, 0xc0, 0xd0], [0xe5, 0xe9, 0xf0],
            [0x4c, 0x56, 0x6a], [0xbf, 0x61, 0x6a], [0xa3, 0xbe, 0x8c], [0xeb, 0xcb, 0x8b],
            [0x81, 0xa1, 0xc1], [0xb4, 0x8e, 0xad], [0x8f, 0xbc, 0xbb], [0xec, 0xef, 0xf4],
        ],
        cursor: Some([0xd8, 0xde, 0xe9]),
        selection: Some([0x43, 0x4c, 0x5e]),
    },
    // One Dark, GitHub Inc. (Atom), MIT.
    Scheme {
        name: "One Dark",
        fg: [0xab, 0xb2, 0xbf],
        bg: [0x28, 0x2c, 0x34],
        ansi: [
            [0x28, 0x2c, 0x34], [0xe0, 0x6c, 0x75], [0x98, 0xc3, 0x79], [0xe5, 0xc0, 0x7b],
            [0x61, 0xaf, 0xef], [0xc6, 0x78, 0xdd], [0x56, 0xb6, 0xc2], [0xab, 0xb2, 0xbf],
            [0x5c, 0x63, 0x70], [0xe0, 0x6c, 0x75], [0x98, 0xc3, 0x79], [0xe5, 0xc0, 0x7b],
            [0x61, 0xaf, 0xef], [0xc6, 0x78, 0xdd], [0x56, 0xb6, 0xc2], [0xff, 0xff, 0xff],
        ],
        cursor: Some([0x52, 0x8b, 0xff]),
        selection: Some([0x3e, 0x44, 0x51]),
    },
    // Catppuccin, Catppuccin org, MIT.
    Scheme {
        name: "Catppuccin Mocha",
        fg: [0xcd, 0xd6, 0xf4],
        bg: [0x1e, 0x1e, 0x2e],
        ansi: [
            [0x45, 0x47, 0x5a], [0xf3, 0x8b, 0xa8], [0xa6, 0xe3, 0xa1], [0xf9, 0xe2, 0xaf],
            [0x89, 0xb4, 0xfa], [0xf5, 0xc2, 0xe7], [0x94, 0xe2, 0xd5], [0xba, 0xc2, 0xde],
            [0x58, 0x5b, 0x70], [0xf3, 0x8b, 0xa8], [0xa6, 0xe3, 0xa1], [0xf9, 0xe2, 0xaf],
            [0x89, 0xb4, 0xfa], [0xf5, 0xc2, 0xe7], [0x94, 0xe2, 0xd5], [0xa6, 0xad, 0xc8],
        ],
        cursor: Some([0xf5, 0xe0, 0xdc]),
        selection: Some([0x58, 0x5b, 0x70]),
    },
    // Catppuccin, Catppuccin org, MIT.
    Scheme {
        name: "Catppuccin Latte",
        fg: [0x4c, 0x4f, 0x69],
        bg: [0xef, 0xf1, 0xf5],
        ansi: [
            [0x5c, 0x5f, 0x77], [0xd2, 0x0f, 0x39], [0x40, 0xa0, 0x2b], [0xdf, 0x8e, 0x1d],
            [0x1e, 0x66, 0xf5], [0xea, 0x76, 0xcb], [0x17, 0x92, 0x99], [0xac, 0xb0, 0xbe],
            [0x6c, 0x6f, 0x85], [0xd2, 0x0f, 0x39], [0x40, 0xa0, 0x2b], [0xdf, 0x8e, 0x1d],
            [0x1e, 0x66, 0xf5], [0xea, 0x76, 0xcb], [0x17, 0x92, 0x99], [0xbc, 0xc0, 0xcc],
        ],
        cursor: Some([0xdc, 0x8a, 0x78]),
        selection: Some([0xac, 0xb0, 0xbe]),
    },
    // Tango palette, Tango Desktop Project, public domain.
    Scheme {
        name: "Tango",
        fg: [0xd3, 0xd7, 0xcf],
        bg: [0x2e, 0x34, 0x36],
        ansi: [
            [0x2e, 0x34, 0x36], [0xcc, 0x00, 0x00], [0x4e, 0x9a, 0x06], [0xc4, 0xa0, 0x00],
            [0x34, 0x65, 0xa4], [0x75, 0x50, 0x7b], [0x06, 0x98, 0x9a], [0xd3, 0xd7, 0xcf],
            [0x55, 0x57, 0x53], [0xef, 0x29, 0x29], [0x8a, 0xe2, 0x34], [0xfc, 0xe9, 0x4f],
            [0x72, 0x9f, 0xcf], [0xad, 0x7f, 0xa8], [0x34, 0xe2, 0xe2], [0xee, 0xee, 0xec],
        ],
        cursor: None,
        selection: None,
    },
    // Tokyo Night, enkia, MIT.
    Scheme {
        name: "Tokyo Night",
        fg: [0xc0, 0xca, 0xf5],
        bg: [0x1a, 0x1b, 0x26],
        ansi: [
            [0x15, 0x16, 0x1e], [0xf7, 0x76, 0x8e], [0x9e, 0xce, 0x6a], [0xe0, 0xaf, 0x68],
            [0x7a, 0xa2, 0xf7], [0xbb, 0x9a, 0xf7], [0x7d, 0xcf, 0xff], [0xa9, 0xb1, 0xd6],
            [0x41, 0x48, 0x68], [0xf7, 0x76, 0x8e], [0x9e, 0xce, 0x6a], [0xe0, 0xaf, 0x68],
            [0x7a, 0xa2, 0xf7], [0xbb, 0x9a, 0xf7], [0x7d, 0xcf, 0xff], [0xc0, 0xca, 0xf5],
        ],
        cursor: Some([0xc0, 0xca, 0xf5]),
        selection: Some([0x28, 0x34, 0x57]),
    },
];

/// The scheme that is OpenCRT Dark or Light, as the window theme is.
pub const FOLLOW_SYSTEM: &str = "Follow the system (OpenCRT Dark/Light)";

/// Whether the window theme is dark (set by the app as it changes).
pub static SYSTEM_DARK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Schemes made in Options > Colour Schemes (kept for the life of the app).
static USER_SCHEMES: std::sync::RwLock<Vec<&'static Scheme>> = std::sync::RwLock::new(Vec::new());

/// The built-in schemes, then the user's.
pub fn schemes() -> Vec<&'static Scheme> {
    SCHEMES.iter().chain(USER_SCHEMES.read().unwrap().iter().copied()).collect()
}

/// Make the user's schemes available (replacing earlier ones). Leaks a
/// little memory per edit, which is fine for something edited by hand.
pub fn set_user_schemes(defs: &[crate::config::SchemeDef]) {
    let list = defs.iter().filter_map(|d| d.to_scheme()).map(|s| &*Box::leak(Box::new(s))).collect();
    *USER_SCHEMES.write().unwrap() = list;
}

/// Look up a scheme by name, falling back to the default.
pub fn scheme_named(name: &str) -> &'static Scheme {
    schemes().into_iter().find(|s| s.name == name).unwrap_or(&SCHEMES[0])
}

/// `#rrggbb` as a colour.
pub fn parse_hex(text: &str) -> Option<Rgb> {
    let hex = text.trim().strip_prefix('#').unwrap_or(text.trim());
    if hex.len() != 6 {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok();
    Some([byte(0)?, byte(2)?, byte(4)?])
}

pub fn to_hex(rgb: Rgb) -> String {
    format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2])
}

/// Colours of the default scheme.
pub const DEFAULT_FG: Rgb = [0xe0, 0xe0, 0xe0];
pub const DEFAULT_BG: Rgb = [0x00, 0x00, 0x00];

const ANSI16: [[u8; 3]; 16] = [
    [0x00, 0x00, 0x00],
    [0xcc, 0x00, 0x00],
    [0x4e, 0x9a, 0x06],
    [0xc4, 0xa0, 0x00],
    [0x34, 0x65, 0xa4],
    [0x75, 0x50, 0x7b],
    [0x06, 0x98, 0x9a],
    [0xd3, 0xd7, 0xcf],
    [0x55, 0x57, 0x53],
    [0xef, 0x29, 0x29],
    [0x8a, 0xe2, 0x34],
    [0xfc, 0xe9, 0x4f],
    [0x72, 0x9f, 0xcf],
    [0xad, 0x7f, 0xa8],
    [0x34, 0xe2, 0xe2],
    [0xee, 0xee, 0xec],
];

/// Our own `Dimensions` implementation (the `(usize, usize)` one is test-only).
struct Size {
    cols: usize,
    rows: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.rows
    }
    fn screen_lines(&self) -> usize {
        self.rows
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

/// Terminal side effects collected while parsing.
#[derive(Default)]
struct Pending {
    /// Bytes to write back to the host (DA / DSR replies).
    reply: Vec<u8>,
    /// `Some(None)` means the title was reset.
    title: Option<Option<String>>,
    bell: bool,
}

#[derive(Clone, Default)]
struct Listener(Rc<RefCell<Pending>>);

impl EventListener for Listener {
    fn send_event(&self, event: Event) {
        let mut pending = self.0.borrow_mut();
        match event {
            Event::PtyWrite(text) => pending.reply.extend_from_slice(text.as_bytes()),
            Event::Title(title) => pending.title = Some(Some(title)),
            Event::ResetTitle => pending.title = Some(None),
            Event::Bell => pending.bell = true,
            _ => {}
        }
    }
}

pub struct Terminal {
    term: Term<Listener>,
    listener: Listener,
    parser: Processor,
    cols: usize,
    rows: usize,
    /// Title set by the host (OSC 0/2), if any.
    pub title: Option<String>,
    pub scheme: &'static Scheme,
    scrollback: usize,
    /// Cursor shape unless the host picks one (DECSCUSR).
    cursor: CursorShape,
    /// Characters that end a double-clicked word; None for the built-in set.
    delimiters: Option<String>,
}

impl Terminal {
    pub fn new(cols: usize, rows: usize) -> Self {
        let size = Size { cols, rows };
        let listener = Listener::default();
        let config = Config::default();
        let scrollback = config.scrolling_history;
        let term = Term::new(config, &size, listener.clone());
        Self {
            term,
            listener,
            parser: Processor::new(),
            cols,
            rows,
            title: None,
            scheme: &SCHEMES[0],
            scrollback,
            cursor: CursorShape::Block,
            delimiters: None,
        }
    }

    fn apply_options(&mut self) {
        let default_cursor_style = CursorStyle { shape: self.cursor, blinking: false };
        let defaults = Config::default();
        let semantic_escape_chars = self.delimiters.clone().unwrap_or(defaults.semantic_escape_chars.clone());
        self.term.set_options(Config { scrolling_history: self.scrollback, default_cursor_style, semantic_escape_chars, ..defaults });
    }

    /// Characters that end a word for double-click selection; empty for the
    /// built-in set. Spaces and tabs always separate words.
    pub fn set_word_delimiters(&mut self, chars: &str) {
        self.delimiters = (!chars.is_empty()).then(|| format!("{chars} \t"));
        self.apply_options();
    }

    /// Lines of scrollback history to keep.
    pub fn set_scrollback(&mut self, lines: usize) {
        self.scrollback = lines;
        self.apply_options();
    }

    /// The cursor's shape when the host does not choose one.
    pub fn set_cursor_shape(&mut self, shape: CursorShape) {
        self.cursor = shape;
        self.apply_options();
    }

    /// Feed raw bytes from the remote side into the terminal parser.
    /// Returns any reply bytes the terminal needs sent back to the host.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.parser.advance(&mut self.term, bytes);
        let mut pending = self.listener.0.borrow_mut();
        if let Some(title) = pending.title.take() {
            self.title = title;
        }
        std::mem::take(&mut pending.reply)
    }

    /// A new connection in this tab: drop the old session's screen into history
    /// and undo the modes it set (alternate screen, mouse reporting, keypad,
    /// colours, scroll region). Not RIS: that would also wipe the scrollback.
    pub fn restart(&mut self) {
        self.feed(b"\x1b[?1049l\x1b[0m\x1b(B\x1b[r\x1b[4l\x1b[?6l\x1b[?7h\x1b[?25h\x1b[?1l\x1b>");
        self.feed(b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1006l\x1b[?2004l\x1b[H\x1b[2J");
        self.term.scroll_display(Scroll::Bottom);
    }

    /// True once per bell (BEL) received since the last call.
    pub fn take_bell(&mut self) -> bool {
        std::mem::take(&mut self.listener.0.borrow_mut().bell)
    }

    pub fn mode(&self) -> TermMode {
        *self.term.mode()
    }

    pub fn resize(&mut self, cols: usize, rows: usize) {
        self.term.resize(Size { cols, rows });
        self.cols = cols;
        self.rows = rows;
    }

    pub fn scroll(&mut self, scroll: Scroll) {
        self.term.scroll_display(scroll);
    }

    /// (lines scrolled back, lines of history available).
    pub fn scroll_position(&self) -> (usize, usize) {
        let grid = self.term.grid();
        (grid.display_offset(), grid.history_size())
    }

    /// The grid point under `(x, y)` (pixels from the grid origin, cells of `cell`
    /// = (width, height)) and which half of the cell it falls in. Clamped to the screen.
    pub fn point_at(&self, (x, y): (f32, f32), cell: (f32, f32)) -> (Point, Side) {
        let col = (x / cell.0).max(0.0);
        let row = (y / cell.1).max(0.0) as usize;
        let side = if col.fract() < 0.5 { Side::Left } else { Side::Right };
        let col = (col as usize).min(self.cols - 1);
        let row = row.min(self.rows - 1);
        let offset = self.term.grid().display_offset() as i32;
        (Point::new(Line(row as i32 - offset), Column(col)), side)
    }

    pub fn start_selection(&mut self, ty: SelectionType, point: Point, side: Side) {
        self.term.selection = Some(Selection::new(ty, point, side));
    }

    pub fn update_selection(&mut self, point: Point, side: Side) {
        if let Some(selection) = self.term.selection.as_mut() {
            selection.update(point, side);
        }
    }

    pub fn select_all(&mut self) {
        let grid = self.term.grid();
        let mut selection = Selection::new(SelectionType::Lines, Point::new(grid.topmost_line(), Column(0)), Side::Left);
        selection.update(Point::new(grid.bottommost_line(), grid.last_column()), Side::Right);
        self.term.selection = Some(selection);
    }

    pub fn clear_selection(&mut self) {
        self.term.selection = None;
    }

    /// Find `text` (literally) after the previous hit, or before it when
    /// `backwards`, wrapping around the scrollback. A hit is selected and
    /// scrolled into view. Returns whether anything matched.
    pub fn find(&mut self, text: &str, match_case: bool, backwards: bool) -> bool {
        if text.is_empty() {
            return false;
        }
        // RegexSearch is smart-case: lowercase text matches any case unless forced.
        let pattern = format!("{}{}", if match_case { "(?-i)" } else { "" }, regex_escape(text));
        let Ok(mut regex) = RegexSearch::new(&pattern) else {
            return false;
        };
        let grid = self.term.grid();
        let selection = self.term.selection.as_ref().and_then(|s| s.to_range(&self.term));
        let (origin, direction) = match (selection, backwards) {
            (Some(r), false) => (r.end.add(grid, Boundary::Grid, 1), Direction::Right),
            (Some(r), true) => (r.start.sub(grid, Boundary::Grid, 1), Direction::Left),
            // A new search starts from the newest output and works back.
            (None, _) => (Point::new(grid.bottommost_line(), grid.last_column()), Direction::Left),
        };
        let Some(hit) = self.term.search_next(&mut regex, origin, direction, Side::Left, None) else {
            return false;
        };
        let mut selection = Selection::new(SelectionType::Simple, *hit.start(), Side::Left);
        selection.update(*hit.end(), Side::Right);
        self.term.selection = Some(selection);
        self.term.scroll_to_point(*hit.start());
        true
    }

    /// The selection as HTML with the colours and weight it shows on screen
    /// (Edit > Copy with Colours); None without a selection.
    pub fn selection_html(&self) -> Option<String> {
        let range = self.term.selection.as_ref()?.to_range(&self.term)?;
        let (scheme, colors, grid) = (self.colours(), self.term.colors(), self.term.grid());
        let hex = |c: Rgb| format!("#{:02x}{:02x}{:02x}", c[0], c[1], c[2]);
        let mut html = format!(
            "<pre style=\"color:{};background:{};font-family:'IBM Plex Mono',monospace\">",
            hex(scheme.fg),
            hex(scheme.bg)
        );
        let last_col = self.cols - 1;
        for line in range.start.line.0..=range.end.line.0 {
            let row = &grid[Line(line)];
            let first = if range.is_block || line == range.start.line.0 { range.start.column.0 } else { 0 };
            let last = if range.is_block || line == range.end.line.0 { range.end.column.0 } else { last_col };
            let mut runs: Vec<((Rgb, Rgb, bool), String)> = Vec::new();
            for col in first..=last.min(last_col) {
                let cell = &row[Column(col)];
                if cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                    continue;
                }
                let (fg, bg) = cell_colors(cell.fg, cell.bg, cell.flags, colors, scheme);
                let key = (fg, bg, cell.flags.contains(Flags::BOLD));
                let c = if cell.flags.contains(Flags::HIDDEN) { ' ' } else { cell.c };
                match runs.last_mut() {
                    Some((k, text)) if *k == key => text.push(c),
                    _ => runs.push((key, c.to_string())),
                }
            }
            // Trailing blanks on the terminal's own background are not text.
            while let Some(((_, bg, _), text)) = runs.last_mut()
                && *bg == scheme.bg
            {
                let kept = text.trim_end_matches(' ').len();
                text.truncate(kept);
                if !text.is_empty() {
                    break;
                }
                runs.pop();
            }
            for ((fg, bg, bold), text) in runs {
                let text = text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
                let weight = if bold { ";font-weight:bold" } else { "" };
                html.push_str(&format!("<span style=\"color:{};background:{}{weight}\">{text}</span>", hex(fg), hex(bg)));
            }
            let wraps = !range.is_block && last == last_col && row[Column(last_col)].flags.contains(Flags::WRAPLINE);
            if line != range.end.line.0 && !wraps {
                html.push('\n');
            }
        }
        html.push_str("</pre>");
        Some(html)
    }

    /// The selected text, if a non-empty selection exists. Trailing newlines are
    /// dropped so pasting a copied line does not execute it.
    pub fn selection_text(&self) -> Option<String> {
        let text = self.term.selection_to_string()?;
        let text = text.trim_end_matches('\n');
        (!text.is_empty()).then(|| text.to_string())
    }
}

/// Escape regex syntax so `text` matches literally.
fn regex_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// One visible cell with its colours resolved (attributes, selection and a
/// focused block cursor already applied), ready to paint.
#[derive(Clone)]
pub struct CellView {
    pub row: usize,
    pub col: usize,
    /// `' '` for blank or hidden cells.
    pub c: char,
    pub fg: Rgb,
    pub bg: Rgb,
    /// Occupies two columns.
    pub wide: bool,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strike: bool,
    /// Inside the selection (its colours are already swapped).
    pub selected: bool,
}

/// A cursor drawn on top of the cells (a focused block cursor is drawn by
/// inverting its cell instead).
#[derive(Debug, PartialEq)]
pub enum CursorMark {
    Beam,
    Underline,
    Hollow,
}

impl Terminal {
    /// Visit every visible cell in row order.
    pub fn for_each_cell(&self, focused: bool, mut f: impl FnMut(&CellView)) {
        let content = self.term.renderable_content();
        let rows = self.rows as i32;
        let offset = content.display_offset as i32;
        let cursor = content.cursor;
        let block_cursor = focused && cursor.shape == CursorShape::Block;
        let scheme = self.colours();

        for c in content.display_iter {
            let row = c.point.line.0 + offset;
            if row < 0 || row >= rows || c.flags.contains(Flags::WIDE_CHAR_SPACER) {
                continue;
            }
            let (mut fg, mut bg) = cell_colors(c.fg, c.bg, c.flags, content.colors, scheme);
            let selected = content.selection.is_some_and(|r| r.contains(c.point));
            let on_cursor = block_cursor && c.point == cursor.point;
            match (on_cursor, scheme.cursor, selected, scheme.selection) {
                (true, Some(colour), ..) => (fg, bg) = (scheme.bg, colour),
                (false, _, true, Some(colour)) => bg = colour,
                _ if selected != on_cursor => std::mem::swap(&mut fg, &mut bg),
                _ => {}
            }
            f(&CellView {
                row: row as usize,
                col: c.point.column.0,
                c: if c.flags.contains(Flags::HIDDEN) { ' ' } else { c.c },
                fg,
                bg,
                wide: c.flags.contains(Flags::WIDE_CHAR),
                bold: c.flags.contains(Flags::BOLD),
                italic: c.flags.contains(Flags::ITALIC),
                underline: c.flags.intersects(Flags::ALL_UNDERLINES),
                strike: c.flags.contains(Flags::STRIKEOUT),
                selected,
            });
        }
    }

    /// The web address under screen cell (`row`, `col`), if there is one.
    pub fn url_at(&self, row: usize, col: usize) -> Option<String> {
        let mut line = vec![' '; self.cols];
        self.for_each_cell(false, |cell| {
            if cell.row == row && cell.col < line.len() {
                line[cell.col] = cell.c;
            }
        });
        find_url(&line, col)
    }

    /// The cursor to draw over the cells, as (row, col, shape), if any.
    pub fn cursor_mark(&self, focused: bool) -> Option<(usize, usize, CursorMark)> {
        let content = self.term.renderable_content();
        let cursor = content.cursor;
        let row = cursor.point.line.0 + content.display_offset as i32;
        if row < 0 || row >= self.rows as i32 {
            return None;
        }
        let mark = match cursor.shape {
            CursorShape::Hidden => return None,
            CursorShape::Block if focused => return None,
            CursorShape::Beam => CursorMark::Beam,
            CursorShape::Underline => CursorMark::Underline,
            _ => CursorMark::Hollow,
        };
        Some((row as usize, cursor.point.column.0, mark))
    }

    /// 1-based (row, column) of the cursor on screen, for the status bar.
    /// The visible screen as text, one line per row, trailing blanks trimmed.
    /// The colours in use: the scheme, or OpenCRT Dark/Light for `FOLLOW_SYSTEM`.
    pub fn colours(&self) -> &'static Scheme {
        if self.scheme.name != FOLLOW_SYSTEM {
            return self.scheme;
        }
        let dark = SYSTEM_DARK.load(std::sync::atomic::Ordering::Relaxed);
        scheme_named(if dark { "OpenCRT Dark" } else { "OpenCRT Light" })
    }

    pub fn screen_text(&self) -> String {
        let (cols, rows) = self.size();
        let mut lines = vec![vec![' '; cols]; rows];
        self.for_each_cell(false, |cell| {
            if let Some(slot) = lines.get_mut(cell.row).and_then(|line| line.get_mut(cell.col)) {
                *slot = cell.c;
            }
        });
        lines.iter().map(|line| line.iter().collect::<String>().trim_end().to_string()).collect::<Vec<_>>().join("\n")
    }

    pub fn cursor_position(&self) -> (usize, usize) {
        let point = self.term.grid().cursor.point;
        (point.line.0.max(0) as usize + 1, point.column.0 + 1)
    }

    pub fn size(&self) -> (usize, usize) {
        (self.cols, self.rows)
    }
}

/// The http(s) address in `line` that covers column `col`. It runs to the next
/// space or quote/bracket; trailing punctuation is not part of it.
pub fn find_url(line: &[char], col: usize) -> Option<String> {
    let text: String = line.iter().collect();
    let ends = |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`' | '{' | '}' | '|');
    for scheme in ["https://", "http://"] {
        for (byte, _) in text.match_indices(scheme) {
            let start = text[..byte].chars().count();
            let rest: String = text[byte..].chars().take_while(|&c| !ends(c)).collect();
            let mut url = rest.trim_end_matches(['.', ',', ';', ':', '!', '?']).to_string();
            // A closing bracket belongs to the address only if it opened one.
            while url.ends_with(')') && url.matches('(').count() < url.matches(')').count() {
                url.pop();
            }
            if (start..start + url.chars().count()).contains(&col) && url.len() > scheme.len() {
                return Some(url);
            }
        }
    }
    None
}

/// Resolve a cell's on-screen (fg, bg): bold brightens the 8 base colours, dim
/// darkens, inverse swaps.
fn cell_colors(fg: Color, bg: Color, flags: Flags, colors: &Colors, scheme: &Scheme) -> (Rgb, Rgb) {
    let fg = match fg {
        Color::Named(n) if flags.contains(Flags::BOLD) => Color::Named(n.to_bright()),
        Color::Indexed(i) if i < 8 && flags.contains(Flags::BOLD) => Color::Indexed(i + 8),
        other => other,
    };
    let mut fg = color_to_rgb(fg, colors, scheme);
    if flags.contains(Flags::DIM) {
        fg = fg.map(|v| (v as u16 * 2 / 3) as u8);
    }
    let bg = color_to_rgb(bg, colors, scheme);
    if flags.contains(Flags::INVERSE) { (bg, fg) } else { (fg, bg) }
}

fn color_to_rgb(color: Color, colors: &Colors, scheme: &Scheme) -> Rgb {
    match color {
        Color::Named(n) => named_rgb(n, colors, scheme),
        Color::Spec(rgb) => [rgb.r, rgb.g, rgb.b],
        Color::Indexed(i) => indexed_rgb(i, colors, scheme),
    }
}

fn named_rgb(n: NamedColor, colors: &Colors, scheme: &Scheme) -> Rgb {
    if let Some(rgb) = colors[n] {
        return [rgb.r, rgb.g, rgb.b];
    }
    let idx = match n {
        NamedColor::Black => 0,
        NamedColor::Red => 1,
        NamedColor::Green => 2,
        NamedColor::Yellow => 3,
        NamedColor::Blue => 4,
        NamedColor::Magenta => 5,
        NamedColor::Cyan => 6,
        NamedColor::White => 7,
        NamedColor::BrightBlack => 8,
        NamedColor::BrightRed => 9,
        NamedColor::BrightGreen => 10,
        NamedColor::BrightYellow => 11,
        NamedColor::BrightBlue => 12,
        NamedColor::BrightMagenta => 13,
        NamedColor::BrightCyan => 14,
        NamedColor::BrightWhite => 15,
        NamedColor::DimBlack => 0,
        NamedColor::DimRed => 1,
        NamedColor::DimGreen => 2,
        NamedColor::DimYellow => 3,
        NamedColor::DimBlue => 4,
        NamedColor::DimMagenta => 5,
        NamedColor::DimCyan => 6,
        NamedColor::DimWhite => 7,
        // Bold default text keeps the scheme colour; the bold face carries the weight.
        NamedColor::Foreground | NamedColor::BrightForeground | NamedColor::Cursor => return scheme.fg,
        NamedColor::DimForeground => return scheme.fg.map(|v| (v as u16 * 2 / 3) as u8),
        NamedColor::Background => return scheme.bg,
    };
    scheme.ansi[idx]
}

fn indexed_rgb(i: u8, colors: &Colors, scheme: &Scheme) -> Rgb {
    if let Some(rgb) = colors[i as usize] {
        return [rgb.r, rgb.g, rgb.b];
    }
    match i {
        0..=15 => scheme.ansi[i as usize],
        16..=231 => {
            let n = (i - 16) as u32;
            let r = n / 36 % 6;
            let g = n / 6 % 6;
            let b = n % 6;
            let level = |v: u32| if v == 0 { 0 } else { 55 + v * 40 };
            [level(r) as u8, level(g) as u8, level(b) as u8]
        }
        232..=255 => {
            let v = 8 + (i as u32 - 232) * 10;
            [v as u8, v as u8, v as u8]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_basic_text_and_cursor_moves() {
        let mut t = Terminal::new(10, 2);
        t.feed(b"hello");

        let content = t.term.renderable_content();
        let cells: Vec<char> = content.display_iter.map(|c| c.c).collect();
        assert_eq!(&cells[..5], &['h', 'e', 'l', 'l', 'o']);

        // Cursor home (ESC [ H), then overwrite the first cell.
        t.feed(b"\x1b[H");
        t.feed(b"X");

        let content = t.term.renderable_content();
        let cells: Vec<char> = content.display_iter.map(|c| c.c).collect();
        assert_eq!(cells[0], 'X');
        assert_eq!(cells[1], 'e');
    }

    #[test]
    fn finds_urls_under_the_pointer() {
        let line: Vec<char> = "see https://example.com/a?b=1. and (http://x.org/p) end".chars().collect();
        assert_eq!(find_url(&line, 4).as_deref(), Some("https://example.com/a?b=1"));
        assert_eq!(find_url(&line, 28).as_deref(), Some("https://example.com/a?b=1"));
        assert_eq!(find_url(&line, 29), None, "the full stop is not part of it");
        assert_eq!(find_url(&line, 40).as_deref(), Some("http://x.org/p"));
        assert_eq!(find_url(&line, 0), None);
        let wiki: Vec<char> = "https://en.wikipedia.org/wiki/Rust_(language)".chars().collect();
        assert_eq!(find_url(&wiki, 10).as_deref(), Some("https://en.wikipedia.org/wiki/Rust_(language)"));
        let mut t = Terminal::new(40, 2);
        t.feed(b"go to https://opencrt.test now");
        assert_eq!(t.url_at(0, 10).as_deref(), Some("https://opencrt.test"));
        assert_eq!(t.url_at(0, 2), None);
    }

    #[test]
    fn clear_screen_and_scrollback_sequences() {
        let mut t = Terminal::new(10, 2);
        t.feed(b"one\r\ntwo\r\nthree\r\nfour");
        assert!(t.scroll_position().1 > 0, "lines went into history");
        // Clear Screen: the screen empties, history stays.
        t.feed(b"\x1b[H\x1b[2J");
        let mut text = String::new();
        t.for_each_cell(false, |c| text.push(c.c));
        assert!(text.trim().is_empty(), "{text:?}");
        assert!(t.scroll_position().1 > 0);
        // Clear Scrollback: the history goes too.
        t.feed(b"\x1b[3J");
        assert_eq!(t.scroll_position().1, 0);
    }

    #[test]
    fn restart_clears_the_screen_and_modes_but_keeps_history() {
        let mut t = Terminal::new(10, 2);
        t.feed(b"old\r\n\x1b[?1049h\x1b[?1000h\x1b[?1h\x1b[?2004hvim");
        assert!(t.mode().contains(TermMode::ALT_SCREEN | TermMode::MOUSE_REPORT_CLICK));
        t.restart();
        let mut text = String::new();
        t.for_each_cell(false, |c| text.push(c.c));
        assert!(text.trim().is_empty(), "{text:?}");
        assert!(!t.mode().intersects(TermMode::ALT_SCREEN | TermMode::MOUSE_MODE | TermMode::APP_CURSOR | TermMode::BRACKETED_PASTE));
        assert!(t.scroll_position().1 > 0, "the old screen went into history");
        assert_eq!(t.cursor_position(), (1, 1));
    }

    #[test]
    fn cursor_shape_setting_yields_to_the_host() {
        let mut t = Terminal::new(10, 2);
        assert_eq!(t.cursor_mark(true).map(|m| m.2), None, "focused block cursor is drawn by inverse cells");
        t.set_cursor_shape(CursorShape::Underline);
        assert_eq!(t.cursor_mark(true).map(|m| m.2), Some(CursorMark::Underline));
        // DECSCUSR 6 (steady bar) from the host wins until it resets with 0.
        t.feed(b"\x1b[6 q");
        assert_eq!(t.cursor_mark(true).map(|m| m.2), Some(CursorMark::Beam));
        t.feed(b"\x1b[0 q");
        assert_eq!(t.cursor_mark(true).map(|m| m.2), Some(CursorMark::Underline));
    }

    #[test]
    fn scrollback_size_changes_apply_to_a_live_terminal() {
        let mut t = Terminal::new(10, 3);
        t.feed("x\r\n".repeat(50).as_bytes());
        assert_eq!(t.scroll_position().1, 48);
        t.set_scrollback(10);
        assert_eq!(t.scroll_position().1, 10);
    }

    #[test]
    fn answers_cursor_position_report() {
        let mut t = Terminal::new(10, 3);
        assert!(t.feed(b"\r\nab").is_empty());
        assert_eq!(t.feed(b"\x1b[6n"), b"\x1b[2;3R");
    }

    #[test]
    fn copies_selection_as_coloured_html() {
        let mut t = Terminal::new(20, 2);
        t.feed(b"\x1b[1;31mERR\x1b[0m a<b\r\nok");
        t.select_all();
        let html = t.selection_html().unwrap();
        let red = color_to_rgb(Color::Named(NamedColor::BrightRed), t.term.colors(), t.colours());
        let red = format!("color:#{:02x}{:02x}{:02x}", red[0], red[1], red[2]);
        assert!(html.contains(&format!("{red};")) && html.contains("font-weight:bold\">ERR</span>"), "{html}");
        assert!(html.contains(">ok</span></pre>") && html.contains("a&lt;b</span>\n"), "{html}");
    }

    #[test]
    fn scrollback_and_selection() {
        let mut t = Terminal::new(12, 3);
        t.feed(b"one\r\ntwo\r\nhello world\r\nlast");
        assert_eq!(t.scroll_position(), (0, 1));

        // Word (double-click) selection on the visible "hello world" row.
        let cell = (10.0, 20.0);
        let (point, side) = t.point_at((75.0, 25.0), cell);
        assert_eq!((point, side), (Point::new(Line(1), Column(7)), Side::Right));
        t.start_selection(SelectionType::Semantic, point, side);
        assert_eq!(t.selection_text().as_deref(), Some("world"));

        // With user delimiters, "host:22" stops at ':' only if ':' is listed.
        let mut u = Terminal::new(20, 2);
        u.feed(b"ssh host:22/x");
        u.start_selection(SelectionType::Semantic, Point::new(Line(0), Column(5)), Side::Left);
        assert_eq!(u.selection_text().as_deref(), Some("host"));
        u.set_word_delimiters("/");
        u.start_selection(SelectionType::Semantic, Point::new(Line(0), Column(5)), Side::Left);
        assert_eq!(u.selection_text().as_deref(), Some("host:22"));

        // Scroll back one line: the top visible row is now history line -1.
        t.scroll(Scroll::Delta(1));
        assert_eq!(t.scroll_position(), (1, 1));
        let (point, _) = t.point_at((0.0, 0.0), cell);
        assert_eq!(point.line, Line(-1));
        t.start_selection(SelectionType::Simple, point, Side::Left);
        t.update_selection(Point::new(Line(-1), Column(2)), Side::Right);
        assert_eq!(t.selection_text().as_deref(), Some("one"));

        let html = t.selection_html().unwrap();
        assert!(html.starts_with("<pre style=") && html.ends_with(">one</span></pre>"), "{html}");

        // A block (column) selection takes the same columns from each line.
        t.start_selection(SelectionType::Block, Point::new(Line(-1), Column(1)), Side::Left);
        t.update_selection(Point::new(Line(0), Column(2)), Side::Right);
        assert_eq!(t.selection_text().as_deref(), Some("ne\nwo"));

        t.select_all();
        assert_eq!(t.selection_text().as_deref(), Some("one\ntwo\nhello world\nlast"));
        t.clear_selection();
        assert_eq!(t.selection_text(), None);
    }

    #[test]
    fn find_walks_matches_and_wraps() {
        let mut t = Terminal::new(20, 3);
        t.feed(b"alpha Beta\r\ngamma beta\r\ndelta (x)\r\nlast");
        // A new search starts at the newest output and goes back.
        assert!(t.find("beta", false, false));
        assert_eq!(t.selection_text().as_deref(), Some("beta"));
        assert!(t.find("beta", false, false));
        assert_eq!(t.selection_text().as_deref(), Some("Beta"));
        // Forward from the older hit finds the newer one again.
        assert!(t.find("beta", false, false));
        assert_eq!(t.selection_text().as_deref(), Some("beta"));
        // Case-sensitive search only finds the capitalised one.
        t.clear_selection();
        assert!(t.find("Beta", true, true));
        assert!(t.find("Beta", true, true));
        assert_eq!(t.selection_text().as_deref(), Some("Beta"));
        // Regex characters are literal.
        assert!(t.find("(x)", false, false));
        assert_eq!(t.selection_text().as_deref(), Some("(x)"));
        assert!(!t.find("missing", false, false));
    }

    #[test]
    fn title_and_bell_are_reported() {
        let mut t = Terminal::new(10, 2);
        t.feed(b"\x1b]0;my host\x07\x07");
        assert_eq!(t.title.as_deref(), Some("my host"));
        assert!(t.take_bell());
        assert!(!t.take_bell());
    }

    #[test]
    fn user_schemes_and_cursor_selection_colours() {
        assert_eq!((parse_hex("#0a0B1f"), parse_hex("0a0b1f"), parse_hex("#12")), (Some([10, 11, 31]), Some([10, 11, 31]), None));
        let dark = scheme_named("OpenCRT Dark");
        let mut def = crate::config::SchemeDef::from_scheme("Mine", dark);
        assert_eq!(def.cursor, "#f8b332");
        set_user_schemes(std::slice::from_ref(&def));
        let mine = scheme_named("Mine");
        assert_eq!((mine.fg, mine.cursor, mine.ansi), (dark.fg, dark.cursor, dark.ansi));
        def.ansi[0] = "nope".into();
        assert!(def.to_scheme().is_none());
        def.ansi[0] = "#000000".into();
        def.cursor.clear();
        assert_eq!(def.to_scheme().unwrap().cursor, None);

        // A block cursor takes the scheme's cursor colour; selected cells its selection colour.
        let mut t = Terminal::new(4, 1);
        t.scheme = dark;
        t.feed(b"ab");
        t.start_selection(SelectionType::Simple, Point::new(Line(0), Column(0)), Side::Left);
        t.update_selection(Point::new(Line(0), Column(0)), Side::Right);
        let mut cells = Vec::new();
        t.for_each_cell(true, |c| cells.push((c.col, c.fg, c.bg)));
        assert!(cells.contains(&(0, dark.fg, dark.selection.unwrap())));
        assert!(cells.contains(&(2, dark.bg, dark.cursor.unwrap())));
        set_user_schemes(&[]);

        // The "follow the system" scheme is Dark or Light as the window is.
        let mut t = Terminal::new(2, 1);
        t.scheme = scheme_named(FOLLOW_SYSTEM);
        SYSTEM_DARK.store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(t.colours().name, "OpenCRT Light");
        SYSTEM_DARK.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(t.colours().name, "OpenCRT Dark");
    }

    #[test]
    fn built_in_schemes_have_distinct_names_and_readable_text() {
        let mut names: Vec<String> = SCHEMES.iter().map(|s| s.name.to_lowercase()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), SCHEMES.len());
        let light = |c: Rgb| c.iter().map(|&v| v as u32).sum::<u32>();
        for s in SCHEMES {
            assert!(light(s.fg).abs_diff(light(s.bg)) > 200, "{}: text too close to its background", s.name);
        }
        assert_eq!(scheme_named("Dracula").bg, [0x28, 0x2a, 0x36]);
    }

    #[test]
    fn cell_colors_apply_bold_and_inverse() {
        let t = Terminal::new(2, 1);
        let colors = t.term.colors();
        let red = Color::Named(NamedColor::Red);
        let bg = Color::Named(NamedColor::Background);

        let classic = scheme_named("Light grey on black");
        let (fg, _) = cell_colors(red, bg, Flags::BOLD, colors, classic);
        assert_eq!(fg, ANSI16[9]);

        let (fg, back) = cell_colors(red, bg, Flags::INVERSE, colors, classic);
        assert_eq!((fg, back), (DEFAULT_BG, ANSI16[1]));
    }
}
