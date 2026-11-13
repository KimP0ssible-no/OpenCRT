//! Interface languages: the translations built in from `lang/` and the choice
//! in Global Options. Slint translates the UI's own text; `tr!` translates the
//! texts the Rust code shows, from the same `.po` files.

use std::collections::HashMap;
use std::sync::RwLock;

include!(concat!(env!("OUT_DIR"), "/languages.rs"));

/// The current language's translations by English text; None for English.
static CURRENT: RwLock<Option<HashMap<String, String>>> = RwLock::new(None);

/// `text` in the interface language, with `{}` (or `{0}`, `{1}`...) filled from
/// the arguments in order: `tr!("Cannot load {}: {}", path, e)`.
#[macro_export]
macro_rules! tr {
    ($text:literal $(, $arg:expr)* $(,)?) => {
        $crate::lang::tr($text, &[$(&$arg as &dyn std::fmt::Display),*])
    };
}

/// A language's name in that language, for the Language list.
pub fn native_name(code: &str) -> &str {
    let traditional = ["TW", "HK", "MO", "Hant"].iter().any(|r| code.contains(r));
    match code.split(['_', '-']).next().unwrap_or(code) {
        "zh" if traditional => "繁體中文",
        "zh" => "简体中文",
        "bg" => "Български",
        "cs" => "Čeština",
        "da" => "Dansk",
        "de" => "Deutsch",
        "el" => "Ελληνικά",
        "es" => "Español",
        "et" => "Eesti",
        "fi" => "Suomi",
        "fr" => "Français",
        "ga" => "Gaeilge",
        "hr" => "Hrvatski",
        "hu" => "Magyar",
        "it" => "Italiano",
        "ja" => "日本語",
        "ko" => "한국어",
        "lt" => "Lietuvių",
        "lv" => "Latviešu",
        "mt" => "Malti",
        "nb" | "no" => "Norsk bokmål",
        "nl" => "Nederlands",
        "pl" => "Polski",
        "pt" => "Português",
        "ro" => "Română",
        "ru" => "Русский",
        "sk" => "Slovenčina",
        "sl" => "Slovenščina",
        "sv" => "Svenska",
        "uk" => "Українська",
        _ => code,
    }
}

/// The Language menu's groups of built-in languages, each by its own names:
/// outside Europe (top level), then Western and Southern, Northern, and
/// Central and Eastern Europe (submenus, so no menu is taller than a window).
pub fn menu_groups() -> [Vec<&'static str>; 4] {
    let group = |code: &str| match code.split(['_', '-']).next().unwrap_or(code) {
        "de" | "el" | "es" | "fr" | "ga" | "it" | "mt" | "nl" | "pt" => 1,
        "da" | "et" | "fi" | "lt" | "lv" | "nb" | "no" | "sv" => 2,
        "bg" | "cs" | "hr" | "hu" | "pl" | "ro" | "sk" | "sl" | "uk" => 3,
        _ => 0,
    };
    let mut groups: [Vec<&'static str>; 4] = Default::default();
    for code in LANGUAGES {
        groups[group(code)].push(code);
    }
    for g in &mut groups {
        g.sort_by_key(|c| native_name(c).to_lowercase());
    }
    groups
}

/// Show the interface in `code`: "" follows the system, "en" is English.
pub fn apply(code: &str) {
    if LANGUAGES.is_empty() {
        return;
    }
    let code = if code.is_empty() { system(sys_locale::get_locale().as_deref().unwrap_or("")) } else { code };
    // A language no longer built in falls back to English.
    let code = if slint::select_bundled_translation(code).is_ok() { code } else { "" };
    let _ = slint::select_bundled_translation(code);
    let catalogue = CATALOGUES.iter().find(|(l, _)| *l == code).map(|(_, po)| parse_po(po));
    *CURRENT.write().unwrap() = catalogue;
}

pub fn tr(text: &str, args: &[&dyn std::fmt::Display]) -> String {
    let current = CURRENT.read().unwrap();
    let template = current.as_ref().and_then(|c| c.get(text)).map_or(text, String::as_str);
    fill(template, args)
}

/// `{}` takes the next argument, `{N}` argument N; `{{` and `}}` are braces.
fn fill(template: &str, args: &[&dyn std::fmt::Display]) -> String {
    let (mut out, mut next, mut rest) = (String::new(), 0, template);
    while let Some(i) = rest.find(['{', '}']) {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        if rest.starts_with("{{") || rest.starts_with("}}") {
            out.push_str(&rest[..1]);
            rest = &rest[2..];
        } else if let Some(end) = rest.find('}').filter(|_| rest.starts_with('{')) {
            let index = if end == 1 { next += 1; next - 1 } else { rest[1..end].parse().unwrap_or(usize::MAX) };
            match args.get(index) {
                Some(arg) => out.push_str(&arg.to_string()),
                None => out.push_str(&rest[..=end]),
            }
            rest = &rest[end + 1..];
        } else {
            out.push_str(&rest[..1]);
            rest = &rest[1..];
        }
    }
    out + rest
}

/// The translated texts of a `.po` file by their English text (first plural
/// form; untranslated entries and the header are left out).
fn parse_po(po: &str) -> HashMap<String, String> {
    let mut texts = HashMap::new();
    let (mut id, mut text, mut field) = (String::new(), String::new(), "");
    let quoted = |s: &str| unescape(s.trim().trim_start_matches('"').trim_end_matches('"'));
    for line in po.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("msgid ") {
            keep(&mut texts, &mut id, &mut text);
            (field, id) = ("id", quoted(rest));
        } else if let Some(rest) = line.strip_prefix("msgstr ").or_else(|| line.strip_prefix("msgstr[0] ")) {
            field = "str";
            text.push_str(&quoted(rest));
        } else if line.starts_with("msg") {
            field = "";
        } else if line.starts_with('"') {
            match field {
                "id" => id.push_str(&quoted(line)),
                "str" => text.push_str(&quoted(line)),
                _ => {}
            }
        }
    }
    keep(&mut texts, &mut id, &mut text);
    texts
}

fn keep(texts: &mut HashMap<String, String>, id: &mut String, text: &mut String) {
    let (id, text) = (std::mem::take(id), std::mem::take(text));
    if !id.is_empty() && !text.is_empty() {
        texts.insert(id, text);
    }
}

fn unescape(s: &str) -> String {
    let (mut out, mut chars) = (String::new(), s.chars());
    while let Some(c) = chars.next() {
        out.push(match (c, c == '\\') {
            (_, true) => match chars.next() {
                Some('n') => '\n',
                Some('t') => '\t',
                Some('r') => '\r',
                Some(other) => other,
                None => break,
            },
            (c, false) => c,
        });
    }
    out
}

/// The built-in language for a system locale such as "zh-CN", else "" (English).
fn system(locale: &str) -> &'static str {
    let base = |l: &str| l.split(['_', '-', '@']).next().unwrap_or("").to_string();
    let exact = LANGUAGES.iter().find(|l| l.replace('_', "-").eq_ignore_ascii_case(&locale.replace('_', "-")));
    exact.or_else(|| LANGUAGES.iter().find(|l| base(l) == base(locale) && !base(locale).is_empty())).copied().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn languages_by_locale() {
        assert_eq!(native_name("zh_CN"), "简体中文");
        assert_eq!(native_name("zh_TW"), "繁體中文");
        assert_eq!(native_name("xx"), "xx");
        if LANGUAGES.is_empty() {
            assert_eq!(system("zh-CN"), "", "without built-in languages every locale means English");
        }
    }

    #[test]
    fn texts_fill_and_translate() {
        assert_eq!(fill("Cannot load {}: {}", &[&"a.ini", &"no file"]), "Cannot load a.ini: no file");
        assert_eq!(fill("{1} before {0}, {{braces}}", &[&1, &2]), "2 before 1, {braces}");
        let po = "msgid \"\"\nmsgstr \"Content-Type: text/plain; charset=UTF-8\\n\"\n\n#: x\nmsgid \"Cannot load {}: {}\"\nmsgstr \"\"\n\"Kann {} nicht laden: {}\"\n\nmsgid \"Say \\\"hi\\\"\"\nmsgstr \"\"\n\nmsgid \"{n} tab\"\nmsgid_plural \"{n} tabs\"\nmsgstr[0] \"{n} Tab\"\nmsgstr[1] \"{n} Tabs\"\n";
        let texts = parse_po(po);
        assert_eq!(texts.get("Cannot load {}: {}").map(String::as_str), Some("Kann {} nicht laden: {}"));
        assert_eq!(texts.get("{n} tab").map(String::as_str), Some("{n} Tab"));
        assert!(!texts.contains_key("Say \"hi\"") && !texts.contains_key(""), "untranslated and the header are left out");
    }

    /// Every `tr!` text must be in lang/opencrt.pot (lang/update-template.sh adds them).
    #[test]
    fn rust_texts_are_in_the_template() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let template = std::fs::read_to_string(dir.join("lang/opencrt.pot")).unwrap();
        let mut missing = Vec::new();
        for entry in std::fs::read_dir(dir.join("src")).unwrap().flatten() {
            let source = std::fs::read_to_string(entry.path()).unwrap_or_default();
            let parts: Vec<&str> = source.split("tr!(\"").collect();
            for (before, part) in parts.iter().zip(&parts[1..]) {
                // `tr!` itself, not the end of `include_str!` and the like.
                if before.ends_with(|c: char| c.is_alphanumeric() || c == '_') {
                    continue;
                }
                let end = part.char_indices().find(|&(j, c)| c == '"' && !part[..j].ends_with('\\')).map_or(0, |(j, _)| j);
                let text = &part[..end];
                if !template.contains(&format!("msgid \"{text}\"")) {
                    missing.push(format!("{}: {text}", entry.file_name().to_string_lossy()));
                }
            }
        }
        assert!(missing.is_empty(), "run lang/update-template.sh; missing from opencrt.pot:\n{}", missing.join("\n"));
    }
}
