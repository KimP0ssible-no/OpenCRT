//! Interface languages: the translations built in from `lang/` and the choice
//! in Global Options. Slint follows the system locale by itself.

include!(concat!(env!("OUT_DIR"), "/languages.rs"));

/// A language's name in that language, for the Language list.
pub fn native_name(code: &str) -> &str {
    let traditional = ["TW", "HK", "MO", "Hant"].iter().any(|r| code.contains(r));
    match code.split(['_', '-']).next().unwrap_or(code) {
        "zh" if traditional => "繁體中文",
        "zh" => "简体中文",
        "ja" => "日本語",
        "ko" => "한국어",
        "de" => "Deutsch",
        "es" => "Español",
        "fr" => "Français",
        "it" => "Italiano",
        "nl" => "Nederlands",
        "pl" => "Polski",
        "pt" => "Português",
        "ru" => "Русский",
        _ => code,
    }
}

/// Show the interface in `code`: "" follows the system, "en" is English.
pub fn apply(code: &str) {
    if LANGUAGES.is_empty() {
        return;
    }
    let code = if code.is_empty() { system(sys_locale::get_locale().as_deref().unwrap_or("")) } else { code };
    // A language no longer built in falls back to English.
    if slint::select_bundled_translation(code).is_err() {
        let _ = slint::select_bundled_translation("");
    }
}

/// The built-in language for a system locale such as "zh-CN", else "" (English).
fn system(locale: &str) -> &'static str {
    let base = |l: &str| l.split(['_', '-', '@']).next().unwrap_or("").to_string();
    let exact = LANGUAGES.iter().find(|l| l.replace('_', "-").eq_ignore_ascii_case(&locale.replace('_', "-")));
    exact.or_else(|| LANGUAGES.iter().find(|l| base(l) == base(locale) && !base(locale).is_empty())).copied().unwrap_or("")
}

#[cfg(test)]
mod tests {
    #[test]
    fn languages_by_locale() {
        assert_eq!(super::native_name("zh_CN"), "简体中文");
        assert_eq!(super::native_name("zh_TW"), "繁體中文");
        assert_eq!(super::native_name("xx"), "xx");
        // Without built-in languages every locale means English.
        if super::LANGUAGES.is_empty() {
            assert_eq!(super::system("zh-CN"), "");
        }
    }
}
