include!("../../packaging/windows/resources.rs");

fn main() {
    // Translations: every lang/<locale>/LC_MESSAGES/opencrt.po is built in, one
    // translation per text rather than per component (see lang/README.md).
    println!("cargo:rerun-if-changed=lang");
    let mut languages: Vec<String> = std::fs::read_dir("lang")
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join("LC_MESSAGES/opencrt.po").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    languages.sort();
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("languages.rs");
    std::fs::write(out, format!("pub const LANGUAGES: &[&str] = &{languages:?};\n")).unwrap();
    let mut config = slint_build::CompilerConfiguration::new()
        .with_style("fluent".into())
        .with_default_translation_context(slint_build::DefaultTranslationContext::None);
    // Slint refuses an empty translation folder.
    if !languages.is_empty() {
        config = config.with_bundled_translations("lang");
    }
    slint_build::compile_with_config("ui/main.slint", config).expect("Slint UI failed to compile");

    // The icon shows in Explorer, taskbar pins and the installer.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let icon = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/icons/opencrt.ico");
        windows_resources(env!("CARGO_PKG_VERSION"), "OpenCRT terminal client", Some(&icon));
    }
}
