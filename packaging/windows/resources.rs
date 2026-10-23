// Windows resources for both executables' build scripts (`include!`d): version
// information naming OpenCRT and its version, and an optional icon.
// SignPath checks ProductName and ProductVersion before it signs a file.

/// The `version = "x.y.z"` of the `[package]` in a Cargo.toml.
#[allow(dead_code)]
fn package_version(cargo_toml: &str) -> String {
    let text = std::fs::read_to_string(cargo_toml).expect("cannot read Cargo.toml");
    let line = text.lines().find(|l| l.starts_with("version = \"")).expect("no version in Cargo.toml");
    line.trim_start_matches("version = \"").trim_end_matches('"').to_string()
}

fn windows_resources(version: &str, description: &str, icon: Option<&std::path::Path>) {
    let mut numbers: Vec<u16> = version.split('.').map(|n| n.parse().expect("version is not x.y.z")).collect();
    numbers.resize(4, 0);
    let numbers = numbers.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    // rc and windres both take forward slashes, which need no escaping.
    let icon = icon.map(|p| format!("1 ICON \"{}\"\n", p.display().to_string().replace('\\', "/"))).unwrap_or_default();
    let rc = format!(
        r#"{icon}1 VERSIONINFO
FILEVERSION {numbers}
PRODUCTVERSION {numbers}
FILEOS 0x40004
FILETYPE 0x1
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "OpenCRT"
            VALUE "FileDescription", "{description}"
            VALUE "FileVersion", "{version}"
            VALUE "LegalCopyright", "Copyright 2026 Kim Attree"
            VALUE "ProductName", "OpenCRT"
            VALUE "ProductVersion", "{version}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
    );
    let path = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("opencrt.rc");
    std::fs::write(&path, rc).unwrap();
    embed_resource::compile(&path, embed_resource::NONE).manifest_optional().expect("failed to compile Windows resources");
}
