include!("../../packaging/windows/resources.rs");

fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/main.slint", config).expect("Slint UI failed to compile");

    // The icon shows in Explorer, taskbar pins and the installer.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let icon = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/icons/opencrt.ico");
        windows_resources(env!("CARGO_PKG_VERSION"), "OpenCRT terminal client", Some(&icon));
    }
}
