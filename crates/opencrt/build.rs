fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/main.slint", config).expect("Slint UI failed to compile");

    // Give the Windows executable its icon (Explorer, taskbar pins, installer).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("../../packaging/windows/opencrt.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("failed to compile Windows resources");
    }
}
