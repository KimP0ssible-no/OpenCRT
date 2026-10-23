//! Linux: link the C++ runtime OpenH264 needs statically (libstdc++.a, found
//! through the compiler), so the helper still needs nothing beyond glibc.
//! `.cargo/config.toml` keeps cc from asking for the shared one.

include!("../../packaging/windows/resources.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // Released as part of OpenCRT, so it carries OpenCRT's version.
        println!("cargo:rerun-if-changed=../opencrt/Cargo.toml");
        windows_resources(&package_version("../opencrt/Cargo.toml"), "OpenCRT remote desktop helper", None);
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let compiler = std::env::var("CXX").unwrap_or_else(|_| "c++".into());
    let found = std::process::Command::new(&compiler).arg("-print-file-name=libstdc++.a").output();
    match found.ok().map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string()) {
        // The compiler echoes the bare name back when it has no such file.
        Some(path) if std::path::Path::new(&path).is_absolute() => println!("cargo:rustc-link-arg={path}"),
        _ => panic!("{compiler} has no static libstdc++ (libstdc++.a): install it (libstdc++-static, libstdc++-<n>-dev)"),
    }
}
