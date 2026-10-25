// libFuzzer and OpenH264 are C++; .cargo/config.toml keeps cc from linking
// its runtime, which the shipped binaries avoid but these need.
fn main() {
    println!("cargo:rustc-link-lib=stdc++");
}
