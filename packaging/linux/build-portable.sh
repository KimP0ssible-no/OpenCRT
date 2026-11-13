#!/bin/sh
# Build the Linux release binaries against glibc 2.28 (AlmaLinux 8) so the
# .deb and .rpm run on RHEL/Rocky/Alma 8+, Fedora, Debian 10+ and Ubuntu 20.04+.
# They link glibc and, for Skia in opencrt, fontconfig and the C++ runtime
# (see skia-deps.sh); the display libraries are loaded at run time. Output:
# target/portable/release/.
#
#   packaging/linux/build-portable.sh            # from the repository root
set -eu
# The toolchain and crate downloads are kept in the opencrt-linux-cargo volume.
docker run --rm -v "$PWD":/src -w /src -v opencrt-linux-cargo:/cargo \
    -e CARGO_HOME=/cargo -e RUSTUP_HOME=/cargo/rustup \
    -e HOST_IDS="$(id -u):$(id -g)" almalinux:8 sh -euc '
    dnf -y -q --enablerepo=powertools install gcc gcc-c++ libstdc++-static make perl git >/dev/null
    sh packaging/linux/skia-deps.sh
    /cargo/bin/rustc --version >/dev/null 2>&1 || curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --no-modify-path
    export PATH=/cargo/bin:$PATH
    export CARGO_TARGET_DIR=target/portable
    # Skia: the newer GCC and the static FreeType (see skia-deps.sh).
    PATH=/opt/rh/gcc-toolset-12/root/usr/bin:$PATH LIBRARY_PATH=/opt/freetype/lib64 cargo build --release
    cargo build --release --manifest-path crates/opencrt-rdp/Cargo.toml
    chown -R "$HOST_IDS" target/portable
'
