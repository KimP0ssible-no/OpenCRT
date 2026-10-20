#!/bin/sh
# Build the Windows executables and the Inno Setup installer on Linux, in
# Docker: MinGW cross-compiles (x86_64-pc-windows-gnu, runtime linked in) and
# Inno Setup runs under Wine. Output: dist/opencrt-<version>-x64-setup.exe.
# Run from the repository root after generating the third-party notices
# (see docs/packaging.md). The CI builds the MSVC version on Windows instead.
#
#   packaging/windows/build-cross.sh
set -eu
mkdir -p dist
# Toolchain, crates, Wine and Inno Setup are kept in the opencrt-windows-cross volume.
docker run --rm -v "$PWD":/src -w /src -v opencrt-windows-cross:/cache \
    -e CARGO_HOME=/cache/cargo -e RUSTUP_HOME=/cache/rustup -e WINEPREFIX=/cache/wine \
    -e WINEDEBUG=-all -e HOST_IDS="$(id -u):$(id -g)" debian:trixie sh -euc '
    export DEBIAN_FRONTEND=noninteractive
    dpkg --add-architecture i386
    apt-get -qq update
    apt-get -qq install -y --no-install-recommends gcc libc6-dev gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 nasm curl ca-certificates \
        wine wine32:i386 wine64 xvfb xauth >/dev/null
    /cache/cargo/bin/rustc --version >/dev/null 2>&1 || curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --no-modify-path
    export PATH=/cache/cargo/bin:$PATH
    rustup target add x86_64-pc-windows-gnu >/dev/null
    export CARGO_TARGET_DIR=target/windows-cross
    cargo build --release --target x86_64-pc-windows-gnu
    cargo build --release --target x86_64-pc-windows-gnu --manifest-path crates/opencrt-rdp/Cargo.toml

    iscc="/cache/wine/drive_c/InnoSetup/ISCC.exe"
    if [ ! -f "$iscc" ]; then
        # A fully set-up prefix first, or Inno Setup cannot find Program Files.
        rm -rf "$WINEPREFIX"
        xvfb-run -a wineboot --init
        wineserver -w
        curl -sSfL -o /tmp/is.exe https://github.com/jrsoftware/issrc/releases/download/is-6_7_3/innosetup-6.7.3.exe
        xvfb-run -a wine /tmp/is.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CURRENTUSER /DIR="C:\\InnoSetup"
        wineserver -w
    fi
    xvfb-run -a wine "$iscc" /Q /DBinDir="Z:\\src\\target\\windows-cross\\x86_64-pc-windows-gnu\\release" \
        /O"Z:\\src\\dist" packaging/windows/opencrt.iss
    chown -R "$HOST_IDS" target/windows-cross dist
'
