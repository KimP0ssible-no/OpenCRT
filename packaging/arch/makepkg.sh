#!/bin/sh
# Inside Arch Linux, as root, from the repository root: make the package
# into dist/. BIN_DIR and NOTICES_DIR are passed on to the PKGBUILD.
set -eu
root=$(pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/opencrt/Cargo.toml | head -1)
pacman -Syu --noconfirm --needed base-devel >/dev/null
id builder >/dev/null 2>&1 || useradd -m builder
build=$(mktemp -d)
mkdir -p "$build/out" dist
sed "s/^pkgver=.*/pkgver=$version/" packaging/arch/PKGBUILD > "$build/PKGBUILD"
chown -R builder "$build"
# makepkg will not run as root.
su builder -c "cd '$build' && OPENCRT_ROOT='$root' BIN_DIR='${BIN_DIR:-}' NOTICES_DIR='${NOTICES_DIR:-}' PKGDEST='$build/out' makepkg --nodeps --force"
cp "$build"/out/*.pkg.tar.zst dist/
