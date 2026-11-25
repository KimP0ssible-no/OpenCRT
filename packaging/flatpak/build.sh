#!/bin/sh
# Wrap the glibc 2.28 Linux binaries (build-portable.sh, or CI's AlmaLinux 8
# build) into a Flatpak bundle for this machine's architecture:
#   packaging/flatpak/build.sh <binaries folder> <notices folder> <output folder>
# The folders hold opencrt, opencrt-rdp and ocrt, and THIRD-PARTY-NOTICES*.html.
# Needs flatpak and flatpak-builder; the runtime and SDK come from Flathub
# (installed for the user). Output: OpenCRT-<version>-<arch>.flatpak.
set -eu
bin=$1
notices=$2
out=$3
root=$(cd "$(dirname "$0")/../.." && pwd)
arch=$(uname -m)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/crates/opencrt/Cargo.toml" | head -1)

work=$root/target/flatpak
rm -rf "$work"
mkdir -p "$work/input" "$out"
in=$work/input
for b in opencrt opencrt-rdp ocrt; do
    install -m 755 "$bin/$b" "$in/$b"
done
cp "$root/LICENSE" "$root/NOTICE" "$root/SLINT-LICENSE.md" "$root/crates/opencrt/ui/fonts/OFL.txt" "$notices"/THIRD-PARTY-NOTICES*.html "$in/"
cp "$root/packaging/linux/opencrt.desktop" "$root/crates/opencrt/ui/opencrt.svg" "$root"/packaging/icons/opencrt-*.png "$in/"
cp "$root/packaging/flatpak/org.opencrt.OpenCRT.metainfo.xml" "$in/"

flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak-builder --user --install-deps-from=flathub --disable-rofiles-fuse --force-clean --repo="$work/repo" \
    --state-dir="$work/state" "$work/build" "$root/packaging/flatpak/org.opencrt.OpenCRT.yml"
bundle=$(cd "$out" && pwd)/OpenCRT-$version-$arch.flatpak
flatpak build-bundle --runtime-repo=https://dl.flathub.org/repo/flathub.flatpakrepo "$work/repo" "$bundle" org.opencrt.OpenCRT
echo "$bundle"
