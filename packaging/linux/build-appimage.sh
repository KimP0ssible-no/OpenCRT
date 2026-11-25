#!/bin/sh
# Wrap the glibc 2.28 Linux binaries (build-portable.sh, or CI's AlmaLinux 8
# build) into an AppImage for this machine's architecture:
#   packaging/linux/build-appimage.sh <binaries folder> <notices folder> <output folder>
# The folders hold opencrt, opencrt-rdp and ocrt, and THIRD-PARTY-NOTICES*.html.
# appimagetool and the AppImage runtime are pinned release files, checked by
# their SHA-256. Needs curl; no FUSE (the tool runs unpacked).
set -eu
bin=$1
notices=$2
out=$3
root=$(cd "$(dirname "$0")/../.." && pwd)
arch=$(uname -m)
case $arch in
    x86_64)
        tool_sha=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
        runtime_sha=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d ;;
    aarch64)
        tool_sha=f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158
        runtime_sha=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444 ;;
    *) echo "no AppImage tools for $arch" >&2; exit 1 ;;
esac
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/crates/opencrt/Cargo.toml" | head -1)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() {
    curl -sSfL --retry 5 -o "$work/$1" "$2"
    echo "$3  $work/$1" | sha256sum -c - > /dev/null
}
fetch appimagetool "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-$arch.AppImage" "$tool_sha"
fetch runtime "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-$arch" "$runtime_sha"
chmod +x "$work/appimagetool"

app=$work/OpenCRT.AppDir
mkdir -p "$app/usr/bin" "$app/usr/share/doc/opencrt" "$app/usr/share/icons/hicolor/256x256/apps"
for b in opencrt opencrt-rdp ocrt; do
    install -m 755 "$bin/$b" "$app/usr/bin/$b"
done
cp "$root/LICENSE" "$root/NOTICE" "$root/SLINT-LICENSE.md" "$root/crates/opencrt/ui/fonts/OFL.txt" "$notices"/THIRD-PARTY-NOTICES*.html "$app/usr/share/doc/opencrt/"
cp "$root/packaging/linux/opencrt.desktop" "$app/"
cp "$root/packaging/icons/opencrt-256.png" "$app/opencrt.png"
cp "$root/packaging/icons/opencrt-256.png" "$app/usr/share/icons/hicolor/256x256/apps/opencrt.png"
ln -s opencrt.png "$app/.DirIcon"
# The program itself: the RDP helper is found beside it, in usr/bin.
ln -s usr/bin/opencrt "$app/AppRun"

mkdir -p "$out"
image=$(cd "$out" && pwd)/OpenCRT-$version-$arch.AppImage
ARCH=$arch "$work/appimagetool" --appimage-extract-and-run --no-appstream --runtime-file "$work/runtime" "$app" "$image"

# What the AppImage holds, unpacked as a user's system would see it.
(cd "$work" && "$image" --appimage-extract > /dev/null)
for f in AppRun opencrt.desktop opencrt.png usr/bin/opencrt usr/bin/opencrt-rdp usr/bin/ocrt usr/share/doc/opencrt/LICENSE; do
    test -e "$work/squashfs-root/$f" || { echo "the AppImage lacks $f" >&2; exit 1; }
done
echo "$image"
