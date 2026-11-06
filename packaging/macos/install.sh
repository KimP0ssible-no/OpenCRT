#!/bin/sh
# Install or upgrade OpenCRT on macOS from the latest GitHub release:
#   curl -fsSL https://raw.githubusercontent.com/KimP0ssible-no/OpenCRT/main/packaging/macos/install.sh | sh
# A disk image fetched with curl is not quarantined, so macOS opens the app
# without the Open Anyway step a browser download needs.
set -eu

base=https://github.com/KimP0ssible-no/OpenCRT/releases/latest/download
dest=/Applications
[ -w "$dest" ] || { dest=$HOME/Applications; mkdir -p "$dest"; }

if pgrep -xq opencrt; then
    echo "Quit OpenCRT first, then run this again." >&2
    exit 1
fi

tmp=$(mktemp -d)
trap 'hdiutil detach -quiet "$tmp/mnt" 2>/dev/null || true; rm -rf "$tmp"' EXIT

echo "Downloading OpenCRT..."
curl -fsSL -o "$tmp/OpenCRT.dmg" "$base/OpenCRT.dmg"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
(cd "$tmp" && grep '  OpenCRT.dmg$' SHA256SUMS | shasum -a 256 -c - > /dev/null) || {
    echo "The download does not match SHA256SUMS; nothing was installed." >&2
    exit 1
}

hdiutil attach -quiet -nobrowse -readonly -noautoopen -mountpoint "$tmp/mnt" "$tmp/OpenCRT.dmg"
rm -rf "$dest/.OpenCRT.app.new"
ditto "$tmp/mnt/OpenCRT.app" "$dest/.OpenCRT.app.new"
rm -rf "$dest/OpenCRT.app"
mv "$dest/.OpenCRT.app.new" "$dest/OpenCRT.app"
# A new modification time makes the Dock and Finder read the icon again.
touch "$dest/OpenCRT.app"

echo "OpenCRT is installed in $dest."
open "$dest/OpenCRT.app"
