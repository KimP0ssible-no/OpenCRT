#!/bin/sh
# Write OpenCRT's version into every file that carries it. CI runs this on a
# release tag vX.Y.Z before building; main itself stays at 0.0.0.
# Usage (from the repository root): sh packaging/set-version.sh X.Y.Z
set -eu
v=${1:-}
echo "$v" | grep -qxE '[0-9]+\.[0-9]+\.[0-9]+' || { echo "usage: $0 X.Y.Z" >&2; exit 1; }
edit() {
    file=$1 program=$2 expect=$3
    # Lines without CR, so a Windows (CRLF) checkout matches too.
    awk -v v="$v" "{ sub(/\r\$/, \"\") } $program" "$file" > "$file.new"
    mv "$file.new" "$file"
    grep -qxF "$expect" "$file" || { echo "$file: no $expect" >&2; exit 1; }
}
edit crates/opencrt/Cargo.toml '!done && /^version = "/ { sub(/"[^"]*"/, "\"" v "\""); done = 1 } 1' "version = \"$v\""
for lock in Cargo.lock crates/opencrt/fuzz/Cargo.lock; do
    edit "$lock" 'prev == "name = \"opencrt\"" && /^version = "/ { sub(/"[^"]*"/, "\"" v "\"") } { print; prev = $0 }' "version = \"$v\""
done
edit packaging/arch/PKGBUILD '/^pkgver=/ { sub(/=.*/, "=" v) } 1' "pkgver=$v"
edit packaging/windows/opencrt.iss '/^#define AppVersion "/ { sub(/"[^"]*"/, "\"" v "\"") } 1' "#define AppVersion \"$v\""
