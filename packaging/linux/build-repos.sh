#!/bin/sh
# Build the signed APT, DNF/Zypper and pacman repositories that GitHub Pages
# serves, from release packages:
#   packaging/linux/build-repos.sh <packages folder> <output folder> <base URL>
# The folder holds the .deb, .rpm and .pkg.tar.zst files of the releases to
# offer (newest Arch package wins: a pacman repository has one per name).
# Signs with the OpenPGP key $REPO_KEY_ID from gpg's keyring: the .rpm
# packages, each Arch package and every repository's metadata.
# Needs apt-utils, createrepo-c, rpm, pacman-package-manager, makepkg,
# libarchive-tools, zstd and gnupg (Debian 13).
set -eu
src=$1
out=$2
url=$3
key=${REPO_KEY_ID:?REPO_KEY_ID is the signing key}
sign() { gpg --batch --yes --local-user "$key" "$@"; }

mkdir -p "$out/apt/pool/main" "$out/apt/dists/stable/main/binary-amd64" "$out/rpm" "$out/arch"
gpg --batch --yes --armor --export "$key" > "$out/opencrt.asc"

cp "$src"/*.deb "$out/apt/pool/main/"
(
    cd "$out/apt"
    apt-ftparchive packages pool > dists/stable/main/binary-amd64/Packages
    gzip -9kf dists/stable/main/binary-amd64/Packages
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=OpenCRT -o APT::FTPArchive::Release::Label=OpenCRT \
        -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable \
        -o APT::FTPArchive::Release::Architectures=amd64 -o APT::FTPArchive::Release::Components=main \
        release dists/stable > dists/stable/Release
    sign --clearsign --output dists/stable/InRelease dists/stable/Release
    sign --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
)

cp "$src"/*.rpm "$out/rpm/"
rpmsign --define "_gpg_name $key" --addsign "$out"/rpm/*.rpm > /dev/null
createrepo_c --quiet "$out/rpm"
sign --armor --detach-sign "$out/rpm/repodata/repomd.xml"
cat > "$out/rpm/opencrt.repo" <<EOF
[opencrt]
name=OpenCRT
baseurl=$url/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$url/opencrt.asc
EOF

newest=$(ls "$src"/*.pkg.tar.zst | sort -V | tail -n 1)
cp "$newest" "$out/arch/"
sign --detach-sign "$out/arch/$(basename "$newest")"
repo-add --quiet --sign --key "$key" "$out/arch/opencrt.db.tar.zst" "$out/arch/$(basename "$newest")"
# repo-add reports some failures (a missing compressor) only on stderr.
test -s "$out/arch/opencrt.db.tar.zst"
# Pages serves no symbolic links: the names pacman asks for become copies.
for name in opencrt.db opencrt.db.sig opencrt.files opencrt.files.sig; do
    cp --remove-destination "$out/arch/${name%%.sig}.tar.zst${name#"${name%%.sig}"}" "$out/arch/$name"
done

fingerprint=$(gpg --batch --with-colons --fingerprint "$key" | awk -F: '/^fpr/ { print $10; exit }')
sed -e "s|@URL@|$url|g" -e "s|@FINGERPRINT@|$fingerprint|g" "$(dirname "$0")/repo-index.html" > "$out/index.html"
