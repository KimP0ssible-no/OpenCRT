#!/bin/sh
# Prove the repositories from build-repos.sh update OpenCRT: in Debian, Fedora,
# Rocky Linux 8 and Arch containers, set up the repository as the published
# instructions say, install the old version, upgrade, and check the new one
# is installed.
#   packaging/linux/test-repos.sh <repo folder built for http://127.0.0.1:8765> \
#       <old .pkg.tar.zst> <old version> <new version>
# Needs docker and python3.
set -eu
repo=$(cd "$1" && pwd)
old_arch=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
old=$3
new=$4
url=http://127.0.0.1:8765

python3 -m http.server 8765 --bind 127.0.0.1 --directory "$repo" > /dev/null 2>&1 &
server=$!
trap 'kill $server' EXIT
sleep 1

run() { docker run --rm --network host -v "$old_arch:/old.pkg.tar.zst:ro" "$@"; }

echo "== Debian 12"
run debian:12 sh -euc "
    apt-get -qq update && apt-get -qq install -y curl ca-certificates > /dev/null
    install -d /etc/apt/keyrings
    curl -fsSL $url/opencrt.asc > /etc/apt/keyrings/opencrt.asc
    echo 'deb [signed-by=/etc/apt/keyrings/opencrt.asc] $url/apt stable main' > /etc/apt/sources.list.d/opencrt.list
    apt-get -qq update
    apt-get -qq install -y opencrt=$old-1 > /dev/null
    apt-get -qq install -y --only-upgrade opencrt > /dev/null
    test \"\$(dpkg-query -W -f='\${Version}' opencrt)\" = $new-1"

for image in fedora:latest rockylinux:8; do
    echo "== $image"
    run "$image" sh -euc "
        curl -fsSL -o /etc/yum.repos.d/opencrt.repo $url/rpm/opencrt.repo
        dnf -q -y install opencrt-$old > /dev/null
        dnf -q -y upgrade opencrt > /dev/null
        test \"\$(rpm -q --qf '%{VERSION}' opencrt)\" = $new"
done

echo "== Arch Linux"
run archlinux:latest sh -euc "
    pacman-key --init > /dev/null 2>&1
    curl -fsSL $url/opencrt.asc | pacman-key --add - > /dev/null
    fingerprint=\$(curl -fsSL $url/opencrt.asc | gpg --with-colons --import-options show-only --import 2>/dev/null | awk -F: '/^fpr/ { print \$10; exit }')
    pacman-key --lsign-key \"\$fingerprint\" > /dev/null 2>&1
    printf '\n[opencrt]\nServer = $url/arch\n' >> /etc/pacman.conf
    pacman -U --noconfirm /old.pkg.tar.zst > /dev/null
    pacman -Sy --noconfirm opencrt > /dev/null
    test \"\$(pacman -Q opencrt)\" = 'opencrt $new-1'"
echo "all repositories upgrade $old to $new"
