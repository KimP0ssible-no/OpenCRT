#!/bin/sh
# Make the Arch Linux package (dist/opencrt-<version>-1-x86_64.pkg.tar.zst)
# in Docker from the portable binaries and the third-party notices; run
# packaging/linux/build-portable.sh and cargo about first (docs/packaging.md).
#
#   packaging/arch/build-arch.sh            # from the repository root
set -eu
docker run --rm -v "$PWD":/src -w /src -e HOST_IDS="$(id -u):$(id -g)" archlinux:latest sh -euc '
    packaging/arch/makepkg.sh
    chown "$HOST_IDS" dist dist/*.pkg.tar.zst
'
