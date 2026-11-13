#!/bin/sh
# What Skia's ready-made library needs and AlmaLinux 8 lacks, for the glibc
# 2.28 build (run as root in almalinux:8):
# - FreeType 2.10 or newer: built here as a static library in /opt/freetype,
#   so the program does not depend on the system's FreeType version. In lib64:
#   GCC here turns a LIBRARY_PATH entry that ends in lib into lib64.
# - A C++ runtime from GCC 9 or newer: gcc-toolset-12 links the newer symbols
#   into the program, which then runs on AlmaLinux 8's own libstdc++.
# Build OpenCRT afterwards with
#   PATH=/opt/rh/gcc-toolset-12/root/usr/bin:$PATH LIBRARY_PATH=/opt/freetype/lib64
set -eu
version=2.13.3
sha256=0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289
dnf -y -q install gcc-toolset-12-gcc gcc-toolset-12-gcc-c++ fontconfig-devel make xz >/dev/null
# fontconfig-devel brings the system's FreeType 2.9: with its link file gone,
# only the static one below can be linked.
rm -f /usr/lib64/libfreetype.so
[ -f /opt/freetype/lib64/libfreetype.a ] && exit 0
cd "$(mktemp -d)"
curl -sSfL --retry 5 -o freetype.tar.xz "https://download.savannah.gnu.org/releases/freetype/freetype-$version.tar.xz"
echo "$sha256  freetype.tar.xz" | sha256sum -c - >/dev/null
tar xf freetype.tar.xz
cd "freetype-$version"
# No optional libraries: the program then needs none of them at run time.
./configure -q --prefix=/opt/freetype --libdir=/opt/freetype/lib64 --enable-static --disable-shared --with-pic \
    --with-zlib=no --with-bzip2=no --with-png=no --with-harfbuzz=no --with-brotli=no >/dev/null
make -s -j"$(nproc)" >/dev/null
make -s install >/dev/null
