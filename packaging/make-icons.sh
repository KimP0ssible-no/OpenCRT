#!/bin/sh
# Renders the OpenCRT icon (crates/opencrt/ui/opencrt.svg) to PNGs and a
# multi-size Windows .ico. Needs resvg (cargo install resvg) and python3.
# Run from the repository root: sh packaging/make-icons.sh
set -eu
svg=crates/opencrt/ui/opencrt.svg
out=packaging/icons
sizes="16 24 32 48 64 128 256"
for size in $sizes; do
    resvg -w "$size" -h "$size" "$svg" "$out/opencrt-$size.png"
done
# .ico with PNG-compressed entries (supported since Windows Vista).
python3 -I - "$out" $sizes <<'EOF'
import struct, sys
out, sizes = sys.argv[1], [int(s) for s in sys.argv[2:]]
pngs = [open(f"{out}/opencrt-{s}.png", "rb").read() for s in sizes]
ico = struct.pack("<HHH", 0, 1, len(sizes))
offset = 6 + 16 * len(sizes)
for size, png in zip(sizes, pngs):
    dim = 0 if size >= 256 else size
    ico += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
    offset += len(png)
open(f"{out}/opencrt.ico", "wb").write(ico + b"".join(pngs))
EOF
echo "icons written to $out"
