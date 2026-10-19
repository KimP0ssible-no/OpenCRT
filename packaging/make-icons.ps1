# Renders the OpenCRT icon (same design as crates/opencrt/ui/opencrt.svg) to
# PNGs and a multi-size Windows .ico. Run from the repository root:
#   powershell -ExecutionPolicy Bypass -File packaging/make-icons.ps1
Add-Type -AssemblyName System.Drawing
$out = Join-Path $PSScriptRoot 'icons'
New-Item -ItemType Directory -Force $out | Out-Null

function Render([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.ScaleTransform($size / 64.0, $size / 64.0)
    $round = {
        param($x, $y, $w, $h, $r)
        $p = New-Object System.Drawing.Drawing2D.GraphicsPath
        $p.AddArc($x, $y, 2 * $r, 2 * $r, 180, 90)
        $p.AddArc($x + $w - 2 * $r, $y, 2 * $r, 2 * $r, 270, 90)
        $p.AddArc($x + $w - 2 * $r, $y + $h - 2 * $r, 2 * $r, 2 * $r, 0, 90)
        $p.AddArc($x, $y + $h - 2 * $r, 2 * $r, 2 * $r, 90, 90)
        $p.CloseFigure()
        $p
    }
    $body = & $round 3 6 58 52 8
    $g.FillPath((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(0x1d, 0x27, 0x31))), $body)
    $g.SetClip($body)
    $g.FillRectangle((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(0x3c, 0x5a, 0x70))), 3, 6, 58, 12)
    $g.ResetClip()
    $light = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(0xe8, 0xe8, 0xe8))
    $g.FillEllipse($light, 9, 10, 4, 4)
    $g.FillEllipse($light, 16, 10, 4, 4)
    $green = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(0x4a, 0xde, 0x80)), 4.5
    $green.StartCap = 'Round'; $green.EndCap = 'Round'; $green.LineJoin = 'Round'
    $g.DrawLines($green, [System.Drawing.PointF[]]@((New-Object System.Drawing.PointF 15, 29), (New-Object System.Drawing.PointF 25, 37), (New-Object System.Drawing.PointF 15, 45)))
    $white = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(0xe8, 0xe8, 0xe8)), 4.5
    $white.StartCap = 'Round'; $white.EndCap = 'Round'
    $g.DrawLine($white, 30, 46, 46, 46)
    $g.Dispose()
    $bmp
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$pngs = @{}
foreach ($size in $sizes) {
    $bmp = Render $size
    $path = Join-Path $out "opencrt-$size.png"
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    $pngs[$size] = [IO.File]::ReadAllBytes($path)
}

# .ico with PNG-compressed entries (supported since Windows Vista).
$ico = New-Object IO.MemoryStream
$w = New-Object IO.BinaryWriter $ico
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($size in $sizes) {
    $dim = if ($size -ge 256) { 0 } else { $size }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]$pngs[$size].Length); $w.Write([uint32]$offset)
    $offset += $pngs[$size].Length
}
foreach ($size in $sizes) { $w.Write($pngs[$size]) }
[IO.File]::WriteAllBytes((Join-Path $out 'opencrt.ico'), $ico.ToArray())
"icons written to $out"
