# ironrdp-graphics 0.9.0, with fixes for Windows' ClearCodec and Progressive

A copy of [ironrdp-graphics](https://crates.io/crates/ironrdp-graphics) 0.9.0
(Devolutions, MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE), used through
`[patch.crates-io]` in `crates/opencrt-rdp/Cargo.toml`.

- `src/clearcodec/mod.rs` (`ClearCodecDecoder::decode`): Windows reuses
  a cached ClearCodec glyph for any area it covers, taking its first width x height
  pixels (as FreeRDP reads it). 0.9.0 demanded the exact cached size and failed
  with "cached glyph dimensions mismatch".
- `src/clearcodec/nscodec.rs` (new): the NSCodec subcodec ([MS-RDPNSC]), which
  0.9.0 left undrawn ("not yet implemented"); Windows uses it for pictures such as
  album art. Checked against FreeRDP on Windows 11 pictures.
- `src/progressive.rs` (`prog_quant`): a Progressive tile's quality 0xFF means full
  quality (no progressive quantization), and Windows then sends no quality table;
  0.9.0 looked 255 up in the empty table ("quant index 255 exceeds table length 0").
- `src/progressive.rs` (`ProgressiveDecoder::decode_bitmap`): Windows sends the
  CONTEXT block once and then uses a new codec context id for each picture; the
  last CONTEXT seen is now used for those (as FreeRDP keeps it), instead of
  failing with "progressive stream missing CONTEXT block".

- `src/progressive.rs`, checked against FreeRDP's decoder on a recording of a
  Windows 11 desktop (all 106 pictures equal to within 1 per colour value):
  - the coefficients carry 5 fractional bits (dequantization by quant - 1, as for
    RemoteFX), so `reconstruct_to_rgba` divides by 32 in the colour conversion;
    0.9.0 did not, and dark areas came out black, light ones white or grey;
  - RFX_TILE_DIFFERENCE tiles add their coefficients to the tile's current ones;
  - an upgrade pass reads its SRL and raw streams on across all ten bands of a
    component (0.9.0 restarted both at every band), reads LL3 from the raw stream
    only, shifts by quant + progQuant - 1, and keeps the SRL state (a value
    directly after a short zero run; kp starting at 8).

Delete this copy and the patch once a released ironrdp-graphics does the same.
