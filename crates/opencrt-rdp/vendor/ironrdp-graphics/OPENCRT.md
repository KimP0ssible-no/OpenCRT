# ironrdp-graphics 0.9.0, with three fixes

A copy of [ironrdp-graphics](https://crates.io/crates/ironrdp-graphics) 0.9.0
(Devolutions, MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE), used through
`[patch.crates-io]` in `crates/opencrt-rdp/Cargo.toml`.

- `src/clearcodec/mod.rs` (`ClearCodecDecoder::decode`): Windows reuses
  a cached ClearCodec glyph for any area it covers, taking its first width x height
  pixels (as FreeRDP reads it). 0.9.0 demanded the exact cached size and failed
  with "cached glyph dimensions mismatch".
- `src/progressive.rs` (`prog_quant`): a Progressive tile's quality 0xFF means full
  quality (no progressive quantization), and Windows then sends no quality table;
  0.9.0 looked 255 up in the empty table ("quant index 255 exceeds table length 0").
- `src/progressive.rs` (`ProgressiveDecoder::decode_bitmap`): Windows sends the
  CONTEXT block once and then uses a new codec context id for each picture; the
  last CONTEXT seen is now used for those (as FreeRDP keeps it), instead of
  failing with "progressive stream missing CONTEXT block".

Delete this copy and the patch once a released ironrdp-graphics does the same.
