# ironrdp-graphics 0.9.0, with one fix

A copy of [ironrdp-graphics](https://crates.io/crates/ironrdp-graphics) 0.9.0
(Devolutions, MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE), used through
`[patch.crates-io]` in `crates/opencrt-rdp/Cargo.toml`.

The fix, in `src/clearcodec/mod.rs` (`ClearCodecDecoder::decode`): Windows reuses
a cached ClearCodec glyph for any area it covers, taking its first width x height
pixels (as FreeRDP reads it). 0.9.0 demanded the exact cached size and failed with
"cached glyph dimensions mismatch".

Delete this copy and the patch once a released ironrdp-graphics does the same.
