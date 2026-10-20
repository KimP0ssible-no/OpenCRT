# ironrdp-pdu 0.9.0, with two fixes

A copy of [ironrdp-pdu](https://crates.io/crates/ironrdp-pdu) 0.9.0 (Devolutions,
MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE), used through
`[patch.crates-io]` in `crates/opencrt-rdp/Cargo.toml`.

The first fix, in `src/codecs/clearcodec/bands.rs` (`decode_vbar`): a ClearCodec
SHORT_VBAR_CACHE_MISS header has shortVBarYOn in its first byte (bits 7:0) and
shortVBarYOff in bits 13:8, as Windows sends it and FreeRDP reads it; 0.9.0 read
them from bits 13:6 and 5:0, so every such V-bar from a Windows server failed with
"shortVBarYOff < shortVBarYOn" and ClearCodec pictures (text, window edges) stayed
black.

The second, in `src/codecs/clearcodec/rlex.rs` (`decode_rlex`): with a one-colour
RLEX palette every segment still starts with the packed stopIndex/suiteDepth byte
(a 1-bit stopIndex); 0.9.0 read each byte as a run length instead, so one-colour
areas failed with "suite exceeds region pixel count".

Delete this copy and the patch once a released ironrdp-pdu reads it right.
