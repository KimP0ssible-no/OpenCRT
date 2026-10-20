# ironrdp-egfx 0.3.0, with three fixes

A copy of [ironrdp-egfx](https://crates.io/crates/ironrdp-egfx) 0.3.0 (Devolutions,
MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE), used through
`[patch.crates-io]` in `crates/opencrt-rdp/Cargo.toml`.

- `src/decode.rs` (`OpenH264Decoder::decode`): Windows sends AVC420 pictures in
  Annex B form already (start codes; FreeRDP hands them to OpenH264 as they are).
  0.3.0 always rewrote them as if length-prefixed, read `00 00 00 01` as a
  one-byte NAL unit, and decoded garbage or nothing. Annex B now passes through;
  length-prefixed input is still converted.
- `src/client.rs` (`handle_wire_to_surface1`): a picture OpenH264 cannot decode
  ("returned no picture") ended the session; it now goes to the handler's
  `on_unhandled_pdu` and the session carries on.
- `src/client.rs` (`decode_avc420`, `crop_decoded_frame`): when the decoded
  picture covers the whole surface, the destination rectangle is cut from its
  own place in it, not from the top left.

Delete this copy and the patch once a released ironrdp-egfx does the same.
