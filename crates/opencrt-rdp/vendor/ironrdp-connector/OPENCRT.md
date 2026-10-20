# ironrdp-connector 0.10.0, with one change

A copy of [ironrdp-connector](https://crates.io/crates/ironrdp-connector) 0.10.0
(Devolutions, MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE), used through
`[patch.crates-io]` in `crates/opencrt-rdp/Cargo.toml`.

The one change: `Config::support_dyn_vc_gfx_protocol`, which sets
`RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` so Windows uses the Graphics Pipeline
(H.264) with OpenCRT. Upstream IronRDP added the same field after the 0.10.0
release (Devolutions/IronRDP#1237); delete this copy and the patch once a
released ironrdp-connector has it.
