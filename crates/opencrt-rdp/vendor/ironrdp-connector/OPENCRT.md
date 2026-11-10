# ironrdp-connector 0.10.0, with two changes

A copy of [ironrdp-connector](https://crates.io/crates/ironrdp-connector) 0.10.0
(Devolutions, MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE), used through
`[patch.crates-io]` in `crates/opencrt-rdp/Cargo.toml`.

The first: `Config::support_dyn_vc_gfx_protocol`, which sets
`RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` so Windows uses the Graphics Pipeline
(H.264) with OpenCRT. Upstream IronRDP added the same field after the 0.10.0
release (Devolutions/IronRDP#1237).

The second: `Config::admin_session`, which sends Client Cluster Data with
`REDIRECTED_SESSIONID_FIELD_VALID` and session 0, the console (administrative)
session `mstsc /admin` and FreeRDP's `/admin` ask for. Upstream still leaves the
block out (its TODO #139). Delete this copy and the patch once a released
ironrdp-connector has both.
