# ironrdp-connector 0.10.0, with four changes

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
block out (its TODO #139).

The third: a connect-time Bandwidth Measure Stop is answered with Bandwidth
Measure Results (`respond_to_connect_time_autodetect`), as FreeRDP's client
does. 0.10.0 answered only RTT requests; gnome-remote-desktop waits for the
results and never starts licensing, so the connection hung after login.

The fourth: `Config::rdstls`, which asks for `PROTOCOL_RDSTLS | PROTOCOL_SSL`
only, for the connection after a Server Redirection with a one-time password
(gnome-remote-desktop's remote login). The RDSTLS exchange itself is in the
helper (`src/redirect.rs`). Upstream has neither.

Delete this copy and the patch once a released ironrdp-connector has all four.
