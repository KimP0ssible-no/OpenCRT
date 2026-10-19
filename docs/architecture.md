# OpenCRT — Architecture & Stack

## Decisions
- **Language**: Rust (stable, edition 2024).
- **GUI**: Slint 1.18, Fluent style, **software renderer** on the winit backend
  (CPU-drawn like a classic desktop app; no GPU swapchain). Replaced egui/eframe
  on 2026-10-12 for a native, SecureCRT-like look.
- **Terminal emulator**: `alacritty_terminal` (VT/xterm engine), GUI-agnostic.
- **Terminal rendering**: `render.rs` rasterises the grid on the CPU with
  `fontdue` (system monospace font, lazy CJK/symbol fallbacks) into an RGBA
  buffer shown as a Slint `Image`. Repainted only when the session changed.
- **SSH**: `russh` (pure-Rust async SSH2 client), one tokio runtime per session
  thread, bridged to the UI with channels; the UI polls them on a 15 ms timer.
- **Clipboard**: `arboard` (Slint has no Rust clipboard API).
- **SFTP**: `russh-sftp`. **Serial**: `serialport`. **Local shell**:
  `alacritty_terminal::tty` (ConPTY on Windows).
- **File dialogs**: `rfd`. **Log timestamps**: `chrono` (already built for Slint).
- **Config**: `serde` + `toml`. **Errors**: `anyhow`; panics and fatal errors
  also go to `crash.log` in the config folder.
- **Scripting**: built-in expect-style scripts (`script.rs`); a Python host
  (`pyo3`) is undecided (needs a Python runtime on users' machines).

- **RDP**: IronRDP (connector, session, TLS via rustls, NTLM via sspi) in a
  separate helper program, `crates/opencrt-rdp` (its own workspace: IronRDP
  pins pre-release RustCrypto crates that conflict with russh's). One helper
  per RDP tab, spawned next to `opencrt`, speaking the `crates/rdp-proto`
  messages over stdin/stdout. The helper decodes the desktop (RemoteFX) and
  sends changed rectangles as RGBA; `src/rdp.rs` keeps the trust store,
  password prompt and the desktop picture shown in the tab.

Every transport runs on its own thread behind the same channels
(`ssh::spawn` → `SshHandle` / `Io` / `SshEvent`), so the UI treats SSH,
Telnet, raw, serial, local and SFTP tabs alike.

## Source layout (`crates/opencrt`)
- `ui/main.slint`, `ui/icons.slint` — window, menus, toolbar, tabs, docks, status
  bar, dialogs; own vector icons. Compiled by `build.rs` with the "fluent" style.
- `src/main.rs` — panic hook, winit + software renderer backend, runs the app.
- `src/app.rs` — app state (tabs, prompts, mouse/selection, transfers, scripts,
  auto-reconnect), Slint callbacks, the 15 ms tick.
- `src/terminal.rs` — alacritty wrapper: feed, replies, scrollback, selection,
  find, cursor shape, resolved cells for rendering.
- `src/render.rs` — CPU glyph rasteriser, font catalogue, keyword highlighting,
  vertical dock-tab labels.
- `src/input.rs` — key/paste/mouse encoding, Button Bar escapes, Latin-1.
- `src/ssh.rs` — connect (direct or via jump host), host-key check, auth chain
  (key file, agent, keyboard-interactive, password), shell loop, agent and X11
  forwarding, key generation, legacy algorithms. A logged-in connection
  (`Shared`) is offered to the UI as a weak `Link`; SFTP tabs and clones open
  channels on it, and the shell's thread keeps it up until they close.
- `src/forward.rs` — L/R/D port forwarding and SOCKS4/5.
- `src/proxy.rs` — outgoing SOCKS5 / HTTP CONNECT proxy for SSH2, Telnet, Raw.
- `src/tftp.rs` — built-in TFTP server (std UDP threads, one per transfer).
- `src/sftp.rs` — the `sftp>` command line over russh-sftp.
- `src/telnet.rs`, `src/serial.rs`, `src/local.rs` — the other transports.
- `src/rdp.rs` — RDP tab: starts the helper, server-certificate trust store
  (`rdp_known_certs`), password prompt, the `Desktop` picture.
- `src/zmodem.rs`, `src/xymodem.rs` — file transfer protocols, driven from
  `Tab::poll` on host output.
- `src/script.rs` — wait/send/sleep scripts (Script > Run, logon scripts) and
  the script recorder.
- `src/sessions.rs` — Session Manager tree, folder rename, merge, ssh_config import.
- `src/config.rs` — config folder (or `/F`), sessions.toml / options.toml types,
  crash log.
- `src/log.rs` — plain-text session logs (escape-stripped, optional timestamps).
- `examples/dev_server.rs` — local SSH server for manual testing (sz/rz/sx/sb,
  mouse, bell, title, lines, exit, and SFTP via `src/memfs.rs`, the in-memory
  file system the SFTP tests also use).

## Windows build note
`russh`'s crypto backend (`aws-lc-rs` → `aws-lc-sys`) needs NASM on Windows
x86_64; we use the crate's prebuilt objects via `.cargo/config.toml`:

```toml
[env]
AWS_LC_SYS_PREBUILT_NASM = "1"
```

## Slint notes
- The software renderer cannot rotate items, so vertical text is pre-rendered.
- A `TouchArea` inside a `ContextMenuArea` takes right-clicks first; open the menu
  with `ContextMenuArea.show()` from `pointer-event`.
- Slint reports macOS Command as `control` and Control as `meta`.
- Special keys arrive as private-use code points (`input.rs` lists them);
  Backspace is U+0008 and Delete is U+007F.
