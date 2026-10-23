# Building packages

All packages start from a release build of both programs: `opencrt` and the
RDP helper `opencrt-rdp`, which must ship in the same folder (binaries at
`target/release/opencrt[.exe]` and `target/release/opencrt-rdp[.exe]`):

```
cargo build --release
cargo build --release --manifest-path crates/opencrt-rdp/Cargo.toml --target-dir target
```

Every package also ships the third-party licence notices of both programs'
dependencies, generated with cargo-about (`cargo install cargo-about --locked --features cli`):

```
cargo about generate about.hbs -o target/THIRD-PARTY-NOTICES.html
cargo about generate -c about.toml --manifest-path crates/opencrt-rdp/Cargo.toml about.hbs -o target/THIRD-PARTY-NOTICES-RDP.html
```

`about.toml` lists the licences dependencies may use; a dependency under any
other licence makes the command fail, so it is reviewed before it ships.

The CI workflow (`.github/workflows/ci.yml`) runs the same steps on each platform.

## Self-contained packages
The packages need nothing beyond what every system already has:

- **Linux**: the binaries are built against glibc 2.28 (AlmaLinux 8) and link
  only glibc's own libraries and libgcc. fontconfig is loaded at run time
  if present (the UI and terminal fonts are built in); the display libraries
  (Wayland / X11, xkbcommon) are loaded by the windowing layer and are part
  of any desktop. The .deb depends only on `libc6 (>= 2.28)`, the .rpm only
  on `glibc >= 2.28` (both written out in `crates/opencrt/Cargo.toml`: the
  tools' automatic scans ask for more than is needed, or for names no
  package provides). Build the binaries this way locally with
  `packaging/linux/build-portable.sh` (Docker; output in
  `target/portable/release/`), then package with
  `CARGO_TARGET_DIR=target/portable cargo deb -p opencrt --no-build` and
  `cargo generate-rpm -p crates/opencrt --target-dir target/portable`.
  CI does the same in an `almalinux:8` container and fails if a binary needs
  a newer glibc or another library.
- **Windows**: the C runtime is linked into the executables
  (`.cargo/config.toml`, `+crt-static`), so no Visual C++ Redistributable is
  needed; CI fails if an executable imports the dynamic runtime.

Checked on 2026-10-16: the .deb installs with no other packages (apt lists
only `opencrt`) on Debian 11, Ubuntu 20.04 and 24.04; the .rpm installs with
plain `rpm -i` on Rocky Linux 8, Fedora, openSUSE Leap 15.6 and Tumbleweed
(SUSE needs no package of its own); the Arch package installs with
`pacman -U` and nothing else (it depends on `glibc` and `gcc-libs`, both in
the base system); `ocrt` works and the GUI starts up to needing a display in
all of them.

| Platform | Tool | Command | Output |
|---|---|---|---|
| Windows | Inno Setup 6 | `iscc packaging\windows\opencrt.iss` | `packaging\windows\Output\opencrt-<ver>-x64-setup.exe` |
| Windows (MSI) | `cargo install cargo-wix`, WiX 3 | `cargo wix -p opencrt --no-build` | `target\wix\*.msi` |
| Debian/Ubuntu | `cargo install cargo-deb` | `cargo deb -p opencrt --no-build` | `target/debian/*.deb` |
| Red Hat/Fedora/SUSE | `cargo install cargo-generate-rpm` | `cargo generate-rpm -p crates/opencrt` | `target/generate-rpm/*.rpm` |
| Arch Linux | `makepkg` (in Arch) | `packaging/arch/makepkg.sh` (or `packaging/arch/build-arch.sh` with Docker) | `dist/*.pkg.tar.zst` |
| macOS | `cargo install cargo-bundle` | `cargo bundle --release -p opencrt`, copy `opencrt-rdp` into `OpenCRT.app/Contents/MacOS/`, then `hdiutil create` (see CI) | `OpenCRT.app` / `.dmg` |

Icons: `packaging/make-icons.ps1` renders `packaging/icons/*.png` and
`opencrt.ico` from the design in `crates/opencrt/ui/opencrt.svg`. The Windows
executables embed `opencrt.ico` and version information (ProductName OpenCRT,
ProductVersion from `crates/opencrt/Cargo.toml`, also for `opencrt-rdp.exe`)
through `packaging/windows/resources.rs`, which both build scripts include.

## Building everything on Linux for sharing
With Docker, all three packages can be made on the Linux workstation into
`dist/` (git-ignored):

```
packaging/linux/build-portable.sh        # glibc 2.28 binaries (AlmaLinux 8)
cargo about generate about.hbs -o target/THIRD-PARTY-NOTICES.html
cargo about generate -c about.toml --manifest-path crates/opencrt-rdp/Cargo.toml about.hbs -o target/THIRD-PARTY-NOTICES-RDP.html
CARGO_TARGET_DIR=target/portable cargo deb -p opencrt --no-build -o dist/
cargo generate-rpm -p crates/opencrt --target-dir target/portable -o dist/
packaging/arch/build-arch.sh             # Arch package from the same binaries
packaging/windows/build-cross.sh         # MinGW cross build + Inno Setup under Wine
(cd dist && sha256sum *.exe *.deb *.rpm *.pkg.tar.zst > SHA256SUMS)
```

The Windows build made this way is `x86_64-pc-windows-gnu` (MinGW, runtime
linked in): it imports only Windows system DLLs, like the MSVC build CI makes.
Inno Setup 6.7.3 is downloaded from its GitHub releases into the
`opencrt-windows-cross` Docker volume the first time. The installer is
unsigned, so Windows SmartScreen warns before running it ("More info", then
"Run anyway").

## Releases
CI (`.github/workflows/ci.yml`) builds and tests every push. Pushing a tag
`vX.Y.Z` also publishes a GitHub Release with the Windows installer and MSI,
the macOS disk image, the .deb, .rpm and Arch packages, and `SHA256SUMS`.
Set the version first in `crates/opencrt/Cargo.toml` and
`packaging/windows/opencrt.iss` (the release job stops if either differs from
the tag), then:

```
git tag v0.1.0
git push github v0.1.0
```

## Before a public release
- **Licence**: OpenCRT's source is Apache-2.0; Slint is used under
  GPL-3.0-only, so the shipped `opencrt` binary is GPL-3.0-only (every
  component OSI-licensed, as SignPath Foundation requires). Dependencies must
  stay GPL-3.0-compatible: `about.toml` accepts no GPL-2.0-only licence.
- **Code signing**: Windows installer/executable and macOS bundle are unsigned;
  macOS also needs notarisation for Gatekeeper.
- **Identifiers**: the macOS bundle id (`org.opencrt.OpenCRT`) and the Inno
  Setup `AppId` are placeholders chosen for this project; keep them stable once
  shipped (upgrades rely on them).

## Not yet verified
The .deb and .rpm were built and installed as above. The Inno Setup installer
cross-built on Linux (`packaging/windows/build-cross.sh`) installs and runs on
Windows 11 (2026-10-16). The WiX and cargo-bundle steps have not been run yet,
and the MSVC build's static runtime is unchecked (`dumpbin /dependents
opencrt.exe` should list only system DLLs, no VCRUNTIME140.dll).
