#!/bin/sh
# Write the winget manifest of a published release, ready to submit to
# github.com/microsoft/winget-pkgs (see docs/packaging.md). The installer is
# the signed Inno Setup program of the GitHub release; its checksum comes from
# the release's SHA256SUMS. Output: dist/winget/manifests/o/OpenCRT/OpenCRT/<version>/.
#
#   packaging/winget/manifest.sh X.Y.Z [release date, YYYY-MM-DD]
set -eu
v=${1:-}
echo "$v" | grep -qxE '[0-9]+\.[0-9]+\.[0-9]+' || { echo "usage: $0 X.Y.Z [YYYY-MM-DD]" >&2; exit 1; }
date=${2:-$(date -u +%F)}
id=OpenCRT.OpenCRT
repo=https://github.com/KimP0ssible-no/OpenCRT
setup=opencrt-$v-x64-setup.exe
sha=$(curl -sSfL "$repo/releases/download/v$v/SHA256SUMS" | awk -v f="$setup" '$2 == f { print toupper($1) }')
echo "$sha" | grep -qxE '[0-9A-F]{64}' || { echo "$setup is not in the SHA256SUMS of release v$v" >&2; exit 1; }
out=dist/winget/manifests/o/OpenCRT/OpenCRT/$v
mkdir -p "$out"
schema=1.9.0

cat > "$out/$id.yaml" <<YAML
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.$schema.schema.json
PackageIdentifier: $id
PackageVersion: $v
DefaultLocale: en-US
ManifestType: version
ManifestVersion: $schema
YAML

# The setup asks "for me" or "for all users"; winget chooses with the scope.
cat > "$out/$id.installer.yaml" <<YAML
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.$schema.schema.json
PackageIdentifier: $id
PackageVersion: $v
InstallerType: inno
UpgradeBehavior: install
ProductCode: '{6F1D4C2E-8E0B-4E6B-9C5A-0C4C3D7A1E21}_is1'
ReleaseDate: $date
Installers:
- Architecture: x64
  Scope: user
  InstallerUrl: $repo/releases/download/v$v/$setup
  InstallerSha256: $sha
  InstallerSwitches:
    Custom: /CURRENTUSER
- Architecture: x64
  Scope: machine
  InstallerUrl: $repo/releases/download/v$v/$setup
  InstallerSha256: $sha
  InstallerSwitches:
    Custom: /ALLUSERS
  ElevationRequirement: elevatesSelf
ManifestType: installer
ManifestVersion: $schema
YAML

cat > "$out/$id.locale.en-US.yaml" <<YAML
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.$schema.schema.json
PackageIdentifier: $id
PackageVersion: $v
PackageLocale: en-US
Publisher: OpenCRT
PublisherUrl: $repo
PublisherSupportUrl: $repo/issues
PackageName: OpenCRT
PackageUrl: $repo
License: Apache-2.0 AND GPL-3.0-only
LicenseUrl: $repo/blob/main/LICENSE
ShortDescription: SSH, Telnet, serial, RDP and VNC terminal client with a session manager and file transfer.
Description: OpenCRT is a tabbed terminal client for SSH2, Telnet, serial lines, RDP and VNC, with a session manager, SFTP and Zmodem file transfer, port forwarding, scripting, logging and keyword highlighting.
Moniker: opencrt
Tags:
- ssh
- sftp
- telnet
- serial
- rdp
- vnc
- terminal
ReleaseNotesUrl: $repo/releases/tag/v$v
ManifestType: defaultLocale
ManifestVersion: $schema
YAML
echo "$out"
