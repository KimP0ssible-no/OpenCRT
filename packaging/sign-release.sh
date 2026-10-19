#!/bin/sh
# Sign a release folder's SHA256SUMS with the minisign key in $MINISIGN_KEY
# (its password, if it has one, in $MINISIGN_PASSWORD), then check the
# signature with the public key OpenCRT is built with, so a release can never
# go out signed with a key the program would refuse.
#   packaging/sign-release.sh <release folder> [public key]
set -eu
dir=$1
pub=${2:-$(dirname "$0")/minisign.pub}
key=$(mktemp)
trap 'rm -f "$key"' EXIT
printf '%s\n' "$MINISIGN_KEY" > "$key"
printf '%s\n' "${MINISIGN_PASSWORD:-}" | minisign -S -s "$key" -m "$dir/SHA256SUMS" -t "OpenCRT ${GITHUB_REF_NAME:-} SHA256SUMS"
minisign -V -q -p "$pub" -m "$dir/SHA256SUMS"
