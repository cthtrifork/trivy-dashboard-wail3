#!/usr/bin/env bash
# Turns a built binary into the assets a release publishes:
#
#   <out>/trivy-scanner_linux_amd64                     raw binary: what the in-app updater installs
#   <out>/trivy-scanner_<version>_linux_amd64.tar.gz    binary + README + LICENSE, for people
#   <out>/SHA256SUMS                                    SHA-256 of both
#
# Why both files: the updater installs a single file (or an archive with exactly one
# top-level entry), so it cannot use the tarball; people downloading by hand want the
# README and LICENSE. SHA256SUMS has a fixed name because the updater looks it up by name.
#
#   scripts/package-release.sh <binary> <version> <outdir>
set -euo pipefail

bin="${1:?usage: package-release.sh <binary> <version> <outdir>}"
version="${2:?usage: package-release.sh <binary> <version> <outdir>}"
out="${3:?usage: package-release.sh <binary> <version> <outdir>}"
app="${APP:-trivy-scanner}"

bin="$(realpath "$bin")"
out="$(realpath -m "$out")"
cd "$(dirname "$0")/.."

[ -x "$bin" ] || { echo "package-release: $bin is not an executable file" >&2; exit 1; }

stage="$(mktemp -d)"
trap 'rm -rf "${stage:?}"' EXIT
mkdir -p "$out"

raw="${app}_linux_amd64"
archive="${app}_${version}_linux_amd64.tar.gz"

cp "$bin" "$out/$raw"
chmod +x "$out/$raw"

cp "$bin" "$stage/$app"
cp README.md "$stage/"
[ -f LICENSE ] && cp LICENSE "$stage/"
tar -C "$stage" -czf "$out/$archive" .

(cd "$out" && sha256sum "$raw" "$archive" > SHA256SUMS)
ls -l "$out"
