#!/usr/bin/env bash
# The updater installs a single file, so it gets the raw binary; SHA256SUMS has a fixed name it looks up.
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
