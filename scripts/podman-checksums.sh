#!/bin/sh
# Usage: scripts/podman-checksums.sh [version]   (default: PODMAN_VERSION from the Dockerfile; run by Renovate)
set -eu

dockerfile=build/docker/headless.Dockerfile
version=${1:-$(sed -n 's/^ARG PODMAN_VERSION=//p' "$dockerfile")}
[ -n "$version" ] || { echo "no podman version" >&2; exit 1; }

shasums=$(mktemp)
trap 'rm -f "$shasums"' EXIT
curl -fsSL -o "$shasums" "https://github.com/containers/podman/releases/download/$version/shasums"

for arch in amd64 arm64; do
  sum=$(sed -n "s/^\([0-9a-f]\{64\}\)  podman-remote-static-linux_$arch\.tar\.gz\$/\1/p" "$shasums")
  [ -n "$sum" ] || { echo "no checksum for $arch in podman $version" >&2; exit 1; }
  sed -i "s/^ARG PODMAN_SHA256_$arch=.*/ARG PODMAN_SHA256_$arch=$sum/" "$dockerfile"
done
echo "podman $version: checksums updated in $dockerfile"
