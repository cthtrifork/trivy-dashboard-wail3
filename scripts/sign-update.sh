#!/usr/bin/env bash
# Signs, or verifies, a release binary for the in-app updater with an Ed25519 key.
#
#   scripts/sign-update.sh sign   <binary> <version> <private-key.pem>   writes <binary>.sig
#   scripts/sign-update.sh verify <binary> <version> <public-key.pem>    checks <binary>.sig
#
# What is signed is a short statement naming the version, the asset and its SHA-256 (not the raw bytes),
# so a validly signed old binary cannot be offered as a newer release. internal/selfupdate.Statement
# builds the same text and the app checks the signature against the public key compiled into it;
# a test runs this script against that code.
set -euo pipefail

usage() { echo "usage: sign-update.sh sign|verify <binary> <version> <key.pem>" >&2; exit 2; }
mode="${1:-}"; bin="${2:-}"; version="${3:-}"; key="${4:-}"
[ -n "$mode" ] && [ -n "$bin" ] && [ -n "$version" ] && [ -n "$key" ] || usage
[ -f "$bin" ] || { echo "sign-update: $bin is not a file" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp:?}"' EXIT
sum="$(sha256sum "$bin" | cut -d' ' -f1)"
printf 'trivy-scanner release\nversion: %s\nasset: %s\nsha256: %s\n' "${version#v}" "$(basename "$bin")" "$sum" > "$tmp/statement"

case "$mode" in
  sign)
    openssl pkeyutl -sign -inkey "$key" -rawin -in "$tmp/statement" -out "$bin.sig"
    ;;
  verify)
    openssl pkeyutl -verify -pubin -inkey "$key" -rawin -in "$tmp/statement" -sigfile "$bin.sig" >/dev/null
    ;;
  *) usage ;;
esac
