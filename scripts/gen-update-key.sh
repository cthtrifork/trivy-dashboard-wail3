#!/usr/bin/env bash
# One-time setup of the update signing key (docs/releasing.md, "The update signing key").
#
#   scripts/gen-update-key.sh <private-key-out.pem>
#
# Writes the private key to the given file (mode 0600, refuse to overwrite) and the public key to
# internal/selfupdate/update-signing-key.pub, which is compiled into the app. Store the private key
# in the RELEASE_UPDATE_SIGNING_KEY repository secret, commit the public key, and delete the file.
set -euo pipefail

out="${1:?usage: gen-update-key.sh <private-key-out.pem>}"
[ ! -e "$out" ] || { echo "gen-update-key: $out exists, not overwriting it" >&2; exit 1; }
cd "$(dirname "$0")/.."

umask 077
openssl genpkey -algorithm ed25519 -out "$out"
openssl pkey -in "$out" -pubout -out internal/selfupdate/update-signing-key.pub
echo "Private key: $out (put it in the RELEASE_UPDATE_SIGNING_KEY secret, then delete the file)"
echo "Public key:  internal/selfupdate/update-signing-key.pub (commit it)"
