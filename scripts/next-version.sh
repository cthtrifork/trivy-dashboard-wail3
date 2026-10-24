#!/usr/bin/env bash
# Prints the tag a release should get.
#
#   scripts/next-version.sh <patch|minor|major> [explicit-tag]
#
# An explicit tag wins (it must be a semantic version with a leading v, e.g. v1.4.0 or
# v1.4.0-rc.1). Otherwise the bump is applied to the highest *stable* vX.Y.Z tag in this
# repository; pre-releases are ignored, so v1.4.0-rc.1 does not become the base. With no
# tags yet the base is v0.0.0, so minor gives v0.1.0 and major gives v1.0.0.
set -euo pipefail

bump="${1:-patch}"
explicit="${2:-}"
semver='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
stable='^v[0-9]+\.[0-9]+\.[0-9]+$'

die() { echo "next-version: $*" >&2; exit 1; }

if [ -n "$explicit" ]; then
  [[ "$explicit" =~ $semver ]] || die "'$explicit' is not a semantic version like v1.2.3 or v1.2.3-rc.1"
  echo "$explicit"
  exit 0
fi

case "$bump" in patch | minor | major) ;; *) die "bump must be patch, minor or major, not '$bump'" ;; esac

latest="$(git tag --list 'v[0-9]*' | grep -E "$stable" | sort -V | tail -n 1 || true)"
latest="${latest:-v0.0.0}"

IFS=. read -r major minor patch <<<"${latest#v}"
case "$bump" in
  major) major=$((major + 1)); minor=0; patch=0 ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  patch) patch=$((patch + 1)) ;;
esac
echo "v${major}.${minor}.${patch}"
