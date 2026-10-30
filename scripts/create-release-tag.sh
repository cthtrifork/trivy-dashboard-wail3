#!/usr/bin/env bash
# Decides the release tag, creates and pushes it if needed, and reports it to the workflow.
#
#   env  BUMP       patch | minor | major (used when TAG_INPUT is empty)
#        TAG_INPUT  optional explicit tag, e.g. v1.4.0 (overrides BUMP); the workflow also passes the
#                   version Release Drafter resolved here for bump `auto`
#        TARGET     what to tag; defaults to HEAD
#   needs: git able to push to "origin", and gh able to read releases (GH_TOKEN)
#   writes tag=<tag> and created=<true|false> to $GITHUB_OUTPUT
#
# It is safe to re-run. If the release already exists it stops with an error. If the tag exists
# but the release does not (an earlier run failed after tagging) it reuses the tag, so running
# the workflow again with that tag name finishes the job instead of failing on "tag exists".
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${GITHUB_OUTPUT:-/dev/stdout}"
target="${TARGET:-HEAD}"

die() { echo "::error::$*" >&2; exit 1; }

tag="$("$here/next-version.sh" "${BUMP:-patch}" "${TAG_INPUT:-}")"
echo "Release tag: $tag"

# 1. Never release twice. Only a published release counts: Release Drafter keeps a draft for the next
#    version, and that draft is what this release is about to publish. A failed lookup (auth, network)
#    must not be mistaken for "no release yet", so it stops the run.
published="$(gh release list --exclude-drafts --limit 1000 --json tagName --jq '.[].tagName')" ||
  die "Could not list the releases to check whether $tag exists."
if grep -qxF "$tag" <<<"$published"; then
  die "A release for $tag already exists. Pick a different tag or bump."
fi

# 2. Create the tag unless it is already on the remote (exit 2 means "no such ref").
rc=0
git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1 || rc=$?
case "$rc" in
  0)
    echo "Tag $tag already exists without a release: reusing it."
    created=false
    ;;
  2)
    git tag -a "$tag" -m "$tag" "$target"
    git push origin "refs/tags/$tag"
    echo "Created and pushed $tag at $(git rev-parse --short "$target")."
    created=true
    ;;
  *) die "Could not look up tag $tag on origin (git ls-remote exited $rc)." ;;
esac

{
  echo "tag=$tag"
  echo "created=$created"
} >>"$out"
