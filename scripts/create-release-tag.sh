#!/usr/bin/env bash
# Decides the release tag, creates and pushes it if needed, and reports it to the workflow.
#
#   env  TAG_INPUT  the tag to release, e.g. v1.4.0 or v1.4.0-rc.1: the explicit tag the workflow was
#                   given, or the version Release Drafter resolved from the merged PR titles
#        TARGET     what to tag; defaults to HEAD
#   needs: git able to push to "origin", and gh able to read releases (GH_TOKEN)
#   writes tag=<tag> and created=<true|false> to $GITHUB_OUTPUT
#
# It is safe to re-run. If the release already exists it stops with an error. If the tag exists
# but the release does not (an earlier run failed after tagging) it reuses the tag, so running
# the workflow again with that tag name finishes the job instead of failing on "tag exists".
set -euo pipefail

out="${GITHUB_OUTPUT:-/dev/stdout}"
target="${TARGET:-HEAD}"

die() { echo "::error::$*" >&2; exit 1; }

tag="${TAG_INPUT:-}"
[ -n "$tag" ] || die "No tag to release: TAG_INPUT is empty (Release Drafter found no version)."
semver='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
[[ "$tag" =~ $semver ]] || die "'$tag' is not a semantic version like v1.2.3 or v1.2.3-rc.1."
echo "Release tag: $tag"

# 1. Never release twice. Only a published release counts: Release Drafter keeps a draft for the next
#    version, and that draft is what this release is about to publish. A failed lookup (auth, network)
#    must not be mistaken for "no release yet", so it stops the run.
published="$(gh release list --exclude-drafts --limit 1000 --json tagName --jq '.[].tagName')" ||
  die "Could not list the releases to check whether $tag exists."
if grep -qxF "$tag" <<<"$published"; then
  die "A release for $tag already exists. Pick a different tag."
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
