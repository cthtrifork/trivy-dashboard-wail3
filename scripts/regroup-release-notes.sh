#!/usr/bin/env bash
# Rewrites the GitHub-generated notes of past releases into the sections .github/release-drafter.yml uses.
#
#   scripts/regroup-release-notes.sh [--apply] [tag...]
#
# Dry run by default: prints each rewritten body. With --apply it PATCHes the release notes through
# `gh api` (needs a token that can write releases). No tags means every published release whose
# notes still start with GitHub's "## What's Changed". Releases already in the new format are skipped.
#
# Old PR titles are not Conventional Commits, so a title is classified, in order, by: a
# conventional `type(scope)!:` prefix, the author (Renovate/Dependabot), then keywords on the title.
# Review the dry run; the keyword rules are a guess.
set -euo pipefail

apply=0
[ "${1:-}" = "--apply" ] && { apply=1; shift; }
repo="${GITHUB_REPOSITORY:-cthtrifork/trivy-dashboard-wail3}"

# Section order and names match the categories in .github/release-drafter.yml.
read -r -d '' classify <<'JQ' || true
def section:
  if   .type == "security" then "Security"
  elif .type == "feat" then "New features"
  elif .type == "fix" then "Bug fixes"
  elif .type == "perf" then "Performance"
  elif .type == "docs" then "Documentation"
  elif .type == "deps" then "Dependencies"
  elif (.type == "ci" or .type == "build") then "CI, build and release"
  elif (.type | IN("refactor","test","chore","revert")) then "Maintenance"
  elif .breaking then "Breaking changes"
  elif (.author | test("renovate|dependabot")) and (.title | test("^Update screenshots") | not) then "Dependencies"
  elif (.title | test("^Update screenshots")) then "Maintenance"
  elif (.title | test("^(Fix|Clamp|Restore)\\b")) then "Bug fixes"
  elif (.title | test("^Update (dependency|module|actions/)|^Bump ")) then "Dependencies"
  elif (.title | test("workflow|^CI\\b|Actions lint|Renovate|Dependabot|CI-only|[Rr]elease:|in CI|headless image|Dockerfile|mirror\\.gcr|distroless|wails3 dev|tool-versions|sticky-pull-request|bot commits|screenshots")) then "CI, build and release"
  elif (.title | test("^(Consolidate|Tidy|Drop|Import|Remove|Replace|Route|Use|Move|Track|Pin|Bump)\\b")) then "Maintenance"
  else "New features" end;
JQ

order='["Breaking changes","Security","New features","Bug fixes","Performance","Documentation","Dependencies","CI, build and release","Maintenance","Other changes"]'

rewrite() { # stdin: old body; stdout: new body
  local body footer
  body="$(cat)"
  footer="$(printf '%s\n' "$body" | grep -iE '^\*\*Full Changelog\*\*' | sed -E 's/Full Changelog/Full changelog/' || true)"
  printf '%s\n' "$body" | sed -nE 's/^\* (.+) by @([^ ]+) in .*\/pull\/([0-9]+)$/\1\t\2\t\3/p' \
    | jq -R -r --argjson order "$order" "$classify"'
      select(length > 0) | split("\t")
      | {title: .[0], author: .[1], num: .[2],
         type: ((.[0] | capture("^(?<t>[a-z]+)(\\([^)]*\\))?!?: ") | .t) // ""),
         breaking: (.[0] | test("^[a-z]+(\\([^)]*\\))?!: "))}
      | . + {section: section, text: (.title | sub("^[a-z]+(\\([^)]*\\))?!?: "; "") | (.[0:1] | ascii_upcase) + .[1:])}
      | [.section, "- \(.text) (#\(.num)) @\(.author)"] | @tsv' \
    | jq -R -s -r --argjson order "$order" '
      split("\n") | map(select(length > 0) | split("\t") | {s: .[0], l: .[1]})
      | . as $all | $order[] | . as $sec
      | ($all | map(select(.s == $sec) | .l)) as $ls | select($ls | length > 0)
      | "## \($sec)\n\n" + ($ls | join("\n")) + "\n"'
  [ -n "$footer" ] && printf '\n%s\n' "$footer"
  return 0
}

tags=("$@")
if [ ${#tags[@]} -eq 0 ]; then
  mapfile -t tags < <(gh api --paginate "repos/$repo/releases?per_page=100" \
    --jq '.[] | select(.draft | not) | select(.body | startswith("## What'"'"'s Changed")) | .tag_name')
fi

for tag in "${tags[@]}"; do
  rel="$(gh api "repos/$repo/releases/tags/$tag")"
  id="$(jq -r .id <<<"$rel")"
  new="$(jq -r .body <<<"$rel" | rewrite)"
  echo "=== $tag"
  printf '%s\n' "$new"
  if [ "$apply" = 1 ]; then
    gh api -X PATCH "repos/$repo/releases/$id" -f body="$new" --jq '"updated " + .tag_name' >&2
  fi
done
