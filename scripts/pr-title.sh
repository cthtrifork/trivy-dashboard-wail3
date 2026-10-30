#!/usr/bin/env bash
# The pull request title convention, and the label each title type maps to.
#
#   scripts/pr-title.sh check "<title>"   validate the title; print the labels it earns, one per line
#   scripts/pr-title.sh labels            print every managed label as: name<TAB>color<TAB>description
#
# A title is `type(scope)!: summary`. The scope and the `!` are optional; `!` marks a breaking change.
# Squash merges use the PR title as the commit subject, and the release notes (.github/release.yml)
# group PRs by label, so this is what ends up in front of users. Keep the table, .github/release.yml
# and docs/releasing.md in step.
set -euo pipefail

# type<TAB>label<TAB>color<TAB>description
table="$(printf '%s\t%s\t%s\t%s\n' \
  feat feature a2eeef 'New user-visible functionality' \
  fix bug d73a4a 'Fixes a defect' \
  security security b60205 'Security fix or hardening' \
  perf performance fbca04 'Faster or lighter, same behaviour' \
  refactor refactor cfd3d7 'Internal change, same behaviour' \
  docs documentation 0075ca 'Documentation only' \
  test maintenance ededed 'Tests and housekeeping' \
  chore maintenance ededed 'Tests and housekeeping' \
  revert maintenance ededed 'Tests and housekeeping' \
  ci ci 5319e7 'Workflows and automation' \
  build build 5319e7 'Build, packaging and release tooling' \
  deps dependencies 0366d6 'Pull requests that update a dependency file')"
breaking='breaking-change	e11d21	Changes behaviour users or integrations rely on'

die() { echo "pr-title: $*" >&2; exit 1; }

check() {
  local title="$1" types re
  types="$(cut -f1 <<<"$table" | paste -sd'|')"
  re="^(${types})(\\([a-z0-9._/-]+\\))?(!)?: (.+)$"

  [[ "$title" =~ $re ]] || die "'$title' does not match 'type(scope)!: summary'.
  type is one of: ${types//|/, }
  Examples: 'feat: add severity filter', 'fix(scanner): keep the last scan on restart', 'feat!: drop the v1 config file'"

  local type="${BASH_REMATCH[1]}" bang="${BASH_REMATCH[3]}" summary="${BASH_REMATCH[4]}"
  [ "${#title}" -le 72 ] || die "title is ${#title} characters; keep it to 72 so it reads in the release notes"
  [[ "$summary" != *. ]] || die "drop the trailing period from the summary"
  [[ "$summary" =~ ^[A-Za-z0-9\`] ]] || die "start the summary with a word"

  awk -F'\t' -v t="$type" '$1 == t { print $2 }' <<<"$table"
  if [ -n "$bang" ]; then cut -f1 <<<"$breaking"; fi
}

case "${1:-}" in
  check) [ $# -eq 2 ] || die "usage: pr-title.sh check <title>"; check "$2" ;;
  labels) { cut -f2- <<<"$table"; echo "$breaking"; } | sort -u ;;
  *) die "usage: pr-title.sh check <title> | labels" ;;
esac
