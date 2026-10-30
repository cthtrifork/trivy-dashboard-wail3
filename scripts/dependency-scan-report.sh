#!/usr/bin/env bash
# Usage: dependency-scan-report.sh BASE.json HEAD.json
# Prints a Markdown report of how a pull request changes the vulnerabilities Trivy finds: those only
# in HEAD (introduced) and those only in BASE (resolved).
set -euo pipefail

base=${1:?base trivy json}
head=${2:?head trivy json}

# One sorted, tab-separated line per finding: severity rank, severity, package, version, fix, id, target.
# The rank first makes the sort order CRITICAL -> LOW, and sorted lines are what comm compares.
findings() {
  jq -r '
    .Results[]? | .Target as $target | .Vulnerabilities[]? |
    [ ({CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}[.Severity] // 4),
      .Severity, .PkgName, .InstalledVersion, (.FixedVersion // "–"), .VulnerabilityID, $target ] | @tsv
  ' "$1" | LC_ALL=C sort -u
}

# section TITLE ROWS: a heading and a table for the rows (at most 50), nothing when there are none.
section() {
  local title=$1 rows=$2 max=50
  [ -n "$rows" ] || return 0
  local count
  count=$(wc -l <<<"$rows")

  printf '\n### %s (%s)\n\n' "$title" "$count"
  echo '| Severity | Package | Version | Fixed in | Advisory | Target |'
  echo '|---|---|---|---|---|---|'
  head -n "$max" <<<"$rows" | while IFS=$'\t' read -r _ severity pkg version fixed id target; do
    printf '| %s | `%s` | %s | %s | [%s](https://avd.aquasec.com/nvd/%s) | `%s` |\n' \
      "$severity" "$pkg" "$version" "$fixed" "$id" "${id,,}" "$target"
  done
  if [ "$count" -gt "$max" ]; then
    printf '\n_Showing %s of %s._\n' "$max" "$count"
  fi
}

base_findings=$(findings "$base")
head_findings=$(findings "$head")

# comm -13: only in HEAD. comm -23: only in BASE. Both inputs are sorted.
introduced=$(LC_ALL=C comm -13 <(echo "$base_findings") <(echo "$head_findings") | sed '/^$/d')
resolved=$(LC_ALL=C comm -23 <(echo "$base_findings") <(echo "$head_findings") | sed '/^$/d')

total=$(echo "$head_findings" | sed '/^$/d' | wc -l)
n_introduced=$(echo "$introduced" | sed '/^$/d' | wc -l)
n_resolved=$(echo "$resolved" | sed '/^$/d' | wc -l)

echo '## Trivy dependency scan'
echo
if [ "$n_introduced" -eq 0 ] && [ "$n_resolved" -eq 0 ]; then
  echo "No change in vulnerabilities ($total on this branch)."
  exit 0
fi
echo "$total on this branch: **$n_introduced** introduced, **$n_resolved** resolved."
section Introduced "$introduced"
section Resolved "$resolved"
