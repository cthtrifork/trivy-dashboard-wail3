#!/usr/bin/env bash
# Usage: dependency-scan-report.sh BASE.json HEAD.json
# Prints a Markdown report of how a pull request changes the vulnerabilities Trivy finds: those in
# HEAD that are not in BASE (introduced) and those in BASE that are not in HEAD (resolved). A finding
# is the same package, installed version and advisory id.
set -euo pipefail

base=${1:?base trivy json}
head=${2:?head trivy json}

flat='[.Results[]? | .Target as $t | .Vulnerabilities[]? | {id: .VulnerabilityID, pkg: .PkgName, ver: .InstalledVersion, fixed: (.FixedVersion // ""), sev: .Severity, target: $t}]'
key='"\(.pkg)@\(.ver)|\(.id)"'
order='sort_by([({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}[.sev] // 5), .pkg])'

# only SRC's findings whose key is not among OTHER's
only_in() {
  local keys
  keys=$(jq -c "$flat | map($key)" "$2")
  jq -c --argjson other "$keys" "$flat | map(select($key as \$k | \$other | index(\$k) | not)) | unique_by(.pkg, .ver, .id) | $order" "$1"
}

new=$(only_in "$head" "$base")
gone=$(only_in "$base" "$head")
total=$(jq "$flat | length" "$head")
n_new=$(jq length <<<"$new")
n_gone=$(jq length <<<"$gone")



table() { # JSON list on stdin, header for the fixed-in column
  echo "| Severity | Package | Version | $1 | Advisory | Target |"
  echo "|---|---|---|---|---|---|"
  jq -r '.[:50][] | "| \(.sev) | `\(.pkg)` | \(.ver) | \(if .fixed == "" then "–" else .fixed end) | [\(.id)](https://avd.aquasec.com/nvd/\(.id | ascii_downcase)) | `\(.target)` |"'
}

echo "## Trivy dependency scan"
echo
if [ "$n_new" -eq 0 ] && [ "$n_gone" -eq 0 ]; then
  echo "No change in vulnerabilities (${total} on this branch)."
  exit 0
fi
echo "${total} on this branch: **${n_new}** introduced, **${n_gone}** resolved."
if [ "$n_new" -gt 0 ]; then
  echo
  echo "### Introduced ($n_new)"
  echo
  table "Fixed in" <<<"$new"
  [ "$n_new" -gt 50 ] && printf '\n_Showing 50 of %s._\n' "$n_new"
fi
if [ "$n_gone" -gt 0 ]; then
  echo
  echo "### Resolved ($n_gone)"
  echo
  table "Fixed in" <<<"$gone"
  [ "$n_gone" -gt 50 ] && printf '\n_Showing 50 of %s._\n' "$n_gone"
fi
exit 0
