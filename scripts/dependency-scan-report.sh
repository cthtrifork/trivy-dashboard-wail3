#!/usr/bin/env bash
# Usage: dependency-scan-report.sh BASE.json HEAD.json
# Prints a Markdown report of the vulnerabilities a pull request introduces: findings in the
# Trivy JSON of HEAD that are not in BASE (same package, installed version and advisory id).
set -euo pipefail

base=${1:?base trivy json}
head=${2:?head trivy json}

flat='[.Results[]? | .Target as $t | .Vulnerabilities[]? | {id: .VulnerabilityID, pkg: .PkgName, ver: .InstalledVersion, fixed: (.FixedVersion // ""), sev: .Severity, target: $t, title: (.Title // "")}]'
base_keys=$(jq -c "$flat | map(\"\(.pkg)@\(.ver)|\(.id)\")" "$base")
new=$(jq -c --argjson seen "$base_keys" "$flat | map(select(\"\(.pkg)@\(.ver)|\(.id)\" as \$k | \$seen | index(\$k) | not)) | unique_by(.pkg, .ver, .id)
  | sort_by([({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,UNKNOWN:4}[.sev] // 5), .pkg])" "$head")
total=$(jq "$flat | length" "$head")
count=$(jq length <<<"$new")

echo "## Trivy dependency scan"
echo
if [ "$count" -eq 0 ]; then
  echo "No new vulnerabilities introduced by this pull request (${total} known in the changed tree)."
  exit 0
fi
echo "This pull request introduces **${count}** new vulnerabilit$([ "$count" -eq 1 ] && echo y || echo ies) (${total} in total on this branch)."
echo
echo "| Severity | Package | Installed | Fixed in | Advisory | Target |"
echo "|---|---|---|---|---|---|"
jq -r '.[:50][] | "| \(.sev) | `\(.pkg)` | \(.ver) | \(if .fixed == "" then "–" else .fixed end) | [\(.id)](https://avd.aquasec.com/nvd/\(.id | ascii_downcase)) | `\(.target)` |"' <<<"$new"
if [ "$count" -gt 50 ]; then
  echo
  echo "_Showing 50 of ${count}._"
fi
