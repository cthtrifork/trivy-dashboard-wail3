#!/usr/bin/env bash
# Usage: dependency-scan-report.sh BASE.json HEAD.json
# Prints a Markdown report of how a pull request changes the vulnerabilities Trivy finds: those only
# in HEAD (introduced) and those only in BASE (resolved). A finding is package + version + advisory id.
set -euo pipefail

jq -rn --slurpfile base "${1:?base trivy json}" --slurpfile head "${2:?head trivy json}" '
  def findings: [.Results[]? | .Target as $t | .Vulnerabilities[]?
    | {id: .VulnerabilityID, pkg: .PkgName, ver: .InstalledVersion, fixed: (.FixedVersion // "–"), sev: .Severity, target: $t}];
  def key: "\(.pkg)@\(.ver)|\(.id)";
  def rank: {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}[.sev] // 4;
  def only_in($other): ($other | map({(key): 1}) | add // {}) as $seen
    | unique_by(key) | map(select($seen[key] | not)) | sort_by([rank, .pkg]);
  def section($title; $list):
    if ($list | length) == 0 then empty else
      "", "### \($title) (\($list | length))", "",
      "| Severity | Package | Version | Fixed in | Advisory | Target |",
      "|---|---|---|---|---|---|",
      ($list[:50][] | "| \(.sev) | `\(.pkg)` | \(.ver) | \(.fixed) | [\(.id)](https://avd.aquasec.com/nvd/\(.id | ascii_downcase)) | `\(.target)` |"),
      (if ($list | length) > 50 then "", "_Showing 50 of \($list | length)._" else empty end)
    end;

  ($base[0] | findings) as $b | ($head[0] | findings) as $h
  | ($h | only_in($b)) as $new | ($b | only_in($h)) as $gone
  | "## Trivy dependency scan", "",
    (if ($new | length) + ($gone | length) == 0
     then "No change in vulnerabilities (\($h | length) on this branch)."
     else "\($h | length) on this branch: **\($new | length)** introduced, **\($gone | length)** resolved.",
          section("Introduced"; $new), section("Resolved"; $gone) end)
'
