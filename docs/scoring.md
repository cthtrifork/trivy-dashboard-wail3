# Scoring rules

The Priorities tab ranks findings with a small rule engine (`internal/trivy/assess.go`, `rules.go`). Every score is a sum of rules that fired, each printed on the card with its points and the exact rule, for example `EPSS ≥ 10% → +22`. A line under the reasons says which threshold decided the tier (`Fix soon: score 50 ≥ 45`).

## What you can tune

Open **Scoring rules** above the Priorities list. Changes re-rank immediately (the Go side rescores the latest scan; nothing is scanned again).

| Rule | Points (fixed) | Tunable |
|---|---|---|
| KEV | +50, +10 if used in ransomware | on/off; "always Act now" |
| EPSS | +10 from the cutoff, +22 from *high*, +35 from *very high* | on/off; the three thresholds (percent). *Very high* also forces Fix soon |
| Severity | critical +30, high +25, medium +10, low +3, unknown 0 (unrated scores nothing, so it cannot outrank a rated low) | on/off |
| Attack vector and impact (from the same source as the CVSS score: Red Hat, else NVD, else the highest) | exploitability: network +6, adjacent +2, physical −2; low complexity +2; no privileges +3; no user interaction +3 (at most 14). Impact: confidentiality and integrity high +4 / limited +2 each; availability scores nothing. No published vector: the CVSS score × 2.4, rounded, shown as an estimate. A missing score falls back to the floor of the severity band, as the UI shows it with a "~" (critical 9.0, high 7.0, medium 4.0, low 0.1; nothing for unknown) | on/off |
| Fix availability | fix +5, none −3, will not fix −5 | on/off; **fixed only** (no fix → score 0, Monitor) |
| Tiers | | minimum score for Act now / Fix soon / Plan |

The vector rule is kept small on purpose: severity already comes from the same CVSS data, so a large vector weight would count one number twice. Availability impact scores nothing because a denial of service ends with the attack, while a leak or tampered response does not, and severity already rates it. A plain network DoS with a fix therefore scores 44 (Plan), one point under Fix soon; EPSS or KEV lifts one that is really exploited. Without KEV or EPSS the highest possible score is 30 + 14 + 10 + 5 = 59, so nothing reaches Act now (70) on CVSS alone.

Severity comes from the same source as the CVSS score (Red Hat, else NVD, else the highest) when that source published one, so the band and the score cannot come from different places; otherwise Trivy's own severity is used. OS packages always keep Trivy's severity, which is the distribution's own rating. For language packages Trivy picks GitHub's advisory rating, which can disagree with every other source: one CVE was CRITICAL there and HIGH everywhere else, with a 7.5 score everywhere.

Points are deliberately not editable: you choose which rules apply and where their thresholds sit, so a score can always be recomputed by hand from what the card shows. The score is capped to 0–100. Out-of-order thresholds are repaired on the Go side (cutoff ≤ high ≤ very high, plan ≤ soon ≤ now).

## Presets

Built in (defined in `rules.go`, `Presets()`):

- **balanced**: the default, and exactly what a scan computes.
- **strict**: EPSS counts from 5% and *high* is 20%, fixed only is on, tiers start at 80 / 55 / 35.
- **exploited only**: KEV and EPSS alone; tiers 50 / 20 / 10.

Save your own with **Save preset**. The live rules and your presets are kept in the browser/webview's local storage (like the Trivy version option), so they are per machine, not part of the scan or the VEX file. The preset menu shows **custom** as soon as the rules no longer equal any preset.

## Scope

The rules apply to the Priorities and Vulnerabilities tabs. Compare and the scan result itself use the balanced rules. VEX hiding and the "Only with a fix" list filter in the Priorities toolbar are view filters that run after ranking.

## Code map

- `Rules`, `DefaultRules`, `Presets`, `Rescore`: `internal/trivy/rules.go`
- rule bodies and tier logic: `internal/trivy/assess.go` (`AssessWith`, `applyRules`)
- binding: `ScanService.Rescore`, `ScanService.RulePresets`; UI: `frontend/src/components/RulesEditor.vue`, `rerank()` in `frontend/src/store.js`
