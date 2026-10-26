# Recorded Trivy output

Real output of Trivy, recorded once. It is used **only** by the Go tests and, when
`TRIVY_SCANNER_FAKE_PODMAN=1` is set on a development build, by the screenshot script
(`scripts/screenshots.sh`). Normal runs, `wails3 dev` included, use real podman. Nothing
here is synthetic, with one exception: the `CVSS` block of CVE-2026-78667 in `traefik_3.7.13.json` was removed by hand so the UI has a finding with no reported score (shown as an estimate). Re-recording drops that edit.

| File | What it is | Used for |
|---|---|---|
| `traefik_3.7.13.json` | `trivy image --format json --scanners vuln traefik:3.7.13` | Vulnerabilities / Priorities panels, Compare base |
| `traefik_3.7.16.json` | the same for `traefik:3.7.16` | Compare target |
| `trivy_3.7.16.sbom.json` | `trivy image --format cyclonedx traefik:3.7.16` | SBOM and Dependencies panels |
| `traefik_3.7.13.sbom.json` | the same for `traefik:3.7.13` | the other side of Compare's package diff |

The engine matches files by the **version in the name** (`<anything>_<x.y.z>.json` and
`<anything>_<x.y.z>.sbom.json`), so the `trivy_` prefix on the 3.7.16 SBOM is cosmetic.
If a version has no SBOM, the newest SBOM at or below it is used (else the oldest).

## Provenance
Recorded on 2026-10-24 with Trivy 0.76.1, vulnerability DB `mirror.gcr.io/aquasec/trivy-db:2`, against the
public Docker Hub images `traefik:3.7.13` and `traefik:3.7.16`. Findings reflect the DB at that moment: a new
scan today can differ. The data is public vulnerability information; it says nothing about Traefik beyond
those two images at that date.

## Re-recording
```sh
for v in 3.7.13 3.7.16; do
  trivy image --format json     --scanners vuln traefik:$v > internal/trivy/fixtures/traefik_$v.json
  trivy image --format cyclonedx                traefik:$v > internal/trivy/fixtures/traefik_$v.sbom.json
done
```
The tests pin exact counts from these files (`internal/trivy/fixture_test.go`); update them when you re-record.
