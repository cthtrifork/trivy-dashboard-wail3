# Trivy Scanner (Wails v3)

Desktop app: enter a container image reference, and Trivy runs inside a local
Podman container (`docker.io/aquasec/trivy`). Results show in two panels:

- **Priorities** – the landing view: instead of 150 CVEs, a ranked shortlist (top 10 by default). Each finding gets a 0–100 score from a small explainable rule engine that combines
  CISA **KEV** (documented exploitation), **EPSS** (predicted 30-day exploitation probability), CVSS severity, attack vector/complexity/privileges/user interaction, and fix availability.
  Every card shows the points behind its rank and a plain-English attack-vector assessment. Tiers: Act now / Fix soon / Plan / Monitor (low-risk hidden by default).
- **VEX editor** – on any finding choose `affected`, `not_affected`, `fixed` or `under_investigation`, add a justification / impact / action statement (validated per the OpenVEX rules),
  and **Export OpenVEX** (v0.2.0). Assessments are stored in `<user config dir>/trivy-scanner/vex.json` per image repository, so they carry over to later scans and tags; resolved findings are hidden from the shortlist.
- **Compare** – pick an image repository and two tags (*Load tags* asks the registry via `podman search --list-tags`; you can also type tags or `sha256:` digests). Both are scanned and diffed docker-scout style:
  side-by-side severity counts with deltas, a verdict, vulnerabilities **added / removed / unchanged** with the reason (package upgraded, package removed/new, newly disclosed), and package **added / removed / upgraded / downgraded** with per-package vulnerability counts.
- **Vulnerabilities** – severity cards (click to filter), search, sortable table, click a row for details.
- **Dependencies** – an interactive force-directed **graph** of the SBOM dependency graph (canvas, no libraries): nodes are components (square = OS package, circle = library/app; fill = worst vulnerability in the package itself, ring = vulnerable only via a dependency; size = vulnerability count), arrows point from a package to what it depends on, laid out top-down from the image. Scroll to zoom, drag to pan or move nodes, double-click to fit. Defaults to vulnerable paths only; search, OS/Application filter, and *Focus* (selection ±1–3 hops) keep big images readable (max 400 nodes drawn). Click a node for its vulnerabilities and clickable *Depends on* / *Required by* lists.
- **SBOM** – CycloneDX components (name, version, type, license, purl) with search and type filters.

## Requirements
- Go 1.26+ (required by Wails v3 beta.34), [Wails v3 CLI](https://v3.wails.io) (`go install github.com/wailsapp/wails/v3/cmd/wails3@latest`)
- Linux: GTK4 + WebKitGTK 6 dev packages (see Wails docs); macOS/Windows: native webview
- `podman` on PATH (override with `PODMAN=/path/to/podman`)

## Run
    go run .            # or: wails3 build && ./bin/...
    go test ./internal/...

Notes: the Trivy DB is cached in the `trivy-cache` podman volume. Trivy pulls the
target image itself from the registry; for private registries use *Options* to
pass credentials (via `TRIVY_USERNAME`/`TRIVY_PASSWORD` env, not argv).
Locally-built images that aren't in a registry are not scanned.

## Exploitation data
EPSS comes from `api.first.org`, KEV from CISA's JSON feed (cached on disk for 12h, stale cache used if offline). If a feed is unreachable the scan still works and the UI says which signal is missing.
Override with `TRIVY_SCANNER_EPSS_URL` / `TRIVY_SCANNER_KEV_URL` (mirrors, air-gapped use) and `TRIVY_SCANNER_VEX_FILE` (VEX store location).

## CI and releases (GitHub Actions)
- **CI** (`.github/workflows/ci.yml`) – every PR and push to `main`: gofmt, `go mod tidy -diff` / `verify`, `go vet`, `go test -race`, a production-tag build that links GTK4/WebKitGTK, and a JS syntax check.
- **Security** (`security.yml`) – `govulncheck` and a Trivy filesystem scan when Go files or dependencies change, plus weekly (new advisories appear without code changes).
- **Release** (`release.yml`) – push a semver tag from `main` (`git tag v1.2.3 && git push origin v1.2.3`; `v1.2.3-rc.1` makes a pre-release). It re-runs vet/tests/govulncheck, builds a Linux amd64 binary, and publishes a GitHub release with a tarball, SHA-256 checksums, generated notes and a build-provenance attestation (`gh attestation verify <tarball> --repo <owner>/<repo>`). Run it manually for a dry run that builds but does not publish.
- Dependabot keeps Go modules and the SHA-pinned actions current.

The release binary is built on Ubuntu 24.04 and links dynamically, so it needs GTK4 and WebKitGTK 6 (and a glibc at least as new as Ubuntu 24.04's) on the machine that runs it, plus `podman`.
