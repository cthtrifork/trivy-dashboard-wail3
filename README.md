# Trivy Scanner (Wails v3)

[![CI](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml)
[![Security](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/cthtrifork/trivy-dashboard-wail3)](https://github.com/cthtrifork/trivy-dashboard-wail3/releases)

Scan a container image for vulnerabilities with [Trivy](https://trivy.dev), which runs in a local Podman container, and get a ranked shortlist of what to fix first instead of a wall of CVEs.

- **Priorities** – the landing view: a ranked shortlist instead of 150 CVEs, filterable by CVSS severity and by tier. An explainable 0–100 score combines CISA **KEV**, **EPSS**, CVSS severity, attack vector and fix availability. Tiers: Act now / Fix soon / Plan / Monitor. Tuning: [`docs/scoring.md`](docs/scoring.md).
- **VEX editor** – assess a finding as `affected`, `not_affected`, `fixed` or `under_investigation`, export or import OpenVEX (v0.2.0). Assessments are stored per image repository in `<user config dir>/trivy-scanner/vex.json`; resolved findings are hidden from the shortlist.
- **Compare** – scan two tags or digests and diff them: severity deltas, vulnerabilities added / removed / unchanged, and package changes.
- **Vulnerabilities** – severity cards, search, sortable table, details.
- **Dependencies** – interactive graph of the SBOM dependency graph. A selected component shows its route from the image and its blast radius (everything that requires it, directly or through others).
- **SBOM** – CycloneDX components with search and type filters.

Screenshots are not committed. The draft [Screenshots preview](../../pulls?q=is%3Apr+is%3Aopen+head%3Abot%2Fupdate-screenshots) PR shows the current ones (Files changed), and `make screenshots` renders them locally.

## Install

Linux amd64 packages (`.deb`, `.rpm`), a tarball and signed checksums are on the [releases page](https://github.com/cthtrifork/trivy-dashboard-wail3/releases). Needs GTK4, WebKitGTK 6 and `podman`. Steps and signature check: [`docs/install.md`](docs/install.md). Release builds can [self-update](docs/self-update.md).

## Documentation
- Configuration, cache and private registries: [`docs/configuration.md`](docs/configuration.md)
- Build from source: [`docs/development.md`](docs/development.md)
- Headless server over an SSH tunnel: [`docs/headless.md`](docs/headless.md)
- Network activity and offline behaviour: [`docs/network.md`](docs/network.md)

## Contributing and licence

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Released under the [MIT licence](LICENSE).
