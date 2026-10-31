# Trivy Scanner (Wails v3)

[![CI](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml)
[![Security](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/cthtrifork/trivy-dashboard-wail3)](https://github.com/cthtrifork/trivy-dashboard-wail3/releases)

Scan a container image with [Trivy](https://trivy.dev) (run in a local Podman container), then decide what each finding means for you. Findings are ranked and explained, and your decisions are recorded as [OpenVEX](https://openvex.dev).

- **Priorities** – a ranked shortlist by tier (Act now / Fix soon / Plan / Monitor). Each score is a sum of readable reasons (CISA **KEV**, **EPSS**, CVSS severity, attack vector, fix availability) with tunable rules and presets: [`docs/scoring.md`](docs/scoring.md).
- **Assessment help** – the VEX editor shows the CVSS vector in plain words, where the package lives, and the other components with the same CVE. It offers example wording per status and justification, and an optional review date after which the finding returns to the list.
- **VEX** – assessments are stored per image repository and carry over to new tags. Export or import OpenVEX (v0.2.0).
- **Compare** – diff two tags or digests: severity deltas, added / removed vulnerabilities, package changes.
- **Vulnerabilities** – severity cards, search, sortable table, details; ignore rules and vendor statuses hide settled findings.
- **Dependencies and SBOM** – dependency graph with each component's route from the image and blast radius; CycloneDX component list.
- **Help** – a built-in dialog explains KEV, EPSS, VEX statuses, justifications and SBOM.

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
