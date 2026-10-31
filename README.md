# Trivy Scanner (Wails v3)

[![CI](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml)
[![Security](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/cthtrifork/trivy-dashboard-wail3)](https://github.com/cthtrifork/trivy-dashboard-wail3/releases)

Scan a container image with [Trivy](https://trivy.dev), which runs in a local Podman container, then decide what each finding means for you. The app ranks the findings, explains each one in plain language, and records your decisions as [OpenVEX](https://openvex.dev) statements, so you triage a shortlist instead of a wall of CVEs.

- **Priorities** – the landing view: a ranked shortlist, filterable by CVSS severity and by tier (Act now / Fix soon / Plan / Monitor). Every score is a sum of readable reasons from CISA **KEV**, **EPSS**, CVSS severity, attack vector and fix availability, each shown with its points, so you can see why a finding ranks where it does. Switch rules on or off, move thresholds and save presets: [`docs/scoring.md`](docs/scoring.md).
- **Assessment help** – the VEX editor opens with what you need to decide:
  - the CVSS vector in plain words (who can exploit it, what they need, what they can do), with the full breakdown and the ratings behind the headline score
  - where the package lives, as the route from the image through its dependencies
  - the other components that carry the same CVE, so one assessment can cover them all
  - a status (`affected`, `not_affected`, `fixed`, `under_investigation`), an OpenVEX justification and an impact statement, with example wording for each choice
  - an optional review date (30 or 90 days, or your own), after which the finding returns to the list marked as expired
- **VEX** – assessments are kept per image repository, so they carry over to new tags; resolved findings leave the shortlist. Export or import OpenVEX (v0.2.0).
- **Compare** – scan two tags or digests and diff them: severity deltas, vulnerabilities added / removed / unchanged, and package changes.
- **Vulnerabilities** – severity cards, search, sortable table, details. Trivy ignore rules and vendor statuses can hide findings you have already settled.
- **Dependencies and SBOM** – an interactive graph of the dependency tree, where a selected component shows its route from the image and its blast radius, and the CycloneDX component list with search and type filters.
- **Help** – a built-in help dialog explains the terms (KEV, EPSS, VEX statuses, justifications, SBOM).

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
