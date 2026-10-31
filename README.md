# Trivy Scanner (Wails v3)

[![CI](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml)
[![Security](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/cthtrifork/trivy-dashboard-wail3)](https://github.com/cthtrifork/trivy-dashboard-wail3/releases)

Scan a container image with [Trivy](https://trivy.dev), then see each vulnerability in the context of the image's SBOM: which component carries it, how it got into the image, and what depends on it. Decisions are recorded as [OpenVEX](https://openvex.dev).

1. **Scan** an image with Trivy in Podman. One scan produces both the vulnerability report and the SBOM.
2. **Triage** a ranked shortlist. Each score lists its reasons (KEV, EPSS, severity, attack vector, fix), and the rules are tunable: [`docs/scoring.md`](docs/scoring.md).
3. **Trace** a finding to its SBOM component, its route from the image and everything that depends on it, in the dependency graph and SBOM views.
4. **Assess** with the CVSS vector in plain words, example wording per status and an optional review date. Assessments are kept per image and carry over to new tags.
5. **Share** the result as OpenVEX (import and export), and compare two tags to see what changed.

Screenshots are not committed. The draft [Screenshots preview](../../pulls?q=is%3Apr+is%3Aopen+head%3Abot%2Fupdate-screenshots) PR shows the current ones (Files changed), and `make screenshots` renders them locally.

## Install

Linux amd64 packages (`.deb`, `.rpm`), a tarball and signed checksums are on the [releases page](https://github.com/cthtrifork/trivy-dashboard-wail3/releases). Needs GTK4, WebKitGTK 6 and `podman`. Steps and signature check: [`docs/install.md`](docs/install.md). Release builds can [self-update](docs/self-update.md).

## Documentation
- Configuration and building from source: [`docs/development.md`](docs/development.md)
- Headless server over an SSH tunnel: [`docs/headless.md`](docs/headless.md)
- Network activity and offline behaviour: [`docs/network.md`](docs/network.md)

## Contributing and licence

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Released under the [MIT licence](LICENSE).
