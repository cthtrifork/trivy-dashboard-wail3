# Trivy Scanner (Wails v3)

[![CI](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml)
[![Security](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/cthtrifork/trivy-dashboard-wail3)](https://github.com/cthtrifork/trivy-dashboard-wail3/releases)

Scan a container image with [Trivy](https://trivy.dev), then decide what each finding means for you. Decisions are recorded as [OpenVEX](https://openvex.dev).

1. **Scan** an image with Trivy in Podman.
2. **Triage** a ranked shortlist, with the reasons for each rank.
3. **Assess** each finding with built-in guidance and record the decision.
4. **Share** the result as OpenVEX, and compare tags to see what changed.

All features: [`docs/features.md`](docs/features.md).

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
