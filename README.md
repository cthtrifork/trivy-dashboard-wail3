# Trivy Scanner (Wails v3)

[![CI](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/ci.yml)
[![Security](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/cthtrifork/trivy-dashboard-wail3/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/cthtrifork/trivy-dashboard-wail3)](https://github.com/cthtrifork/trivy-dashboard-wail3/releases)

Scan a container image with [Trivy](https://trivy.dev), then see each vulnerability in the context of the image's SBOM: which component carries it, how it got into the image, and what depends on it. Decisions are recorded as [OpenVEX](https://openvex.dev).

1. **Scan** an image. One scan gives you both the vulnerabilities and the SBOM.
2. **Triage** a ranked shortlist, with the reasons for each rank ([scoring](docs/scoring.md)).
3. **Trace** a finding to its SBOM component and what depends on it.
4. **Assess** with plain-language guidance, and keep the decision for new tags.
5. **Share** your decisions as clean, valid OpenVEX, and bring in other people's.

![Priorities view with an expanded row showing the reasons for its rank](https://raw.githubusercontent.com/cthtrifork/trivy-dashboard-wail3/bot/update-screenshots/docs/screenshots/01b-priorities-expanded-row.png)

## Install

Linux amd64 packages (`.deb`, `.rpm`), a tarball and signed checksums are on the [releases page](https://github.com/cthtrifork/trivy-dashboard-wail3/releases). Needs GTK4, WebKitGTK 6 and `podman`. Steps and signature check: [`docs/install.md`](docs/install.md). Release builds can [self-update](docs/self-update.md).

## Documentation
- Configuration and building from source: [`docs/development.md`](docs/development.md)
- Headless server over an SSH tunnel: [`docs/headless.md`](docs/headless.md)
- Network activity and offline behaviour: [`docs/network.md`](docs/network.md)

## Contributing and licence

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Released under the [MIT licence](LICENSE).
