# Status

Update this file in every PR that changes what is done or known-unverified. Last updated: 2026-10-24.

## Shipped (merged to `main`)

Scan + Priorities + Vulnerabilities + SBOM + Dependency graph + Compare + VEX editor/OpenVEX + Log panels; qualifyRepo fix for `podman search`; CI/security/release workflows; self-update; Wails lifecycle (cancel on quit); Tag-and-release workflow; headless guide and `Containerfile`.

## Known unverified

- `Containerfile` runtime layer (`apk add podman-remote` on Alpine 3.24): the sandbox cannot reach Alpine mirrors. The maintainer ran it on a real server and reported it works (2026-10-24).
- Rootless podman, SELinux, linger/reboot persistence of the headless container: not tested by an agent.
- End-to-end scan with a real Trivy DB download from the sandbox (ghcr.io blocked); tested via a shim and recorded fixtures.
- The GUI (GTK) build was never run in the sandbox; CI links it, nobody has clicked through it from an agent session.
- Self-update was tested against fakes, not a real published release swap.

## Open ideas (not requested; do not start without asking)

- A quadlet/systemd unit for the headless container so it starts on boot.
- Publish a container image from `release.yml` so servers can `podman pull` instead of building.
- Optional auth in front of server mode (reverse proxy docs).
- Scan history and trend view.
- Version-pinned Trivy image instead of `:latest`.
