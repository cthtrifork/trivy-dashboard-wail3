# Decision log

Short records of decisions. Add new entries at the bottom; supersede rather than delete.

| # | Decision | Why |
|---|---|---|
| 1 | Wails v3 (beta.34), Go 1.26, plain JS frontend with no build step | Matches the requested stack; no Node needed to build; frontend embedded with `go:embed` |
| 2 | Scans run Trivy in a **podman** container, not a local Trivy install | Requested; keeps the host clean; the Trivy DB lives in a host cache directory (local podman) or the `trivy-cache` volume (remote podman), see architecture.md |
| 3 | Fixtures are for tests and screenshots only; `wails dev` uses real podman unless `TRIVY_SCANNER_FAKE_PODMAN=1` | Maintainer reversed an earlier "fake in dev" design; fixtures are compiled out of production builds |
| 4 | Priorities view ranks with an explainable rule engine (KEV, EPSS, CVSS, attack vector, fix availability) | Goal: ten findings that matter, with a reason shown |
| 5 | VEX assessments stored per image repository in a JSON file; export OpenVEX v0.2.0 | Carries over between scans and tags |
| 6 | Dependency view is a force-directed **graph**, not a tree | Maintainer request; canvas, no library |
| 7 | CI follows Wails v3's own workflow for tests; v2 build-action ideas only where they apply (see `ci.md`) | The cross-platform guide has no test step and targets v2 |
| 8 | Linux amd64 only | Maintainer: "only need to build a Linux binary" |
| 9 | **Fedora/GTK3 variant dropped** | Maintainer cancelled it |
| 10 | Self-update via GitHub releases, SHA-256 verified, user-initiated, off in dev/headless | Wails self-update tutorial; see `self-update.md` |
| 11 | Releases cut by the *Tag and release* workflow (tag or patch/minor/major) | Tags cannot be pushed from the agent sandbox; one-click for the maintainer |
| 12 | Headless use is an SSH tunnel to a loopback listener; no auth layer | Wails server mode has none; exposing it is out of scope (principle 10) |
| 13 | Podman-only servers run the app in a container with `podman-remote` and the host socket, `--network host` | Server has no Go; host network keeps the loopback Host guard |
