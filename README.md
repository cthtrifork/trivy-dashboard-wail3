# Trivy Scanner (Wails v3)

Desktop app: enter a container image reference, and Trivy runs inside a local
Podman container (`docker.io/aquasec/trivy`, version pinned in [`internal/trivy/image/Dockerfile`](internal/trivy/image/Dockerfile); choose another version or image under **Options → Trivy version or image**).

- **Priorities** – the landing view: a ranked shortlist instead of 150 CVEs, filterable by CVSS severity and by tier. An explainable 0–100 score combines CISA **KEV**, **EPSS**, CVSS severity, attack vector and fix availability. Tiers: Act now / Fix soon / Plan / Monitor. Tuning: [`docs/scoring.md`](docs/scoring.md).
- **VEX editor** – assess a finding as `affected`, `not_affected`, `fixed` or `under_investigation`, export or import OpenVEX (v0.2.0). Assessments are stored per image repository in `<user config dir>/trivy-scanner/vex.json`; resolved findings are hidden from the shortlist.
- **Compare** – scan two tags or digests and diff them: severity deltas, vulnerabilities added / removed / unchanged, and package changes.
- **Vulnerabilities** – severity cards, search, sortable table, details.
- **Dependencies** – interactive graph of the SBOM dependency graph.
- **SBOM** – CycloneDX components with search and type filters.

Screenshots: [`docs/screenshots`](docs/screenshots).

## Requirements
- Go 1.26+, [Wails v3 CLI](https://v3.wails.io) (`make wails3-install`)
- Node 20.19+ or 22.12+ for the Vue frontend (`frontend/`)
- Linux: GTK4 + WebKitGTK 6 dev packages; macOS/Windows: native webview
- `podman` on PATH (override with `PODMAN=/path/to/podman`)

## Run
    make frontend    # builds frontend/dist, which the binary embeds
    make run         # or: wails3 dev. Real podman, real scans
    make build       # production build
    make test        # replays recorded fixtures, no podman needed
    make demo        # dev builds only: the app on recorded data

`make help` lists all tasks. Without GTK, use the dev container (`make dev`, [`docs/devcontainer.md`](docs/devcontainer.md)).

## Notes
- The Trivy cache is a host directory (`~/.cache/trivy-scanner/trivy` on Linux); set `TRIVY_SCANNER_CACHE` to change it. The vulnerability DB is checked once per session and scans run with `--skip-db-update`. See [`docs/architecture.md`](docs/architecture.md#trivy-cache).
- The image field remembers the last 8 scanned images (with their Critical/High counts) in the browser/webview. Focus the field, pick one with ↑/↓ and press Enter to rescan, or Tab to fill it in.
- Private registries: pass credentials via *Options* (`TRIVY_USERNAME`/`TRIVY_PASSWORD`). Locally-built images not in a registry are not scanned.
- EPSS and KEV feeds can be overridden with `TRIVY_SCANNER_EPSS_URL` / `TRIVY_SCANNER_KEV_URL`; the VEX store with `TRIVY_SCANNER_VEX_FILE`.
- Release builds can self-update: [`docs/self-update.md`](docs/self-update.md).

## More
- Headless server over an SSH tunnel: [`docs/headless.md`](docs/headless.md)
- Wails MCP server (development only): [`docs/mcp.md`](docs/mcp.md)
- Window lifecycle: [`docs/lifecycle.md`](docs/lifecycle.md)
- UI conventions: [`docs/ux-design-sheet.md`](docs/ux-design-sheet.md)
- CI, screenshots and releases: [`docs/ci.md`](docs/ci.md), [`docs/releasing.md`](docs/releasing.md)
- Recorded fixtures for tests and demo mode: [`internal/trivy/fixtures`](internal/trivy/fixtures/README.md)
- Contributors and AI agents: [`AGENTS.md`](AGENTS.md)

The release binary is built on Ubuntu 24.04 and needs GTK4, WebKitGTK 6 and `podman` on the machine that runs it.
