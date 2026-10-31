# Development and configuration

Build and run from source, and the settings that apply to any build. To install a release, see [`install.md`](install.md).

## Requirements
- Go 1.27+, [Wails v3 CLI](https://v3.wails.io) (`make wails3-install`)
- Node 20.19+ or 22.12+ for the Vue frontend (`frontend/`); CI and the container images use the version in `.tool-versions`
- Linux: GTK4 + WebKitGTK 6 dev packages; macOS/Windows: native webview
- `podman` on PATH (override with `PODMAN=/path/to/podman`)

## Run
    make frontend    # builds frontend/dist, which the binary embeds
    make run         # or: wails3 dev. Real podman, real scans
    make build       # production build
    make test        # replays recorded fixtures, no podman needed
    make demo        # dev builds only: the app on recorded data

`make help` lists all tasks. Without GTK, use the dev container (`make dev`, [`devcontainer.md`](devcontainer.md)).

## Configuration
- The Trivy cache is a host directory (`~/.cache/trivy-scanner/trivy` on Linux); set `TRIVY_SCANNER_CACHE` to change it. The vulnerability DB is checked once per session and scans run with `--skip-db-update`. See [`architecture.md`](architecture.md#trivy-cache).
- The image field remembers the last 8 scanned images (with their Critical/High counts) in the browser/webview. Focus the field, pick one with ↑/↓ and press Enter to rescan, or Tab to fill it in.
- Private registries: pass credentials via *Options* (`TRIVY_USERNAME`/`TRIVY_PASSWORD`). Locally-built images not in a registry are not scanned.
- EPSS and KEV feeds can be overridden with `TRIVY_SCANNER_EPSS_URL` / `TRIVY_SCANNER_KEV_URL`; the VEX store with `TRIVY_SCANNER_VEX_FILE`.

## More
- Wails MCP server (development only): [`mcp.md`](mcp.md)
- Window lifecycle: [`lifecycle.md`](lifecycle.md)
- UI conventions: [`ux-design-sheet.md`](ux-design-sheet.md)
- CI, screenshots and releases: [`ci.md`](ci.md), [`releasing.md`](releasing.md)
- Recorded fixtures for tests and demo mode: [`internal/trivy/fixtures`](../internal/trivy/fixtures/README.md)
- Contributing: [`CONTRIBUTING.md`](../.github/CONTRIBUTING.md); AI agents: [`AGENTS.md`](../AGENTS.md)
