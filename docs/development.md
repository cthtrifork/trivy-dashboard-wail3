# Development

Build and run from source. For installing a release, see [`install.md`](install.md).

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

## More
- Wails MCP server (development only): [`mcp.md`](mcp.md)
- Window lifecycle: [`lifecycle.md`](lifecycle.md)
- UI conventions: [`ux-design-sheet.md`](ux-design-sheet.md)
- CI, screenshots and releases: [`ci.md`](ci.md), [`releasing.md`](releasing.md)
- Recorded fixtures for tests and demo mode: [`internal/trivy/fixtures`](../internal/trivy/fixtures/README.md)
- Contributing: [`CONTRIBUTING.md`](../CONTRIBUTING.md); AI agents: [`AGENTS.md`](../AGENTS.md)
