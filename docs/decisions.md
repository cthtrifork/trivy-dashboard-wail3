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
| 14 | Frontend is **Vue 3 + Vite** with generated Wails bindings, replacing plain JS. Supersedes the "no build step" part of decision 1 and the old principle 15 | Maintainer request, following the Wails v3 notes tutorial and its Vue template. Costs: Node 20.19+/22.12+ is needed to build; `go build` needs `frontend/dist` (placeholder `.gitkeep` keeps `go vet`/`go test` working without it); CI, release and the Containerfile build the frontend first. Runtime dependencies are only `vue` and `@wailsio/runtime`; the graph stays canvas. The UI calls `ScanService` through generated bindings (`frontend/bindings`, committed so builds need no wails3 CLI) |
| 15 | VEX author and review-by date are stored per assessment but not exported to OpenVEX; an expired resolved assessment stops hiding its finding | OpenVEX has no statement expiry and its author is document-level. Expiry is a UTC date; the day itself still counts. Expired entries stay on record and are flagged, so a stale "not affected" cannot silently hide a CVE |
| 16 | Releases ship a PGP-signed `.deb` and `.rpm` built with `wails3 tool package` (nfpm), plus the public key. Signing uses nfpm's built-in signer with a key in repo secrets; a release fails if the key is missing | Maintainer request, following the Wails v3 Linux build guide. `wails3 tool sign` was not used: it shells out to `dpkg-sig`/`rpmsign` and passes the passphrase on a command line. Amends decision 8 only in adding formats, still amd64 only |
| 17 | Wails' built-in MCP server (`-tags mcp`) is a dev/test aid only: `make run-mcp`, `.mcp.json`, never in production | It gives an agent unauthenticated control of the UI and `ScanService` (principle 10). `mcp_guard.go` fails `mcp`+`production` builds and CI greps the release binary. In server mode it has no webview, so only `app_info`, `windows_list` and `emit_event` work (checked on beta.34); UI driving needs the desktop build. See `mcp.md` |
