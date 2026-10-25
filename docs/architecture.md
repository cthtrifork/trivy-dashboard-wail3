# Architecture

## Flow

```
frontend (Vue 3)     ──Wails bindings──►  ScanService (service.go)
                                              │
                                   trivy.Scanner (internal/trivy/scanner.go)
                                   ├─ Engine ── PodmanEngine ──► podman run aquasec/trivy image …
                                   │         └─ FixtureEngine (dev builds + TRIVY_SCANNER_FAKE_PODMAN only)
                                   ├─ Enricher ── EPSS + CISA KEV (cached in the user cache dir)
                                   ├─ assess.go ── rule engine: score, tier, attack-vector text
                                   ├─ compare.go ── diff two scans (vulns and packages)
                                   └─ vex.go ── VEXStore (JSON file) + OpenVEX export
```

## Frontend

`frontend/` is a Vue 3 + Vite app. `src/App.vue` is the shell (scan form, tabs, status); each tab is a component in `src/components/`. `src/store.js` holds the shared state (the scan result, saved VEX assessments, options) and the log/status plumbing. The UI calls the Go `ScanService` through generated bindings in `frontend/bindings` (`wails3 generate bindings`, run it via `make bindings`), and listens for `scan:log` events with `@wailsio/runtime`. `src/lib/graph.js` is the canvas dependency graph. `npm run build` writes `frontend/dist`, which `main.go` embeds.

### Large scans

Long lists never put every row in the DOM. `src/lib/virtual.js` (`useVirtualList`) renders only the rows near the scroll viewport, between two spacers; it measures the rows it has rendered (rows differ in height: wrapped text, an expanded detail, an open VEX editor) and assumes the average for the rest. It backs the Vulnerabilities, SBOM and Compare tables and the Priorities cards, so the DOM stays around a thousand nodes whether a scan has 30 or 6,000 findings. The tables use fixed column widths so scrolling never reflows them. The log keeps its last ~300 kB, and the dependency detail pane lists at most 100 entries per section. The scan result itself stays in memory as a shallow (non-reactive) object. The dependency graph is a canvas that draws at most 400 components (the highest-risk ones, or the neighbourhood of the selection), so its cost does not grow with the image; the search box is debounced and filters a per-scan index of precomputed search text and severity weights. Measured on a synthetic graph: 100,000 components kept 61 fps and about 66 MB of heap, with about 35 ms per keystroke. What does grow is the scan payload, because the Go side sends every component (about 45 MB at 100,000). To re-measure, amplify the demo response in Playwright (route `/wails/runtime`) and compare `document.querySelectorAll('*').length` and the JS heap before and after.

## Build modes (tags)

| Build | Command | Notes |
|---|---|---|
| Desktop dev | `go run .` / `wails3 dev` | Real podman; fixtures available with `TRIVY_SCANNER_FAKE_PODMAN=1` |
| Desktop release | `go build -tags production` | GTK4 + WebKitGTK 6; updater on; no fixtures |
| Server (headless) | `-tags server` (+ `production`) | No window, HTTP on `WAILS_SERVER_HOST:PORT` (default `localhost:8080`); `headless=true` disables the updater; OpenVEX save falls back to a browser download |

Build with `CGO_ENABLED=0` for server mode to avoid GTK.

## Podman engine

- Runs `podman run --rm --name trivy-scanner-<random> -v <cache source>:/root/.cache/trivy <trivy image> image --cache-dir /root/.cache/trivy …`; the cache survives between scans. The vulnerability scan also passes `--list-all-pkgs`.
- Cancel: `podman rm --force --ignore --time 0 <name>`, then SIGTERM the client.
- Tags: `podman search --list-tags <repo qualified to docker.io>`.
- Env overrides: `PODMAN` (binary), `CONTAINER_HOST` (remote socket, used by the container deployment), `TRIVY_SCANNER_VEX_FILE`, `TRIVY_SCANNER_EPSS_URL`, `TRIVY_SCANNER_KEV_URL`, `XDG_CACHE_HOME`.

## Trivy cache

The footer shows a small footprint note (`ScanService.Footprint`): the size of the Trivy cache and the Go runtime's memory. The KEV catalog is a few hundred KB, too small to be worth a figure. A podman volume cannot be measured by the app, so it is named instead.

The scanner always gets an explicit `--cache-dir /root/.cache/trivy`, backed by a mount whose source is `TRIVY_SCANNER_CACHE`:

| Value | Meaning | Works with |
|---|---|---|
| unset, local podman | `<user cache dir>/trivy-scanner/trivy` on the host (Linux `~/.cache/trivy-scanner/trivy`, macOS `~/Library/Caches/trivy-scanner/trivy`), created if missing, mounted with `label=disable` for SELinux | Linux, macOS (podman machine shares the home directory) |
| unset, remote podman (`CONTAINER_HOST`/`DOCKER_HOST` set, as in the containerised headless deployment) or Windows | podman named volume `trivy-cache`, which lives wherever podman runs | any |
| `my-volume` | another named volume | any |
| `/abs/path` | a directory **on the machine running podman**; with a remote socket it must already exist (the app cannot create it) | local podman; remote with an existing path |

Relative paths and `:` are rejected, because podman would silently treat `./cache` as a volume name. The host directory is the default only when podman is local: if the app itself runs in a container, its own paths mean nothing to the podman host, so the volume is used there. Upgrading from the volume default re-downloads the Trivy DB once. Set `TRIVY_SCANNER_CACHE=trivy-cache` to keep using the old volume.

### Trivy version

The default image is pinned in [`internal/trivy/image/Dockerfile`](../internal/trivy/image/Dockerfile) (`FROM docker.io/aquasec/trivy:<version>`), embedded into the binary and read by `DefaultTrivyImage()`. Dependabot's `docker` ecosystem (`.github/dependabot.yml`) opens a PR when a newer tag exists, so the version is bumped like any dependency. It is a Dockerfile only because that is what Dependabot understands; it is never built.

Override it per run in the UI: **Options → Trivy version or image** (empty = the default; the field is remembered by the browser/webview). It takes a full reference (`registry.local/mirror/trivy:0.77.0`, `...@sha256:...`) or just a version (`0.77.0` / `v0.77.0`, meaning `docker.io/aquasec/trivy:0.77.0`), and is sent with every scan and comparison as `trivyImage`. Values that look like flags or contain whitespace are refused before anything runs. Changing it makes the next scan re-check the vulnerability DB for that version.

### Vulnerability DB

Before the first scan of a session, and then at most once an hour, the scanner runs `trivy image --download-db-only` (no image, no registry credentials) against the cache. Trivy only downloads when its DB is past `NextUpdate`, so this is cheap when the cache is fresh. The scans themselves then run with `--skip-db-update`, so a Compare (four scans) checks once instead of four times. If the check fails (offline, rate limited) it logs a warning and the scans use whatever is cached; with an empty cache the scan fails with Trivy's own error. A failed check is retried on the next scan. `TRIVY_DB_REPOSITORY` and `TRIVY_JAVA_DB_REPOSITORY`, when set in the app's environment, are forwarded to Trivy for mirrors. The Java DB is not pre-fetched: Trivy downloads it into the same cache only when an image contains JARs.

## Server mode security

Wails rejects requests with a non-loopback `Host` header when bound to loopback (DNS-rebinding guard). Binding `0.0.0.0` is treated as a deliberate network deployment and is unguarded, hence principle 10. Events travel over a WebSocket at `/wails/events`.

## Lifecycle

`ServiceStartup` stores the app context and wires the log emitter; every scan derives from it. `ServiceShutdown` cancels and waits up to one second for the container to be removed. Details: [lifecycle.md](lifecycle.md).

## Release and CI

`ci.yml` (PRs and main), `security.yml` (govulncheck + Trivy fs), `tag-release.yml` (pick tag or patch/minor/major, tags `main`), `release.yml` (build, checksums, attestation, GitHub release). See [ci.md](ci.md), [releasing.md](releasing.md), [self-update.md](self-update.md).

## Deployment without Go

[`Containerfile`](../Containerfile) builds the server binary inside podman; at runtime the container uses `podman-remote` against the host socket. See [headless.md](headless.md).
