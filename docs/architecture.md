# Architecture

## Flow

```
frontend (plain JS)  ──Wails bindings──►  ScanService (service.go)
                                              │
                                   trivy.Scanner (internal/trivy/scanner.go)
                                   ├─ Engine ── PodmanEngine ──► podman run aquasec/trivy image …
                                   │         └─ FixtureEngine (dev builds + TRIVY_SCANNER_FAKE_PODMAN only)
                                   ├─ Enricher ── EPSS + CISA KEV (cached in the user cache dir)
                                   ├─ assess.go ── rule engine: score, tier, attack-vector text
                                   ├─ compare.go ── diff two scans (vulns and packages)
                                   └─ vex.go ── VEXStore (JSON file) + OpenVEX export
```

## Build modes (tags)

| Build | Command | Notes |
|---|---|---|
| Desktop dev | `go run .` / `wails3 dev` | Real podman; fixtures available with `TRIVY_SCANNER_FAKE_PODMAN=1` |
| Desktop release | `go build -tags production` | GTK4 + WebKitGTK 6; updater on; no fixtures |
| Server (headless) | `-tags server` (+ `production`) | No window, HTTP on `WAILS_SERVER_HOST:PORT` (default `localhost:8080`); `headless=true` disables the updater; OpenVEX save falls back to a browser download |

Build with `CGO_ENABLED=0` for server mode to avoid GTK.

## Podman engine

- Runs `podman run --rm --name trivy-scanner-<random> -v <cache source>:/root/.cache/trivy docker.io/aquasec/trivy:latest image --cache-dir /root/.cache/trivy …`; the cache survives between scans. The vulnerability scan also passes `--list-all-pkgs`.
- Cancel: `podman rm --force --ignore --time 0 <name>`, then SIGTERM the client.
- Tags: `podman search --list-tags <repo qualified to docker.io>`.
- Env overrides: `PODMAN` (binary), `CONTAINER_HOST` (remote socket, used by the container deployment), `TRIVY_SCANNER_VEX_FILE`, `TRIVY_SCANNER_EPSS_URL`, `TRIVY_SCANNER_KEV_URL`, `XDG_CACHE_HOME`.

## Trivy cache

The scanner always gets an explicit `--cache-dir /root/.cache/trivy`, backed by a mount whose source is `TRIVY_SCANNER_CACHE`:

| Value | Meaning | Works with |
|---|---|---|
| unset, local podman | `<user cache dir>/trivy-scanner/trivy` on the host (Linux `~/.cache/trivy-scanner/trivy`, macOS `~/Library/Caches/trivy-scanner/trivy`), created if missing, mounted with `label=disable` for SELinux | Linux, macOS (podman machine shares the home directory) |
| unset, remote podman (`CONTAINER_HOST`/`DOCKER_HOST` set, as in the containerised headless deployment) or Windows | podman named volume `trivy-cache`, which lives wherever podman runs | any |
| `my-volume` | another named volume | any |
| `/abs/path` | a directory **on the machine running podman**; with a remote socket it must already exist (the app cannot create it) | local podman; remote with an existing path |

Relative paths and `:` are rejected, because podman would silently treat `./cache` as a volume name. The host directory is the default only when podman is local: if the app itself runs in a container, its own paths mean nothing to the podman host, so the volume is used there. Upgrading from the volume default re-downloads the Trivy DB once. Set `TRIVY_SCANNER_CACHE=trivy-cache` to keep using the old volume.

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
