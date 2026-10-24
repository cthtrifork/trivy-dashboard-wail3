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

- Runs `podman run --rm --name trivy-scanner-<random> -v trivy-cache:/root/.cache/trivy docker.io/aquasec/trivy:latest image --cache-dir /root/.cache/trivy …`; the cache survives between scans. The vulnerability scan also passes `--list-all-pkgs`.
- Cancel: `podman rm --force --ignore --time 0 <name>`, then SIGTERM the client.
- Tags: `podman search --list-tags <repo qualified to docker.io>`.
- Env overrides: `PODMAN` (binary), `CONTAINER_HOST` (remote socket, used by the container deployment), `TRIVY_SCANNER_VEX_FILE`, `TRIVY_SCANNER_EPSS_URL`, `TRIVY_SCANNER_KEV_URL`, `XDG_CACHE_HOME`.

## Trivy cache

The scanner always gets an explicit `--cache-dir /root/.cache/trivy`, backed by a mount whose source is `TRIVY_SCANNER_CACHE`:

| Value | Meaning | Works with |
|---|---|---|
| unset | podman named volume `trivy-cache` | local podman, podman machine (macOS/Windows), remote podman socket (the volume lives on the podman host) |
| `my-volume` | another named volume | same |
| `/abs/path` | a directory **on the machine running podman**, mounted with `label=disable` for SELinux | local podman; with a remote socket the path must already exist on the server (the app cannot create it) |

Relative paths and `:` are rejected, because podman would silently treat `./cache` as a volume name. A host path is *not* the default because it breaks when the app itself runs in a container (its `/data/...` is not the host's), and macOS/Windows podman runs in a VM that sees only some host paths.

## Server mode security

Wails rejects requests with a non-loopback `Host` header when bound to loopback (DNS-rebinding guard). Binding `0.0.0.0` is treated as a deliberate network deployment and is unguarded, hence principle 10. Events travel over a WebSocket at `/wails/events`.

## Lifecycle

`ServiceStartup` stores the app context and wires the log emitter; every scan derives from it. `ServiceShutdown` cancels and waits up to one second for the container to be removed. Details: [lifecycle.md](lifecycle.md).

## Release and CI

`ci.yml` (PRs and main), `security.yml` (govulncheck + Trivy fs), `tag-release.yml` (pick tag or patch/minor/major, tags `main`), `release.yml` (build, checksums, attestation, GitHub release). See [ci.md](ci.md), [releasing.md](releasing.md), [self-update.md](self-update.md).

## Deployment without Go

[`Containerfile`](../Containerfile) builds the server binary inside podman; at runtime the container uses `podman-remote` against the host socket. See [headless.md](headless.md).
