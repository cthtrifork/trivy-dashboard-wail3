# Dev container and hot reload

A dev container with Go, Node, `air` (Go reloader), the `wails3` CLI and the podman client. It runs the app in **server mode** (the GUI needs GTK, which the container does not have) and you use it in a browser.

## Start

1. Install Docker or Podman plus an editor that speaks dev containers (VS Code *Dev Containers*, GitHub Codespaces, or `devcontainer up`).
2. Open the repo and choose **Reopen in Container**. The first start runs `.devcontainer/post-create.sh` (`npm ci`, `go mod download`, installs `air` and `wails3`).
3. In the container terminal: `make dev`, then open <http://localhost:8080> (port 8080 is forwarded).

## What reloads

`make dev` (`scripts/dev.sh`) runs two watchers:

| You edit | What happens |
|---|---|
| `frontend/src/**` (Vue, JS, CSS) | Vite HMR updates the browser, no restart |
| `*.go` (not tests) | `air` rebuilds with `-tags server` and restarts the app; refresh the page |
| an exported `ScanService` method or type | also run `make bindings` and commit `frontend/bindings` |

The Go app proxies the page to Vite (`FRONTEND_DEVSERVER_URL`, dev builds only), so the embedded `frontend/dist` is not used while developing. `WAILS_SERVER_PORT` (default 8080) and `WAILS_VITE_PORT` (default 9245) change the ports.

## Real scans or demo data

Scans run in podman containers through an API socket. Without one, `make dev` prints a notice and uses the recorded demo data (`TRIVY_SCANNER_FAKE_PODMAN=1`, never in production builds).

For real scans on a Linux host with rootless podman:

```sh
systemctl --user enable --now podman.socket          # on the host
```

then uncomment `mounts` and `runArgs` in `.devcontainer/devcontainer.json` and rebuild the container. `CONTAINER_HOST` already points at `/run/podman/podman.sock`. On macOS/Windows or in Codespaces there is no such socket; use demo mode.

## Checks

`make check` (gofmt, `go mod tidy -diff`, vet, race tests, headless build) works in the container. The GUI build and `wails3 dev` do not (no GTK).

## Troubleshooting

- *"unable to connect to frontend server"*: Vite is not up; run `make dev` rather than starting `air` by hand.
- *Port in use*: `WAILS_SERVER_PORT=9090 make dev`.
- Going through a forwarded URL other than `localhost` (Codespaces web URL) can trip Wails' loopback `Host` check; use the editor's local port forward instead.
