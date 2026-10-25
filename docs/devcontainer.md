# Dev container and hot reload

A dev container with Go, Node, `air` (Go reloader), the `wails3` CLI and rootless podman. It runs the app in **server mode** (the GUI needs GTK, which the container does not have) and you use it in a browser.

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

The container runs rootless **podman inside itself**, and the app starts Trivy with it, like a local `go run .`. That is why `devcontainer.json` sets `"privileged": true`, and why podman's storage is a named volume (`trivy-scanner-podman-storage`): rebuilding the dev container keeps the pulled Trivy image. Trivy's DB cache is in `~/.cache/trivy-scanner` inside the container.

Check it with `podman run --rm docker.io/library/alpine echo ok`. If podman cannot run here, `make dev` says so and uses the recorded demo data (`TRIVY_SCANNER_FAKE_PODMAN=1`, never in production builds).

Alternative on a Linux host with rootless podman: reuse the host's podman and image cache instead.

```sh
systemctl --user enable --now podman.socket          # on the host
```

then in `devcontainer.json` add the mount `source=${localEnv:XDG_RUNTIME_DIR}/podman/podman.sock,target=/run/podman/podman.sock,type=bind`, set `CONTAINER_HOST=unix:///run/podman/podman.sock` in `containerEnv`, and install `podman-remote` in place of `podman`. You can then drop `privileged`.

## Checks

The container is headless only: `CGO_ENABLED=0` and `GOFLAGS=-tags=server` are set, so plain `go build`, `go test`, `go vet` and `go run .` all work without GTK, and `make vet` uses `VET_TAGS=server,production`.

`make check` (gofmt, `go mod tidy -diff`, vet, race tests, headless build) works in the container. The desktop GUI build and `wails3 dev` are not supported here.

## Troubleshooting

- *"unable to connect to frontend server"*: Vite is not up; run `make dev` rather than starting `air` by hand.
- *Port in use*: `WAILS_SERVER_PORT=9090 make dev`.
- Going through a forwarded URL other than `localhost` (Codespaces web URL) can trip Wails' loopback `Host` check; use the editor's local port forward instead.
- *Podman storage errors* (overlay on an unsupported filesystem, common on Docker Desktop): `printf '[storage]\ndriver = "vfs"\n' > ~/.config/containers/storage.conf` (slower, always works), then `podman system reset`.
