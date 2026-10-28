# Dev container and hot reload

A dev container with Go and Node (both baked into the `Dockerfile`, copied from the official `golang` and `node` images, pulled from `mirror.gcr.io`, no dev container features), the `wails3` CLI and rootless podman. It runs the app in **server mode** (the GUI needs GTK, which the container does not have) and you use it in a browser.

## Start

1. Install Docker or Podman plus an editor that speaks dev containers (VS Code *Dev Containers*, GitHub Codespaces, or `devcontainer up`).
2. Open the repo and choose **Reopen in Container**. The first start runs `.devcontainer/post-create.sh` (`npm ci`, `go mod download`, installs `wails3`).
3. In the container terminal: `make dev`, then open <http://localhost:8080> (port 8080 is forwarded).

## Editor

The container installs the Go, Biome, MDX and Vue extensions. The Go tools (`goimports`, `golangci-lint`, `govulncheck`, pinned in `tools/go.mod`) come from `make tools`, run by `post-create.sh`. `.vscode/settings.json` is committed: format on save (`goimports` for Go, Biome for JS, Vue, CSS, HTML and JSON; Markdown is left alone) and `golangci-lint` on save.

Frontend checks: `make lint-frontend` (`npm run lint` and `npm run format:check`) and `make format-frontend` (`npm run format`); Biome, config in `biome.json`, generated `bindings/` and `dist/` are ignored. Biome has no equivalent of eslint-plugin-vue, so Vue-specific template rules are not linted. The a11y rules are on; the `noUnusedVariables` rule is off for `.vue` files because template-only bindings such as `ref="scroller"` look unused to Biome.

`.editorconfig` sets UTF-8, LF, a final newline, tabs for Go and the Makefile and two spaces elsewhere. `.gitattributes` normalises text to LF and marks `frontend/bindings` and the lockfile as generated.

## Image mirror

The `Dockerfile` pulls its base images from `mirror.gcr.io`, and nested podman is configured (`/etc/containers/registries.conf.d/10-mirror-gcr.conf`) to try `mirror.gcr.io` before `docker.io`, so the Trivy image does not hit Docker Hub's anonymous rate limit. If the mirror lacks an image or tag, podman falls back to Docker Hub. Remove that file inside the container to bypass the mirror.

## File ownership

The container user is `vscode` with `updateRemoteUserUID` on, so on Linux it takes your host uid and your clone stays writable (`node_modules`, `tmp/`, Go caches, podman storage all belong to you). `post-create.sh` also marks the workspace as a git `safe.directory` for setups where the owner still differs, and `.gitattributes` keeps `*.sh` on LF so a Windows clone still runs.

## What reloads

`make dev` (`scripts/dev.sh`) runs `wails3 dev -config ./build/config.yml`, which is Wails' own watcher (no `air`). The config builds and runs the app in **server mode** (`-tags server`, no GTK) instead of the desktop GUI that a plain `wails3 dev` would build, and starts Vite in the background:

| You edit | What happens |
|---|---|
| `frontend/src/**` (Vue, JS, CSS) | Vite HMR updates the browser, no restart |
| `*.go` (not tests) | `wails3 dev` rebuilds with `-tags server` (`build:server` in `Taskfile.yml`) and restarts the app; refresh the page |
| an exported `ScanService` method or type | also run `make bindings` and commit `frontend/bindings` |

The Go app proxies the page to Vite (`FRONTEND_DEVSERVER_URL`, set by `wails3 dev`, dev builds only), so the embedded `frontend/dist` is not used while developing. `WAILS_SERVER_PORT` (default 8080) and `WAILS_VITE_PORT` (default 9245) change the ports.

## Real scans or demo data

The container runs rootless **podman inside itself**, and the app starts Trivy with it, like a local `go run .`. That is why `devcontainer.json` sets `"privileged": true`, and why podman's storage is a named volume (`trivy-scanner-podman-storage`): rebuilding the dev container keeps the pulled Trivy image. Trivy's DB cache is in `~/.cache/trivy-scanner` inside the container.

Check it with `podman run --rm docker.io/library/alpine echo ok`. If podman cannot run here, `make dev` says so and uses the recorded demo data (`TRIVY_SCANNER_FAKE_PODMAN=1`, never in production builds).

Alternative on a Linux host with rootless podman: reuse the host's podman and image cache instead.

```sh
systemctl --user enable --now podman.socket          # on the host
```

then in `devcontainer.json` add the mount `source=${localEnv:XDG_RUNTIME_DIR}/podman/podman.sock,target=/run/podman/podman.sock,type=bind`, set `CONTAINER_HOST=unix:///run/podman/podman.sock` in `containerEnv`, and install `podman-remote` in place of `podman`. You can then drop `privileged`.

## Checks

The container is headless only: `CGO_ENABLED=0` and `GOFLAGS=-tags=server` are set, so plain `go build`, `go test`, `go vet` and `go run .` all work without GTK, and `make vet` uses `VET_TAGS=server,production`. `make test` runs without `-race` (it needs cgo, hence GTK); CI still uses it.

`make check` (gofmt, `go mod tidy -diff`, vet, race tests, headless build) works in the container. The desktop GUI build is not supported here; `wails3 dev` works because `build/config.yml` builds server mode.

## Troubleshooting

- *"unable to connect to frontend server"*: Vite is not up; run `make dev` rather than starting the app by hand.
- *"The connection was reset" on localhost:8080* (Zed, Docker-published ports): the app must not bind only to the container's loopback. `devcontainer.json` sets `WAILS_SERVER_HOST=0.0.0.0` for that; rebuild the container if yours predates it, or run `WAILS_SERVER_HOST=0.0.0.0 make dev`.
- *Port in use*: `WAILS_SERVER_PORT=9090 make dev`.
- Going through a forwarded URL other than `localhost` (Codespaces web URL) can trip Wails' loopback `Host` check; use the editor's local port forward instead.
- *Podman storage errors* (overlay on an unsupported filesystem, common on Docker Desktop): `printf '[storage]\ndriver = "vfs"\n' > ~/.config/containers/storage.conf` (slower, always works), then `podman system reset`.
