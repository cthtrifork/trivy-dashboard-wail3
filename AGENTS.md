# AGENTS.md

Start here. This file is for AI coding agents (and humans) picking up work on **Trivy Scanner**, a Go + Wails v3 app that scans container images with Trivy running in podman.

Read in this order, stopping when you have enough:

1. This file: commands, rules, gotchas.
2. [`docs/principles.md`](docs/principles.md): the standing rules and preferences for this repo.
3. [`docs/architecture.md`](docs/architecture.md): how the code is laid out and why.
4. [`docs/agent-runbook.md`](docs/agent-runbook.md): sandbox quirks, PR recipe, verification checklist.
5. [`docs/decisions.md`](docs/decisions.md): why things are the way they are (do not re-litigate without new facts).

## Commands

`make help` lists shortcuts (`make check` runs the GTK-free CI checks; `make headless*` manages the podman deployment). The commands below are the Makefile targets; the `Makefile` has the underlying invocations.

```sh
make frontend                                      # Vue app -> frontend/dist; required before any build/run, not before vet/test
make format                                        # gofmt plus Biome for the Vue app (make fmt / format-frontend run one each)
make test                                          # what CI runs (go test -race -count=1 ./...); recorded fixtures, no podman needed
make vet                                           # go vet, with and without -tags production
make build-server                                  # headless build (CGO_ENABLED=0, -tags server,production), no GTK
make run-mcp                                       # desktop app with Wails' MCP server on 127.0.0.1:9099 (dev only, docs/mcp.md); run-mcp-server is the headless variant
make demo                                          # demo mode on recorded data (dev builds only)
make screenshots                                   # renders into the gitignored docs/screenshots (needs Node + Playwright); never commit them
```

The GUI build links GTK4/WebKitGTK 6 and usually cannot be built in a sandbox. Use the `server` tag with `CGO_ENABLED=0` there; without `CGO_ENABLED=0` you get `pkg-config: Package gtk4 was not found`.

## Rules that are easy to get wrong

- **Real podman by default.** Fake data exists only for Go tests and screenshots, behind `TRIVY_SCANNER_FAKE_PODMAN=1`, and only in builds *without* `-tags production`. Never make fixtures reachable from a production build; CI checks the binary for demo code.
- **Never try to build or run the GTK GUI.** Do not run a plain `go build`/`go run`, `wails3 build`/`dev`, or install GTK4/WebKitGTK; it fails in the sandbox and wastes time. Always use `CGO_ENABLED=0` with `-tags server` (add `production` to check the release shape), and exercise the UI through the headless server (see `docs/agent-runbook.md`). Mention in the PR that the GUI path was not tested.
- **Use the dev container for anything that needs `wails3`, podman or real scans.** The sandbox has Docker but no `wails3` CLI and no podman. Bring the container up and run commands in it (`docs/agent-runbook.md`, "Dev container"): `devcontainer up --workspace-folder .` then `devcontainer exec --workspace-folder . make bindings`. Run `make bindings` there after changing an exported `ScanService` method or type, and never hand-edit `frontend/bindings`.
- **Always open a PR** for every change, without being asked, from a new branch off `main`. Do not push to `main`. If the session names a branch to develop on, use it, but still open the PR.
- **Do not watch CI or subscribe to PR activity** after opening a PR unless the user says to. Open it, report the link and what you verified, stop.
- **Be honest about verification.** Say what you ran, and list what you could not test (see `docs/principles.md`).
- Final answers to the user are in English.
- **Wails' MCP server (`-tags mcp`) is development only** (`docs/mcp.md`). `internal/app/mcp_guard.go` rejects `mcp` + `production`, and CI checks the release binary. In headless mode only `app_info`, `windows_list` and `emit_event` work (no webview), so the DOM, input and `call_bound_method` tools need the desktop build; say in the PR if you could not test that.
- Wails `application.New` must be called before `initUpdater`, which runs before `app.Run` (self-update tutorial order).
- The Trivy scanner container is named `trivy-scanner-<random>` so cancel can `podman rm --force --ignore --time 0` it by name before signalling the client.
- Pin GitHub Actions by commit SHA with a version comment, as the existing workflows do.

- **Run the frontend lint before every push that touches `frontend/src`:** `make format-frontend lint-frontend`. CI's `lint` job fails on unformatted Vue/JS/CSS and skips test/build/vet behind it.
- **Frontend is Vue 3 + Vite** (decision 14). After changing an exported `ScanService` method or a type it exchanges, run `make bindings` (needs the `wails3` CLI) and commit `frontend/bindings`. `frontend/dist` is untracked build output except `.gitkeep`.

## Layout

| Path | What |
|---|---|
| `main.go` | Thin entry point: creates the Wails app and window, embeds `frontend/dist` |
| `internal/app` | The app itself: `ScanService` (the Wails binding the frontend calls, `service.go`), config, tray, updater, version stamp |
| `internal/app/engine_dev.go` / `engine_prod.go` | Engine selection: real podman, or fixtures in dev builds |
| `internal/app/update*.go`, `internal/selfupdate` | In-app updater (release builds only) |
| `internal/app/headless_*.go` | `headless` const (true with `-tags server`) |
| `internal/trivy` | Engine, scanner, EPSS/KEV enrichment, priority rules, compare, VEX/OpenVEX |
| `internal/trivy/fixtures` | Recorded Trivy output used by tests and screenshots |
| `frontend/` | Vue 3 + Vite app (`src/`), generated Wails bindings (`bindings/`, committed); `dist/` is build output embedded with `go:embed` |
| `Taskfile.yml`, `build/config.yml`, `.devcontainer/`, `scripts/dev.sh` | `wails3 dev` config (server mode), dev container and the `make dev` hot-reload loop, see `docs/devcontainer.md` |
| `internal/app/mcp_guard.go`, `.mcp.json` | Compile error for `mcp`+`production`; project MCP client entry for `make run-mcp` |
| `build/docker/headless.Dockerfile` | Podman-only server deployment, see `docs/headless.md` |
| `.github/workflows` | `ci`, `security`, `release`, `tag-release` |
| `scripts/` | release/version helpers and the screenshot driver |
