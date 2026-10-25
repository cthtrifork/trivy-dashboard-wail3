# AGENTS.md

Start here. This file is for AI coding agents (and humans) picking up work on **Trivy Scanner**, a Go + Wails v3 app that scans container images with Trivy running in podman.

Read in this order, stopping when you have enough:

1. This file: commands, rules, gotchas.
2. [`docs/principles.md`](docs/principles.md): the standing rules and preferences for this repo.
3. [`docs/architecture.md`](docs/architecture.md): how the code is laid out and why.
4. [`docs/agent-runbook.md`](docs/agent-runbook.md): sandbox quirks, PR recipe, verification checklist.
5. [`docs/decisions.md`](docs/decisions.md): why things are the way they are (do not re-litigate without new facts).

## Commands

`make help` lists shortcuts (`make check` runs the GTK-free CI checks; `make headless*` manages the podman deployment). Underlying commands:

```sh
(cd frontend && npm ci && npm run build)           # Vue app -> frontend/dist; required before any `go build`/`go run`, not before vet/test
go test -race -count=1 ./...                       # what CI runs; replays recorded fixtures, no podman needed
go vet ./... && go vet -tags production ./...
gofmt -l .                                         # must print nothing
go mod tidy -diff                                  # must print nothing
CGO_ENABLED=0 go build -tags server,production -trimpath -o trivy-scanner .   # headless build, no GTK
TRIVY_SCANNER_FAKE_PODMAN=1 go run .               # demo mode on recorded data (dev builds only)
scripts/screenshots.sh                             # rewrites docs/screenshots (needs Node + Playwright)
```

The GUI build links GTK4/WebKitGTK 6 and usually cannot be built in a sandbox. Use the `server` tag with `CGO_ENABLED=0` there; without `CGO_ENABLED=0` you get `pkg-config: Package gtk4 was not found`.

## Rules that are easy to get wrong

- **Real podman by default.** Fake data exists only for Go tests and screenshots, behind `TRIVY_SCANNER_FAKE_PODMAN=1`, and only in builds *without* `-tags production`. Never make fixtures reachable from a production build; CI checks the binary for demo code.
- **Always open a PR** for every change, without being asked, from a new branch off `main`. Do not push to `main`. If the session names a branch to develop on, use it, but still open the PR.
- **Do not watch CI or subscribe to PR activity** after opening a PR unless the user says to. Open it, report the link and what you verified, stop.
- **Be honest about verification.** Say what you ran, and list what you could not test (see `docs/principles.md`).
- Final answers to the user are in English.
- Wails `application.New` must be called before `initUpdater`, which runs before `app.Run` (self-update tutorial order).
- The Trivy scanner container is named `trivy-scanner-<random>` so cancel can `podman rm --force --ignore --time 0` it by name before signalling the client.
- Pin GitHub Actions by commit SHA with a version comment, as the existing workflows do.

- **Frontend is Vue 3 + Vite** (decision 14). After changing an exported `ScanService` method or a type it exchanges, run `make bindings` (needs the `wails3` CLI) and commit `frontend/bindings`. `frontend/dist` is untracked build output except `.gitkeep`.

## Layout

| Path | What |
|---|---|
| `main.go`, `service.go` | App wiring; `ScanService` is the Wails binding the frontend calls |
| `engine_dev.go` / `engine_prod.go` | Engine selection: real podman, or fixtures in dev builds |
| `update*.go`, `internal/selfupdate` | In-app updater (release builds only) |
| `headless_*.go` | `headless` const (true with `-tags server`) |
| `internal/trivy` | Engine, scanner, EPSS/KEV enrichment, priority rules, compare, VEX/OpenVEX |
| `internal/trivy/fixtures` | Recorded Trivy output used by tests and screenshots |
| `frontend/` | Vue 3 + Vite app (`src/`), generated Wails bindings (`bindings/`, committed); `dist/` is build output embedded with `go:embed` |
| `.devcontainer/`, `.air.toml`, `scripts/dev.sh` | Dev container and the `make dev` hot-reload loop, see `docs/devcontainer.md` |
| `Containerfile` | Podman-only server deployment, see `docs/headless.md` |
| `.github/workflows` | `ci`, `security`, `release`, `tag-release` |
| `scripts/` | release/version helpers and the screenshot driver |
