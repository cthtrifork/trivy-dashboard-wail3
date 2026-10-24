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
- **Never wait for CI** after opening a PR unless asked. Open it, report, stop.
- **Work in a new branch from `main` and open a PR** for every change. Do not push to `main`.
- **Be honest about verification.** Say what you ran, and list what you could not test (see `docs/principles.md`).
- Final answers to the user are in English.
- Wails `application.New` must be called before `initUpdater`, which runs before `app.Run` (self-update tutorial order).
- The Trivy scanner container is named `trivy-scanner-<random>` so cancel can `podman rm --force --ignore --time 0` it by name before signalling the client.
- Pin GitHub Actions by commit SHA with a version comment, as the existing workflows do.

## Layout

| Path | What |
|---|---|
| `main.go`, `service.go` | App wiring; `ScanService` is the Wails binding the frontend calls |
| `engine_dev.go` / `engine_prod.go` | Engine selection: real podman, or fixtures in dev builds |
| `update*.go`, `internal/selfupdate` | In-app updater (release builds only) |
| `headless_*.go` | `headless` const (true with `-tags server`) |
| `internal/trivy` | Engine, scanner, EPSS/KEV enrichment, priority rules, compare, VEX/OpenVEX |
| `internal/trivy/fixtures` | Recorded Trivy output used by tests and screenshots |
| `frontend/` | Plain JS/HTML/CSS, no build step, embedded with `go:embed` |
| `Containerfile` | Podman-only server deployment, see `docs/headless.md` |
| `.github/workflows` | `ci`, `security`, `release`, `tag-release` |
| `scripts/` | release/version helpers and the screenshot driver |
