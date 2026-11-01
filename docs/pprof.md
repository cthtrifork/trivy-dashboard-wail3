# Profiling (pprof)

Go's `net/http/pprof` endpoint, for finding CPU and allocation hot spots in a **running** app. It is a development aid. This repo never ships it.

## Turning it on

Compiled in only with the `pprof` build tag; it starts when the process starts.

```sh
make run-pprof-server          # headless: CGO_ENABLED=0 go run -tags server,pprof .
go run -tags pprof .           # desktop build (needs GTK4 + WebKitGTK 6)
```

The log prints `pprof endpoint started url=http://127.0.0.1:6060/debug/pprof/`. Set `TRIVY_SCANNER_PPROF_ADDR` for another loopback address or port (`127.0.0.1:0` picks a free port).

## Using it

Start a CPU profile, then do the flow you want to measure (scan, compare, scan a new image). Only one CPU profile can run at a time, and the capture always lasts the full `seconds`:

```sh
curl -s 'localhost:6060/debug/pprof/profile?seconds=60' -o cpu.pprof &
# ...click through the flow...
go tool pprof -top -cum -nodecount=25 cpu.pprof
curl -s localhost:6060/debug/pprof/allocs -o allocs.pprof
go tool pprof -sample_index=alloc_space -top allocs.pprof
```

A scan spends its time inside the Trivy container, so the app's own CPU is a small share of the wall time; expect mostly JSON decoding, version parsing and the per-finding assessment. Use the heap and `allocs` profiles for memory.

## Real scans in the dev container

The sandbox has no podman, so build and run the app in the dev container ([`devcontainer.md`](devcontainer.md), [`agent-runbook.md`](agent-runbook.md), "Dev container"). It shares the host network, so the endpoint is reachable from the host as well:

```sh
devcontainer exec --workspace-folder . make frontend
devcontainer exec --workspace-folder . bash -c 'CGO_ENABLED=0 go build -tags server,pprof -o /tmp/app-pprof . && WAILS_SERVER_PORT=18080 WAILS_SERVER_HOST=127.0.0.1 /tmp/app-pprof'
```

Run one throwaway scan first: it pulls the Trivy image and the vulnerability DB, which would otherwise dominate the profile. Then drive the UI with Playwright (as `scripts/screenshots.mjs` does) while a profile is recording. Use `mirror.gcr.io/library/<image>` names in the sandbox. After a scan the image field splits into repository and tag; press the *Clear* button to type a new image.

## Security

Anyone who can reach the port can read goroutine stacks, heap contents and the command line, and can make the process burn CPU.

- Binds to loopback only. A non-loopback `TRIVY_SCANNER_PPROF_ADDR` aborts start-up (principle 10).
- **Never in releases.** `internal/app/pprof_guard.go` makes `-tags pprof,production` fail to compile, and CI greps the production binary for the start-up message (`Production build contains no pprof endpoint`).
- Not in the container image: `build/docker/headless.Dockerfile` builds with `server,production`.
