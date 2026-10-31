# Architecture

## Flow

```
frontend (Vue 3)     ──Wails bindings──►  ScanService (internal/app/service.go)
                                              │
                                   trivy.Scanner (internal/trivy/scanner.go)
                                   ├─ Engine ── PodmanEngine ──► podman run aquasec/trivy image …
                                   │         └─ FixtureEngine (dev builds + TRIVY_SCANNER_FAKE_PODMAN only)
                                   ├─ Enricher ── EPSS + CISA KEV (cached in the user cache dir)
                                   ├─ assess.go, rules.go ── rule engine: score, tier, attack-vector text; tunable Rules (docs/scoring.md)
                                   ├─ compare.go ── diff two scans (vulns and packages)
                                   └─ vex.go ── VEXStore (JSON file) + OpenVEX export
```

## Frontend

`frontend/` is a Vue 3 + Vite app. `src/App.vue` is the shell (scan form, tabs, status); each tab is a component in `src/components/`. `src/store.js` holds the shared state (the scan result, saved VEX assessments, options) and the log/status plumbing. The UI calls the Go `ScanService` through generated bindings in `frontend/bindings` (`wails3 generate bindings`, run it via `make bindings`), and listens for `scan:log` events with `@wailsio/runtime`. The VEX assess form is one `VexDrawer.vue` dialog mounted in `App.vue`; `VexBox.vue` is only the button that sets `assessing` in the store, and `src/lib/glance.js` turns a CVSS vector into the drawer's one-line headline and fact tiles. `src/lib/graph.js` is the canvas dependency graph; `src/lib/where.js` walks the requires-edges for the route from the image to a component (also used by Priorities) and for its blast radius, and the graph keeps the selected route bright. `npm run build` writes `frontend/dist`, which `main.go` embeds. `internal/app/assets.go` is the Wails `AssetOptions.Middleware` (Wails has no built-in compression or cache headers): gzip for text assets (headless server builds only; the native window gets plain bytes) and `Cache-Control` (immutable for the content-hashed `/assets/*`, `no-cache` for `index.html`). The CodeMirror editors (`JsonBox`, `CodeBox`) are async components mounted on a dialog's first open, so CodeMirror stays out of the first load.

### Large scans

Long lists never put every row in the DOM. `src/lib/virtual.js` (`useVirtualList`) renders only the rows near the scroll viewport, between two spacers; it measures the rows it has rendered (rows differ in height: wrapped text, an expanded detail) and assumes the average for the rest. It backs the Vulnerabilities, SBOM and Compare tables and the Priorities rows, so the DOM stays around a thousand nodes whether a scan has 30 or 6,000 findings. The tables use fixed column widths so scrolling never reflows them. The log keeps its last ~300 kB, and the dependency detail pane lists at most 100 entries per section. The scan result itself stays in memory as a shallow (non-reactive) object. The dependency graph is a canvas that draws at most 800 components (the highest-risk ones, or the neighbourhood of the selection), so its cost does not grow with the image; the search box is debounced and filters a per-scan index of precomputed search text and severity weights. Measured on a synthetic graph: 100,000 components kept 61 fps and about 66 MB of heap, with about 35 ms per keystroke. What does grow is the scan payload, because the Go side sends every component (about 45 MB at 100,000). To re-measure, amplify the demo response in Playwright (route `/wails/runtime`) and compare `document.querySelectorAll('*').length` and the JS heap before and after.

## Build modes (tags)

| Build | Command | Notes |
|---|---|---|
| Desktop dev | `go run .` / `wails3 dev` | Real podman; fixtures available with `TRIVY_SCANNER_FAKE_PODMAN=1` |
| Desktop release | `go build -tags production` | GTK4 + WebKitGTK 6; updater on; no fixtures |
| Server (headless) | `-tags server` (+ `production`) | No window, HTTP on `WAILS_SERVER_HOST:PORT` (default `localhost:8080`); `headless=true` disables the updater; OpenVEX save falls back to a browser download |

Linux desktop builds add a tray icon (`internal/app/tray_linux.go`, art in `internal/app/tray_icon.png`, same as `frontend/public/favicon.svg`; StatusNotifier; GNOME needs the AppIndicator extension). Click or "Show Trivy Scanner" raises the window, "Quit" quits. Closing the window still quits, so a scan is never left running unseen. Other platforms and server mode compile `tray_other.go`, a no-op. The window icon is set through Wails' documented `Icon` options (`app.WindowIcon` in `main.go`).

Build with `CGO_ENABLED=0` for server mode to avoid GTK.

## Podman engine

- Runs `podman run --rm --name trivy-scanner-<random> -v <cache source>:/root/.cache/trivy <trivy image> image --cache-dir /root/.cache/trivy …`; the cache survives between scans. The vulnerability scan also passes `--list-all-pkgs`.
- Cancel: `podman rm --force --ignore --time 0 <name>`, then SIGTERM the client.
- Tags: `podman search --list-tags <repo qualified to docker.io>`.
- Env overrides: `PODMAN` (binary), `CONTAINER_HOST` (remote socket, used by the container deployment), `TRIVY_SCANNER_VEX_FILE`, `TRIVY_SCANNER_EPSS_URL`, `TRIVY_SCANNER_KEV_URL`, `XDG_CACHE_HOME`.

## Trivy cache

The footer shows a small footprint note (`ScanService.Footprint`): the disk size of the Trivy cache. It is hidden when podman is remote, since the cache is then on another host. The KEV catalog is a few hundred KB, too small to be worth a figure. A podman volume cannot be measured by the app, so it is named instead. Demo mode reports zero so the screenshots stay identical between PRs.

The scanner always gets an explicit `--cache-dir /root/.cache/trivy`, backed by a mount whose source is `TRIVY_SCANNER_CACHE`:

| Value | Meaning | Works with |
|---|---|---|
| unset, local podman | `<user cache dir>/trivy-scanner/trivy` on the host (Linux `~/.cache/trivy-scanner/trivy`, macOS `~/Library/Caches/trivy-scanner/trivy`), created if missing, mounted with `label=disable` for SELinux | Linux, macOS (podman machine shares the home directory) |
| unset, remote podman (`CONTAINER_HOST`/`DOCKER_HOST` set, as in the containerised headless deployment) or Windows | podman named volume `trivy-cache`, which lives wherever podman runs | any |
| `my-volume` | another named volume | any |
| `/abs/path` | a directory **on the machine running podman**; with a remote socket it must already exist (the app cannot create it) | local podman; remote with an existing path |

Relative paths and `:` are rejected, because podman would silently treat `./cache` as a volume name. The host directory is the default only when podman is local: if the app itself runs in a container, its own paths mean nothing to the podman host, so the volume is used there. Upgrading from the volume default re-downloads the Trivy DB once. Set `TRIVY_SCANNER_CACHE=trivy-cache` to keep using the old volume.

### Trivy version

The default image is the `pinnedTrivyImage` constant in [`internal/trivy/engine.go`](../internal/trivy/engine.go): a tag plus the digest it had when it was reviewed (`docker.io/aquasec/trivy:0.76.1@sha256:…`), so a tag that is re-pushed or hijacked does not change what runs. `DefaultTrivyImage` is the same reference without the digest, which is what the UI shows. A `// renovate: datasource=docker depName=docker.io/aquasec/trivy` comment above the constant lets the generic custom manager in `.github/renovate.json5` open a PR when a newer tag exists, moving tag and digest together; a digest-only change (same tag, new content) is never automerged. `ResolveTrivyImage` adds the digest back whenever the requested version is the pinned one. Any other version picked in the UI is a plain tag: the picker lists what the registry offers, so those cannot be pinned ahead of time. The vulnerability DB (`trivy-db:2`) is not pinned: see decision 20. **Options → Trivy version** is a tag combobox (`TagInput`) that lists the tags of that repository through `ScanService.ListTags`. Its default is the newest plain version found there (the frontend takes the first plain `X.Y.Z` tag; `latest` is never used), and the pinned constant is only the fallback when the lookup fails.

Override it per run in the UI: **Options → Trivy version** (the field starts with the version of the last successful scan, else the pinned default, and switches to the newest version found once the tag lookup works, unless you choose one; the last-used fallback keeps an offline start on an image podman already has; the field is remembered by the browser/webview). It takes a version (`0.77.0` / `v0.77.0`, meaning `docker.io/aquasec/trivy:0.77.0`); the repository cannot be changed, and anything that is not a version is refused before anything runs. The value is sent with every scan and comparison as `trivyImage`. Changing it makes the next scan re-check the vulnerability DB for that version.

### Surviving a reload

The last scan survives a browser reload or a container restart. After a scan the frontend stores the image and the result in `localStorage` (a result over the quota is dropped) and writes `#image=<ref>` to the URL. On load the image comes from the hash, else from `localStorage`; the stored result is shown when it belongs to that image, and a hash naming a different image reruns the scan. The backend also writes the scan to `last-scan.json` beside the VEX file and reloads it at startup, so a restarted server still has the findings that VEX import/export and re-ranking match against (a new scan deletes it). Credentials are never stored. The hash is read at load only, so editing it in place does nothing until a reload.

### Ignore policy and ignore file

**Options → Sources → Ignore rules** lists the two rule sets with a rule count each, an upload button and an **Edit…** button that opens a large dialog (`IgnoreRulesDialog.vue`, one tab per rule set), like the VEX dialog. The Rego policy takes a [Rego ignore policy](https://trivy.dev/docs/latest/guide/configuration/filtering/#by-rego) (the example in the Trivy docs is a `package trivy` module that defines `ignore`). It can be typed, pasted or loaded from a `.rego` file; the text is remembered by the browser/webview and sent with every scan and comparison as `ignorePolicy`. Empty means none.

For the vulnerability scan only (not the SBOM, not the DB check) the engine starts the scanner container with `sh` as entrypoint, passes the policy in the `SCANNER_IGNORE_POLICY` environment variable, writes it to `/tmp/ignore.rego` inside the container and then `exec`s `trivy ... --ignore-policy /tmp/ignore.rego`. A bind mount would need the file on the podman host, which breaks with a remote podman; the variable works with both, and keeps the policy off the process command line. The policy is limited to 24 KiB. Rego syntax errors are reported by Trivy and appear in the scan log and status line. Findings the policy ignores are simply absent from the report, so they do not show up in the app at all. Demo mode (recorded scans) does not evaluate policies.

The **ignore file** is a separate option for Trivy's [`.trivyignore.yaml`](https://trivy.dev/docs/latest/configuration/filtering/#trivyignoreyaml) (`vulnerabilities:` with an `id` and optional `statement` per entry). It is typed, pasted or loaded the same way, sent as `ignoreFile`, and delivered like the policy: `SCANNER_IGNORE_FILE` is written to `/tmp/ignorefile.yaml` and passed as `--ignorefile`. The two can be used together or alone; each is limited to 24 KiB. Both fields get a quick sanity check while you type (`ScanService.CheckIgnorePolicy` / `CheckIgnoreFile`, `internal/trivy/ignore.go`), and the same check rejects a scan before Trivy starts. The ignore file must be YAML with only Trivy's sections (`vulnerabilities`, `misconfigurations`, `secrets`, `licenses`) and an `id` on every entry; the policy must be `package trivy`, since another package silently ignores nothing. Rego itself is not parsed here (no small library does that; OPA's would be a large dependency): Trivy reports Rego syntax errors in the scan error. Only the YAML format is supported (the file name Trivy sees ends in `.yaml`).

### Vulnerability DB

Before the first scan of a session (and only then) the scanner runs `trivy image --download-db-only` (no image, no registry credentials) against the cache. Trivy only downloads when its DB is past `NextUpdate`, so this is cheap when the cache is fresh, and a stale cache is refreshed on the first scan after startup. Changing the Trivy version does not check again. **Options → Scanner → Update database** (`ScanService.UpdateDB`) runs the same check again on demand; Trivy still downloads only when the cached DB is out of date, and a failure keeps the cached copy. The status line says whether a download happened; that is read from Trivy's output ("Downloading vulnerability DB..." in a log line, checked against Trivy 0.76.1), so if the wording changes it reports that no new database was downloaded. The DB repository is `DefaultDBRepository` (`ghcr.io/aquasecurity/trivy-db:2`, a `// renovate:` comment tracks it; the tag is the DB schema version, so it rarely changes. It is a floating tag on purpose, see decision 20), passed as `TRIVY_DB_REPOSITORY` unless that variable is set in the app's environment. The scans themselves then run with `--skip-db-update`, so a Compare (four scans) checks once instead of four times. If the check fails (offline, rate limited) it logs a warning and the scans use whatever is cached; with an empty cache the scan fails with Trivy's own error, followed by the download error that caused it. A failed check is retried on the next scan. `TRIVY_DB_REPOSITORY` (replacing the default above) and `TRIVY_JAVA_DB_REPOSITORY`, when set in the app's environment, are forwarded to Trivy for mirrors. `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` are forwarded too, a loopback proxy also gives the container the host network, and `TRIVY_SCANNER_CA_BUNDLE` (an absolute path on the podman host) is mounted as the container's CA bundle for TLS-inspecting proxies. The Java DB is not pre-fetched: Trivy downloads it into the same cache only when an image contains JARs.

## Server mode security

Wails rejects requests with a non-loopback `Host` header when bound to loopback (DNS-rebinding guard). Binding `0.0.0.0` is treated as a deliberate network deployment and is unguarded, hence principle 10. Events travel over a WebSocket at `/wails/events`.

## Lifecycle

`ServiceStartup` stores the app context and wires the log emitter; every scan derives from it. `ServiceShutdown` cancels and waits up to one second for the container to be removed. Details: [lifecycle.md](lifecycle.md).

## Release and CI

`ci.yml` (PRs and main), `security.yml` (govulncheck + Trivy fs), `tag-release.yml` (picks the version, releases the head of `main`; the tag is created when the release is published), `release.yml` (build, checksums, attestation, GitHub release). See [ci.md](ci.md), [releasing.md](releasing.md), [self-update.md](self-update.md).

## Deployment without Go

[`build/docker/headless.Dockerfile`](../build/docker/headless.Dockerfile) builds the server binary inside podman; at runtime the container uses `podman-remote` against the host socket. See [headless.md](headless.md).
