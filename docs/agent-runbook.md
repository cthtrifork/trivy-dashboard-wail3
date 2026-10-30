# Agent runbook

Practical notes for working in the cloud sandbox this repo has mostly been developed in. Check each against the current environment; they were true when written.

## Opening a PR

`gh pr create` uses GraphQL, which the sandbox proxy blocks. Use REST:

```sh
git push -u origin claude/<topic>
git remote set-branches --add origin claude/<topic>; git fetch --depth=1 origin claude/<topic>   # shallow clone: give the stop hook a tracking ref
gh api repos/cthtrifork/trivy-dashboard-wail3/pulls -f title='…' -f head=claude/<topic> -f base=main -f body='…' --jq .html_url
```

The PR title follows `type(scope)!: summary` (`docs/releasing.md`, *Release notes*); `scripts/pr-title.sh check "<title>"` validates one, and the *PR title* workflow labels the PR from it.

Commit messages and PR bodies end with the attribution lines from the session's system reminder. Follow `.github/pull_request_template.md`.

## Sandbox quirks

- **Tags cannot be created** from the sandbox (proxy). Use the *Tag and release* workflow instead.
- **Docker Hub anonymous rate limit**: pull through `mirror.gcr.io` (`mirror.gcr.io/library/alpine`). Configure it as a podman registry mirror if you need `docker.io/...` names to work.
- **Reachable**: proxy.golang.org, npm, mirror.gcr.io. **Not reachable** (last checked): Alpine/Debian mirrors, quay.io, ghcr.io pulls, so the Trivy DB cannot be downloaded and `podman-remote` cannot be `apk add`ed.
- **Build inside podman** needs `--network host` plus the sandbox CA (`-v /root/.ccr/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro --build-arg HTTPS_PROXY=$HTTPS_PROXY`), because the proxy listens on 127.0.0.1.
- **No GTK**: the GUI build is not possible; test with `-tags server` and `CGO_ENABLED=0`. A warm Go build cache can hide a missing-GTK failure, so test with an empty `GOCACHE`.
- **Never `pkill -f <pattern>`**: it matches your own shell. Kill by PID or `pkill -x`.
- Running containers as root in the sandbox prints harmless `can't raise ambient capability` warnings.
- Podman API for tests: `podman system service --time 0 unix:///run/podman/podman.sock &`.

## Dev container

The sandbox has the Docker CLI but no daemon, no `wails3` and no podman. The dev container (`.devcontainer/`, see `docs/devcontainer.md`) has all of them plus Go, Node and rootless podman, so use it for `make bindings`, real scans and anything else that needs those. Checked end to end: `wails3 version` works, `make bindings` leaves `frontend/bindings` unchanged, and real scans run.

```sh
dockerd >/tmp/dockerd.log 2>&1 &                    # no daemon by default; wait until `docker info` answers
npm i -g @devcontainers/cli                         # once
devcontainer up --workspace-folder .                # builds the image, runs post-create.sh (npm ci, wails3)
devcontainer exec --workspace-folder . make bindings
```

The sandbox needs two adjustments (neither belongs in the committed config):

- **File ownership.** You are root, so `updateRemoteUserUID` does not remap the `vscode` user and `npm ci` fails with `EACCES` on the workspace. `chown -R 1000:1000 .` before `devcontainer up`, and `chown -R root:root .` when you are done (git also reports "dubious ownership" for the host while it is owned by 1000, which is harmless).
- **The egress proxy.** The proxy listens on 127.0.0.1 and re-signs TLS, so the container needs host networking, the proxy variable and the CA bundle. Pass a throwaway override config (outside the repo, `--override-config <dir>/devcontainer.json`) that copies `.devcontainer/devcontainer.json` and adds `"runArgs": ["--network", "host"]`, the mount `source=/root/.ccr/ca-bundle.crt,target=/etc/ssl/certs/ca-certificates.crt,type=bind,readonly`, and `HTTPS_PROXY`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` in `containerEnv`. The override file must be named `devcontainer.json`, and `build.dockerfile`/`build.context` become absolute paths.

### Real scans in the container

The app forwards `HTTPS_PROXY`/`NO_PROXY` into the Trivy container (and uses the host network for a loopback proxy), and `TRIVY_SCANNER_CA_BUNDLE` mounts a CA bundle, so with the override config above a scan only needs the bundle named:

```sh
export TRIVY_SCANNER_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt PODMAN_IGNORE_CGROUPSV1_WARNING=1
```

`mirror.gcr.io/library/<image>` names scan fine (the DB comes from `mirror.gcr.io/aquasec/trivy-db:2`). A failed DB download now shows up in the scan error. If podman says "current system boot ID differs from cached boot ID" after restarting dockerd, delete `/tmp/storage-run-1000/containers` and `/tmp/storage-run-1000/libpod/tmp` in the container (or recreate it).

Earlier scans (before the proxy passthrough) were verified with `alpine:3.18` (0 findings), `nginx:1.25` (810) and `python:3.9-slim` (468).

## Exercising the app headlessly

```sh
make build-server OUT=/tmp/app
TRIVY_SCANNER_FAKE_PODMAN=1 TRIVY_SCANNER_VEX_FILE=/tmp/vex.json WAILS_SERVER_PORT=18080 /tmp/app &
curl -s -o /dev/null -w '%{http_code}\n' localhost:18080/                      # 200
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' localhost:18080/   # 403
```

Build the frontend before the headless build above (`make frontend`; `make build-server` does it for you); the server embeds `frontend/dist`. For hot reload run `make dev-frontend` and start the app with `FRONTEND_DEVSERVER_URL=http://127.0.0.1:9245`.

For UI work, `scripts/screenshots.sh` drives the real frontend with Playwright (Chromium is preinstalled; do not reinstall Playwright).

## Gotchas from earlier sessions

- Test doubles that close a channel twice panic; guard with `sync.Once`.
- When splicing code with scripts, check for stray braces; prefer the Edit tool.
- The three real-data fixture sets are `traefik_3.7.13.json`, `traefik_3.7.16.json`, and the SBOM `trivy_3.7.16.sbom.json` (plus `traefik_3.7.13.sbom.json`); see `internal/trivy/fixtures/README.md`.

## Picking up a session

1. `git fetch origin main && git checkout -b claude/<topic> origin/main`
2. Read `AGENTS.md`.
3. Make the change, run the checklist in `docs/principles.md`.
4. Open the PR, listing verified and unverified items in its body, then stop.
