# Agent runbook

Practical notes for working in the cloud sandbox this repo has mostly been developed in. Check each against the current environment; they were true when written.

## Opening a PR

`gh pr create` uses GraphQL, which the sandbox proxy blocks. Use REST:

```sh
git push -u origin claude/<topic>
git remote set-branches --add origin claude/<topic>; git fetch --depth=1 origin claude/<topic>   # shallow clone: give the stop hook a tracking ref
gh api repos/cthtrifork/trivy-dashboard-wail3/pulls -f title='…' -f head=claude/<topic> -f base=main -f body='…' --jq .html_url
```

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

## Exercising the app headlessly

```sh
CGO_ENABLED=0 go build -tags server -o /tmp/app .
TRIVY_SCANNER_FAKE_PODMAN=1 TRIVY_SCANNER_VEX_FILE=/tmp/vex.json WAILS_SERVER_PORT=18080 /tmp/app &
curl -s -o /dev/null -w '%{http_code}\n' localhost:18080/                      # 200
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' localhost:18080/   # 403
```

For UI work, `scripts/screenshots.sh` drives the real frontend with Playwright (Chromium is preinstalled; do not reinstall Playwright).

## Gotchas from earlier sessions

- Test doubles that close a channel twice panic; guard with `sync.Once`.
- When splicing code with scripts, check for stray braces; prefer the Edit tool.
- The three real-data fixture sets are `traefik_3.7.13.json`, `traefik_3.7.16.json`, and the SBOM `trivy_3.7.16.sbom.json` (plus `traefik_3.7.13.sbom.json`); see `internal/trivy/fixtures/README.md`.

## Picking up a session

1. `git fetch origin main && git checkout -b claude/<topic> origin/main`
2. Read `AGENTS.md`, then `docs/status.md` for open items.
3. Make the change, run the checklist in `docs/principles.md`.
4. Update `docs/status.md` (move items, add unverified ones), open the PR, stop.
