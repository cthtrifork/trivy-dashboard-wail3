# Running on a headless server

Run Trivy Scanner on a server that has **podman but no Go toolchain**, and use it from your own machine's browser over SSH.

The app is built and served by podman. The scanner container (`aquasec/trivy`) still runs on the *server's* podman, so nothing but podman is needed on the server.

```
your machine                          server (podman only)
┌──────────────┐   ssh -L 8080      ┌───────────────────────────────────────────┐
│   browser    │ ─────────────────► │ trivy-scanner container (host network,    │
│ localhost:8080│                    │   listens on 127.0.0.1:8080)              │
└──────────────┘                    │        │ podman API socket                │
                                    │        ▼                                  │
                                    │ host podman ──► aquasec/trivy (per scan)  │
                                    └───────────────────────────────────────────┘
```

## Quick start: the published image

Every release publishes the image to `ghcr.io/cthtrifork/trivy-dashboard-wail3` (tags `latest`, `1.2.3`, `v1.2.3`). No clone or build needed:

```sh
# 1. Let the app talk to the server's podman through its API socket (rootless).
systemctl --user enable --now podman.socket
sudo loginctl enable-linger "$USER"

# 2. Run it (pin a version such as :1.2.3 instead of :latest for reproducible deployments).
podman run -d --name trivy-scanner --restart unless-stopped \
  --network host --security-opt label=disable --userns=keep-id \
  -v "$XDG_RUNTIME_DIR/podman/podman.sock:/run/podman/podman.sock" \
  -v trivy-scanner-data:/data \
  ghcr.io/cthtrifork/trivy-dashboard-wail3:latest
```

The release also attests the project's OpenVEX document (`vex/openvex.json`) to the image, so Trivy can use it: `trivy image --vex oci ghcr.io/cthtrifork/trivy-dashboard-wail3:latest`. The same document is also in the image at `/usr/share/doc/trivy-scanner/trivy-scanner.vex.json` and attached to each GitHub release as `trivy-scanner_<version>.vex.json`, for scanners that take a file (`grype <image> --vex trivy-scanner_<version>.vex.json`, `trivy image --vex <file>`). Scanners do not find the copy inside the image by themselves, and Docker Scout ignores an embedded VEX file when the image has any attestation (this image has provenance and SBOM attestations); for Scout use `docker scout cves <image> --vex-location <dir with the release's .vex.json>`. Product IDs in statements: `pkg:oci/...` for Trivy's `--vex oci`, `pkg:docker/...` for Scout. Verify the attestation with `gh attestation verify oci://ghcr.io/cthtrifork/trivy-dashboard-wail3:latest --repo cthtrifork/trivy-dashboard-wail3 --predicate-type https://openvex.dev/ns/v0.2.0`.

Then open the SSH tunnel as described below. To update: `podman pull ghcr.io/cthtrifork/trivy-dashboard-wail3:latest`, `podman rm -f trivy-scanner`, and repeat the `podman run`. If the package is private, `podman login ghcr.io` first with a token that has `read:packages`.

## One-time setup (build from source)

```sh
# 1. Let the app talk to the server's podman through its API socket (rootless).
systemctl --user enable --now podman.socket
# keep user services running after you log out
sudo loginctl enable-linger "$USER"

# 2. Get the code and build the image (Go runs inside the build, not on the host).
git clone https://github.com/cthtrifork/trivy-dashboard-wail3.git
cd trivy-dashboard-wail3
podman build -t trivy-scanner --build-arg VERSION="$(git describe --tags --always)" -f build/docker/headless.Dockerfile .

# 3. Run it.
podman run -d --name trivy-scanner --restart unless-stopped \
  --network host --security-opt label=disable --userns=keep-id \
  -v "$XDG_RUNTIME_DIR/podman/podman.sock:/run/podman/podman.sock" \
  -v trivy-scanner-data:/data \
  localhost/trivy-scanner
```

### GitHub token for ghcr.io

If `GITHUB_TOKEN` is set when you run `make headless` (or `make headless-up`), it is passed into the container (with `GITHUB_ACTOR`/`GITHUB_USER` as the login, default `github`). Scans of `ghcr.io/...` images then use it as the registry password when the Options fields are empty. The token is only sent to ghcr.io, never to other registries, and stays on the Go side: the UI shows a masked placeholder, not the value. Typed credentials always win. The same variables are forwarded into the dev container from your host environment.

Then, **from your machine**:

```sh
ssh -L 8080:localhost:8080 user@server
```

and open <http://localhost:8080>. Use another local port if 8080 is taken (`-L 9090:localhost:8080`).

## Shortcut: make

The same steps as a Makefile (needs `make`, `git` and podman on the server):

```sh
make headless          # enable the podman socket, build the image, (re)start the container, print the ssh command
make headless-update   # git pull origin main, rebuild, restart
make headless-status   # container state and whether it answers on localhost
make headless-logs     # follow the logs
make headless-down     # remove the container (data volume stays)
```

`PORT=9090 make headless-up` changes the listen port; `make help` lists every target.

## Updating to the latest `main`

```sh
cd trivy-dashboard-wail3
git pull origin main
podman build -t trivy-scanner --build-arg VERSION="$(git describe --tags --always)" -f build/docker/headless.Dockerfile .
podman rm -f trivy-scanner
# then repeat the `podman run` command above
```

VEX assessments (`/data/vex.json`) and the EPSS/KEV cache live in the `trivy-scanner-data` volume and survive this. The Trivy vulnerability database lives in `/tmp/trivy` on the server when you use `make headless-up` (change it with `make headless-up CACHE=/abs/path`; the Makefile creates the directory). Note `/tmp` may be cleared on reboot, which only costs one database re-download. With the manual `podman run` commands above the app uses podman's `trivy-cache` volume; to use a server directory instead, create it and add `-e TRIVY_SCANNER_CACHE=/abs/path/on/the/server`. The path is a server path, not a path inside the app container.

## Why it is set up this way

- **`--network host` + `WAILS_SERVER_HOST=127.0.0.1`** (the image default): the app listens only on the server's loopback, so it is reachable through the SSH tunnel and nowhere else. Wails also rejects requests whose `Host` header is not a loopback name on loopback binds (DNS-rebinding protection), so `localhost:<any port>` through the tunnel works.
- **No authentication.** Do not bind the app to `0.0.0.0` or publish the port (`-p`) unless something in front of it authenticates users. Anyone who can reach it can start scans and, through the mounted socket, run containers as your user.
- **The podman socket is mounted into the container.** That grants the app control of your (rootless) podman. The image runs as the `nonroot` user (uid 65532) of `cgr.dev/chainguard/static`, and `--userns=keep-id` makes rootless podman run it as your own uid instead, which is what lets it open the socket and write `/data`. Without `--userns=keep-id` the process cannot read the socket. With a rootful podman socket, pass `--user` with a uid/gid (e.g. `--group-add`) that may open it.
- **`--security-opt label=disable`** is needed on SELinux hosts (Fedora, RHEL) so the container may use the socket.
- **Self-update is disabled** in server mode; update by rebuilding as above.
- **OpenVEX export** has no native save dialog on a server, so the browser downloads the file instead.

## Without containers

If Go is installed, you can skip the image:

```sh
git pull origin main
make build-server
./trivy-scanner      # listens on localhost:8080
```

`CGO_ENABLED=0` avoids needing GTK headers on the server. `WAILS_SERVER_HOST` and `WAILS_SERVER_PORT` change the listen address.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Page shows "podman not found" / scans fail immediately | `systemctl --user status podman.socket`; check `ls $XDG_RUNTIME_DIR/podman/podman.sock`. Under plain `ssh` without a session, `XDG_RUNTIME_DIR` may be unset: use `/run/user/$(id -u)`. |
| `403` in the browser | You are not using `localhost`/`127.0.0.1` in the URL, or something rewrites the `Host` header. |
| `Address already in use` | Something else listens on 8080 on the server: set `-e WAILS_SERVER_PORT=8081` and tunnel to that. |
| Tunnel connects but the page does not load | `podman logs trivy-scanner`; confirm `--network host` was used. |
| Slow first scan | Trivy downloads its vulnerability database once into the cache (`/tmp/trivy` with `make`, else the `trivy-cache` volume). |

## What has been verified

Checked in a sandbox with podman 4.9.3 (root, no Go on the "server" side of the test):

- The image's build stage compiles the server binary inside podman with `CGO_ENABLED=0`.
- The binary, running in a container with `--network host`, listens on the host's loopback; `localhost` answers `200` and a foreign `Host` header gets `403`.
- Through the mounted API socket, the in-container podman client runs containers on the host's podman, finds them by `--name`, and removes them with `rm --force --ignore --time 0` (the scan cancel path).
- Data in `/data` survives removing and recreating the container.

**Not verified** (no way to test in the sandbox): rootless podman, SELinux, `loginctl enable-linger`/reboot behaviour, and a full scan end to end (Trivy's database registry was unreachable). The final image is `cgr.dev/chainguard/static` (no shell, no package manager) with upstream's static `podman-remote` (version pinned by `PODMAN_VERSION` in the Dockerfile, bumped by Renovate; it is downloaded over HTTPS from the GitHub release and checked against the SHA-256 pinned in the Dockerfile; Renovate updates the hashes with the version through `scripts/podman-checksums.sh`) installed as `podman`; if your podman server is much newer or older than that client, change `PODMAN_VERSION`. There is no shell in the image; for debugging use `podman logs`, or temporarily swap the base for a debuggable image such as `cgr.dev/chainguard/busybox`.
