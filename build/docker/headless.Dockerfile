# Trivy Scanner in server mode, for hosts that have podman but no Go toolchain.
# See docs/headless.md.
FROM mirror.gcr.io/library/node:26-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM mirror.gcr.io/library/golang:1.27-alpine AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY main.go ./
COPY internal ./internal
COPY --from=frontend /src/frontend/dist ./frontend/dist
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -tags server,production -trimpath -ldflags "-w -s -X github.com/cthtrifork/trivy-dashboard-wail3/internal/app.version=${VERSION}" -o /out/trivy-scanner .

# The app only needs the podman *client*: scans run on the host's podman through its API socket.
# Upstream's static podman-remote runs on a static base like Chainguard's (Alpine's is linked against musl). Keep
# PODMAN_VERSION close to the host's podman; Renovate bumps it.
FROM mirror.gcr.io/library/alpine:3.24 AS podman
# renovate: datasource=github-releases depName=containers/podman
ARG PODMAN_VERSION=v6.1.4
# SHA-256 of the release tarballs for PODMAN_VERSION. Renovate rewrites them with the version
# (postUpgradeTasks in .github/renovate.json5 runs scripts/podman-checksums.sh); to do it by hand,
# run that script. A mismatch fails the build instead of shipping an unchecked binary.
ARG PODMAN_SHA256_amd64=af1f85c22214088a0a9986b9c82b4c9b5b74eda8ecaa6c8cca82b1a63f339b4a
ARG PODMAN_SHA256_arm64=1d7c2a3241b56effa68c724359fb30e603a802699b2b7b20fe2fae5ff6819601
ARG TARGETARCH
RUN file="podman-remote-static-linux_${TARGETARCH}.tar.gz" \
 && wget -q -O "/tmp/${file}" "https://github.com/containers/podman/releases/download/${PODMAN_VERSION}/${file}" \
 && eval "expected=\$PODMAN_SHA256_${TARGETARCH}" \
 && echo "${expected}  /tmp/${file}" | sha256sum -c - \
 && tar -xzf "/tmp/${file}" -C /tmp \
 && install -m 0755 "/tmp/bin/podman-remote-static-linux_${TARGETARCH}" /podman \
 && install -d -m 0777 /data-skel

# Unprivileged user (nonroot, uid 65532, the image default). Chainguard static has no shell to create /data, so it is made in
# the stage above, world-writable: the run commands in docs/headless.md use
# `--userns=keep-id`, which runs the process as the host user (the owner of the podman socket),
# not as 65532, and that user must be able to write to the data volume.
FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
COPY --from=podman /podman /usr/local/bin/podman
COPY --from=podman --chown=65532:65532 --chmod=0777 /data-skel /data
# The project's OpenVEX statements. Scanners do not discover this on their own: pass it with
# `--vex <file>`, or use the attestation on the registry (`--vex oci`). See docs/headless.md.
COPY build/vex/openvex.json /usr/share/doc/trivy-scanner/trivy-scanner.vex.json
COPY --from=build /out/trivy-scanner /usr/local/bin/trivy-scanner
ENV WAILS_SERVER_HOST=127.0.0.1 \
    WAILS_SERVER_PORT=8080 \
    CONTAINER_HOST=unix:///run/podman/podman.sock \
    TRIVY_SCANNER_VEX_FILE=/data/vex.json \
    XDG_CACHE_HOME=/data/cache
VOLUME /data
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/trivy-scanner"]
