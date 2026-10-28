# Trivy Scanner in server mode, for hosts that have podman but no Go toolchain.
# See docs/headless.md.
FROM docker.io/library/node:26-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM docker.io/library/golang:1.26-alpine AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/frontend/dist ./frontend/dist
ARG VERSION=dev
RUN go build -tags server,production -trimpath -ldflags "-w -s -X github.com/cthtrifork/trivy-dashboard-wail3/internal/app.version=${VERSION}" -o /out/trivy-scanner .

# The app only needs the podman *client*: scans run on the host's podman through its API socket.
# Upstream's static podman-remote runs on distroless (Alpine's is linked against musl). Keep
# PODMAN_VERSION close to the host's podman, and update the checksums with it.
FROM docker.io/library/alpine:3.24 AS podman
ARG PODMAN_VERSION=v6.1.4
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) sha=af1f85c22214088a0a9986b9c82b4c9b5b74eda8ecaa6c8cca82b1a63f339b4a ;; \
      arm64) sha=1d7c2a3241b56effa68c724359fb30e603a802699b2b7b20fe2fae5ff6819601 ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && wget -q -O /tmp/podman.tgz "https://github.com/containers/podman/releases/download/${PODMAN_VERSION}/podman-remote-static-linux_${TARGETARCH}.tar.gz" \
 && echo "$sha  /tmp/podman.tgz" | sha256sum -c - \
 && tar -xzf /tmp/podman.tgz -C /tmp \
 && install -m 0755 "/tmp/bin/podman-remote-static-linux_${TARGETARCH}" /podman

# Runs as root (the default), like the Alpine image did: the host's podman socket is usually root-owned.
FROM gcr.io/distroless/static-debian13@sha256:15f8637509792e05b97d83451b0b6ccfa4abd548f997e406ac1e72c87fe1fa78
COPY --from=podman /podman /usr/local/bin/podman
COPY --from=build /out/trivy-scanner /usr/local/bin/trivy-scanner
# The project's OpenVEX statements. Scanners do not discover this on their own: pass it with
# `--vex <file>`, or use the attestation on the registry (`--vex oci`). See docs/headless.md.
COPY vex/openvex.json /usr/share/doc/trivy-scanner/trivy-scanner.vex.json
ENV WAILS_SERVER_HOST=127.0.0.1 \
    WAILS_SERVER_PORT=8080 \
    CONTAINER_HOST=unix:///run/podman/podman.sock \
    TRIVY_SCANNER_VEX_FILE=/data/vex.json \
    XDG_CACHE_HOME=/data/cache
VOLUME /data
ENTRYPOINT ["/usr/local/bin/trivy-scanner"]
