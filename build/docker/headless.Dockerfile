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

FROM docker.io/library/alpine:3.24
# The app only needs the podman *client*: scans run on the host's podman through its API socket.
RUN apk add --no-cache podman-remote ca-certificates \
 && ln -s /usr/bin/podman-remote /usr/local/bin/podman
COPY --from=build /out/trivy-scanner /usr/local/bin/trivy-scanner
# The project's OpenVEX statements. Scanners do not discover this on their own: pass it with
# `--vex <file>`, or use the attestation on the registry (`--vex oci`). See docs/headless.md.
COPY vex/openvex.json /usr/share/doc/trivy-scanner/openvex.json
ENV WAILS_SERVER_HOST=127.0.0.1 \
    WAILS_SERVER_PORT=8080 \
    CONTAINER_HOST=unix:///run/podman/podman.sock \
    TRIVY_SCANNER_VEX_FILE=/data/vex.json \
    XDG_CACHE_HOME=/data/cache
VOLUME /data
ENTRYPOINT ["/usr/local/bin/trivy-scanner"]
