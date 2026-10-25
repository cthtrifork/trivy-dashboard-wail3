# Dev environment for Trivy Scanner: Go, Node and a full rootless podman, so scans run inside
# the container (podman-in-podman/docker, see docs/devcontainer.md). No GTK: the app runs in
# server mode in the browser.
FROM docker.io/library/golang:1.26-trixie AS go
FROM docker.io/library/node:22-trixie-slim AS node

FROM mcr.microsoft.com/devcontainers/base:trixie

COPY --from=go /usr/local/go /usr/local/go
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

RUN apt-get update \
 && apt-get install -y --no-install-recommends podman uidmap fuse-overlayfs passt netavark aardvark-dns make curl \
 && rm -rf /var/lib/apt/lists/* \
 && echo "vscode:100000:65536" > /etc/subuid \
 && echo "vscode:100000:65536" > /etc/subgid \
 && mkdir -p /home/vscode/go /home/vscode/.local/share/containers \
 && chown -R vscode:vscode /home/vscode/go /home/vscode/.local

ENV GOPATH=/home/vscode/go \
    PATH=/usr/local/go/bin:/home/vscode/go/bin:${PATH}
