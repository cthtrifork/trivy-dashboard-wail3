# Dev environment for Trivy Scanner: Go, Node and a full rootless podman, so scans run inside
# the container (podman-in-podman/docker, see docs/devcontainer.md). No GTK: the app runs in
# server mode in the browser.
FROM mcr.microsoft.com/devcontainers/base:trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends podman uidmap fuse-overlayfs slirp4netns netavark aardvark-dns make curl \
 && rm -rf /var/lib/apt/lists/* \
 && echo "vscode:100000:65536" > /etc/subuid \
 && echo "vscode:100000:65536" > /etc/subgid \
 && mkdir -p /home/vscode/.local/share/containers \
 && chown -R vscode:vscode /home/vscode/.local
