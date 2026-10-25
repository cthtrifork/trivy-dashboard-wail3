# Dev environment for Trivy Scanner: Go, Node and the podman *client* (scans run on a podman
# API socket, see docs/devcontainer.md). No GTK: the app runs in server mode in the browser.
FROM mcr.microsoft.com/devcontainers/base:trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends podman-remote make curl \
 && ln -s /usr/bin/podman-remote /usr/local/bin/podman \
 && rm -rf /var/lib/apt/lists/*
