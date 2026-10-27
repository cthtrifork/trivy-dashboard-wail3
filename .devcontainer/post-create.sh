#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# A clone owned by another uid (rootful Docker, Codespaces) would make git refuse to run.
git config --global --add safe.directory "$PWD"

# Rootless podman networking (pasta) opens /dev/net/tun; some hosts create it root-only.
[ -c /dev/net/tun ] && sudo chmod 0666 /dev/net/tun || true

(cd frontend && npm ci --ignore-scripts --no-audit --no-fund)
go mod download
make wails3-install
# Tools the Go extension runs from .vscode/settings.json (format on save, lint on save).
go install golang.org/x/tools/cmd/goimports@v0.38.0
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
