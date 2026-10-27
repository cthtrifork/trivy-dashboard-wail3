#!/usr/bin/env bash
# Hot-reload dev loop, used by `make dev` and the dev container.
#
# `wails3 dev` (config in build/config.yml, tasks in Taskfile.yml) runs Vite with HMR and the Go app in
# server mode (no GTK), rebuilding and restarting it on every .go change. Open http://localhost:$WAILS_SERVER_PORT.
# Scans use podman (nested in the dev container); if it is unusable it falls back to the recorded demo data (dev builds only).
set -euo pipefail

cd "$(dirname "$0")/.."
export WAILS_SERVER_PORT="${WAILS_SERVER_PORT:-8080}"
vite_port="${WAILS_VITE_PORT:-9245}"
export WAILS_VITE_PORT="$vite_port"
export PATH="$PATH:$(go env GOPATH)/bin"

command -v wails3 >/dev/null || { echo "wails3 not found: make wails3-install" >&2; exit 1; }

# Real scans need a working podman (local, or CONTAINER_HOST pointing at a socket).
if [ -z "${TRIVY_SCANNER_FAKE_PODMAN:-}" ] && ! podman info >/dev/null 2>&1; then
  echo "dev: podman is not usable here; using demo data. See docs/devcontainer.md." >&2
  export TRIVY_SCANNER_FAKE_PODMAN=1
fi

(cd frontend && [ -d node_modules ] || npm ci --ignore-scripts --no-audit --no-fund)

echo "dev: http://localhost:$WAILS_SERVER_PORT (Vue: HMR, Go: rebuild on save)"
exec wails3 dev -config ./build/config.yml -port "$vite_port"
