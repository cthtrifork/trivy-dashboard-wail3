#!/usr/bin/env bash
# Hot-reload dev loop, used by `make dev` and the dev container.
#
# Vite serves the Vue app with HMR; the Go app runs in server mode (no GTK) behind it and is
# rebuilt and restarted by air on every .go change. Open http://localhost:$WAILS_SERVER_PORT.
# Scans use podman (nested in the dev container); if it is unusable it falls back to the recorded demo data (dev builds only).
set -euo pipefail

cd "$(dirname "$0")/.."
export WAILS_SERVER_PORT="${WAILS_SERVER_PORT:-8080}"
vite_port="${WAILS_VITE_PORT:-9245}"
export WAILS_VITE_PORT="$vite_port"
export FRONTEND_DEVSERVER_URL="http://127.0.0.1:$vite_port"
export PATH="$PATH:$(go env GOPATH)/bin"

command -v air >/dev/null || { echo "air not found: go install github.com/air-verse/air@v1.61.7" >&2; exit 1; }

# Real scans need a working podman (local, or CONTAINER_HOST pointing at a socket).
if [ -z "${TRIVY_SCANNER_FAKE_PODMAN:-}" ] && ! podman info >/dev/null 2>&1; then
  echo "dev: podman is not usable here; using demo data. See docs/devcontainer.md." >&2
  export TRIVY_SCANNER_FAKE_PODMAN=1
fi

(cd frontend && [ -d node_modules ] || npm ci --ignore-scripts --no-audit --no-fund)

vite_pid=""
trap '[ -n "$vite_pid" ] && kill "$vite_pid" 2>/dev/null || true' EXIT INT TERM

(cd frontend && exec npm run dev) &
vite_pid=$!

# The Wails dev build aborts if the frontend server is not up yet.
for _ in $(seq 1 60); do
  curl -fs -o /dev/null "$FRONTEND_DEVSERVER_URL" && break
  kill -0 "$vite_pid" 2>/dev/null || { echo "vite exited" >&2; exit 1; }
  sleep 0.5
done

echo "dev: http://localhost:$WAILS_SERVER_PORT (Vue: HMR, Go: rebuild on save)"
air -c .air.toml
