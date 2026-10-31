# Sourced by scripts/screenshots.sh and scripts/lighthouse.sh (not run on its own).
#
# Builds the app in headless server mode (no GTK) and starts it with TRIVY_SCANNER_FAKE_PODMAN=1, so
# every scan replays internal/trivy/fixtures and nothing touches podman or the network. A throwaway
# VEX store and cache keep the run independent of your own data.
#
#   source scripts/lib/fake-app.sh   (from the repository root, after `set -euo pipefail`)
#   start_fake_app <port> [command prefix...]
#
# The optional command prefix wraps the app process only (for example `env -u HTTPS_PROXY`), so the
# builds before it still see the proxy. Sets $tmp (scratch directory) and $pid, and removes both on exit.
tmp="$(mktemp -d)"
pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  rm -rf "${tmp:?}"
}
trap cleanup EXIT

start_fake_app() {
  local port="$1"
  shift

  echo "building the frontend…"
  make frontend

  echo "building (server mode)…"
  CGO_ENABLED=0 go build -tags server -o "$tmp/app" .

  "$@" env \
    TRIVY_SCANNER_FAKE_PODMAN=1 \
    TRIVY_SCANNER_VEX_FILE="$tmp/vex.json" \
    XDG_CACHE_HOME="$tmp/cache" \
    WAILS_SERVER_HOST=127.0.0.1 \
    WAILS_SERVER_PORT="$port" \
    "$tmp/app" >"$tmp/app.log" 2>&1 &
  pid=$!

  for _ in $(seq 1 50); do
    curl -fsS -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null && return 0
    kill -0 "$pid" 2>/dev/null || { cat "$tmp/app.log"; echo "app exited early"; exit 1; }
    sleep 0.2
  done
  echo "app did not answer on port $port" >&2
  cat "$tmp/app.log" >&2
  exit 1
}
