# Sourced by screenshots.sh and lighthouse.sh: builds the headless server and starts it on recorded
# fixtures (TRIVY_SCANNER_FAKE_PODMAN=1) with a throwaway VEX store and cache, so nothing touches podman.
#
#   source scripts/lib/fake-app.sh   (from the repo root, after `set -euo pipefail`)
#   start_fake_app <port> [command prefix...]

tmp="$(mktemp -d)"
pid=""
cleanup() {
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
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
    curl -fsS -o /dev/null --max-time 1 "http://127.0.0.1:${port}/" 2>/dev/null && return 0
    kill -0 "$pid" 2>/dev/null || { cat "$tmp/app.log" >&2; echo "app exited early" >&2; exit 1; }
    sleep 0.2
  done
  echo "app did not answer on port $port" >&2
  cat "$tmp/app.log" >&2
  exit 1
}
