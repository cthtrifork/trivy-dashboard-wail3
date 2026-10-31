# Sourced by screenshots.sh and lighthouse.sh: builds the headless server and starts it on recorded
# fixtures (TRIVY_SCANNER_FAKE_PODMAN=1) with a throwaway VEX store and cache, so nothing touches podman.
#
#   source scripts/lib/fake-app.sh   (from the repo root, after `set -euo pipefail`)
#   start_fake_app <port> [command prefix...]
#
# FAKE_APP_TIMEOUT (seconds, default 20) bounds how long to wait for the server to answer.

_fake_app_tmp="$(mktemp -d)"
_fake_app_pid=""

_fake_app_cleanup() {
  local status=$?
  trap - EXIT
  if [ -n "$_fake_app_pid" ]; then
    kill "$_fake_app_pid" 2>/dev/null || true
    wait "$_fake_app_pid" 2>/dev/null || true
  fi
  rm -rf "${_fake_app_tmp:?}"
  exit "$status"
}
trap _fake_app_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

_fake_app_fail() {
  echo "$1" >&2
  if [ -s "$_fake_app_tmp/app.log" ]; then
    echo "--- app log ---" >&2
    cat "$_fake_app_tmp/app.log" >&2
  fi
  exit 1
}

start_fake_app() {
  local port="${1:?usage: start_fake_app <port> [command prefix...]}"
  shift

  if curl -fsS -o /dev/null --max-time 1 "http://127.0.0.1:${port}/" 2>/dev/null; then
    echo "port $port is already in use; refusing to test against another server" >&2
    exit 1
  fi

  echo "building the frontend…"
  make frontend

  echo "building (server mode)…"
  CGO_ENABLED=0 go build -tags server -o "$_fake_app_tmp/app" .

  "$@" env \
    TRIVY_SCANNER_FAKE_PODMAN=1 \
    TRIVY_SCANNER_VEX_FILE="$_fake_app_tmp/vex.json" \
    XDG_CACHE_HOME="$_fake_app_tmp/cache" \
    WAILS_SERVER_HOST=127.0.0.1 \
    WAILS_SERVER_PORT="$port" \
    "$_fake_app_tmp/app" >"$_fake_app_tmp/app.log" 2>&1 &
  _fake_app_pid=$!

  local tries=$(( ${FAKE_APP_TIMEOUT:-20} * 5 )) i
  for ((i = 0; i < tries; i++)); do
    if curl -fsS -o /dev/null --max-time 1 "http://127.0.0.1:${port}/" 2>/dev/null; then
      return 0
    fi
    kill -0 "$_fake_app_pid" 2>/dev/null || _fake_app_fail "app exited early"
    sleep 0.2
  done
  _fake_app_fail "app did not answer on port $port within ${FAKE_APP_TIMEOUT:-20}s"
}
