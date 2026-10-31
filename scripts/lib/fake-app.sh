# Sourced by screenshots.sh and lighthouse.sh: helpers to build the headless server and run it on recorded
# fixtures (TRIVY_SCANNER_FAKE_PODMAN=1) with a throwaway VEX store and cache, so nothing touches podman.
# The caller owns the work directory <dir> (mktemp -d) and removes it.
#
#   fake_app_build <dir>          build the frontend and the server binary into <dir>
#   fake_app_start <dir> <port>   start it and wait until it answers; the app inherits the caller's environment
#   fake_app_stop <dir>           stop it

fake_app_build() {
  make frontend
  CGO_ENABLED=0 go build -tags server -o "$1/app" .
}

fake_app_start() {
  local dir="$1" port="$2"

  TRIVY_SCANNER_FAKE_PODMAN=1 \
    TRIVY_SCANNER_VEX_FILE="$dir/vex.json" \
    XDG_CACHE_HOME="$dir/cache" \
    WAILS_SERVER_HOST=127.0.0.1 \
    WAILS_SERVER_PORT="$port" \
    "$dir/app" >"$dir/app.log" 2>&1 &
  echo $! >"$dir/app.pid"

  for _ in $(seq 1 50); do
    curl -fsS -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null && return 0
    sleep 0.2
  done
  cat "$dir/app.log" >&2
  echo "app did not answer on port $port" >&2
  return 1
}

fake_app_stop() {
  [ -f "$1/app.pid" ] && kill "$(cat "$1/app.pid")" 2>/dev/null || true
}
