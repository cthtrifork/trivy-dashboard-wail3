# Sourced by screenshots.sh and lighthouse.sh: run the headless server on recorded fixtures, no podman.

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
