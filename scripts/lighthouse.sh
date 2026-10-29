#!/usr/bin/env bash
# Audits the UI with Lighthouse (mobile and desktop) and fails when a score drops below the
# thresholds in scripts/lighthouse.mjs.
#
# Like scripts/screenshots.sh it builds the app in headless server mode (no GTK) and starts it with
# TRIVY_SCANNER_FAKE_PODMAN=1, so nothing touches podman or the network. The page is served by the
# same asset middleware the headless release build uses (gzip, cache headers).
#
# Requirements: Go, Node 20+ and a Chrome or Chromium (CHROME_PATH, default: google-chrome).
# Lighthouse itself runs through `npx lighthouse@$LIGHTHOUSE_VERSION` (pinned in the Makefile).
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-lighthouse}"
port="${LIGHTHOUSE_PORT:-18081}"
tmp="$(mktemp -d)"
pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  rm -rf "${tmp:?}"
}
trap cleanup EXIT

echo "building the frontend…"
make frontend

echo "building (server mode)…"
CGO_ENABLED=0 go build -tags server -o "$tmp/app" .

TRIVY_SCANNER_FAKE_PODMAN=1 \
TRIVY_SCANNER_VEX_FILE="$tmp/vex.json" \
XDG_CACHE_HOME="$tmp/cache" \
WAILS_SERVER_HOST=127.0.0.1 \
WAILS_SERVER_PORT="$port" \
  "$tmp/app" >"$tmp/app.log" 2>&1 &
pid=$!

for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null && break
  kill -0 "$pid" 2>/dev/null || { cat "$tmp/app.log"; echo "app exited early"; exit 1; }
  sleep 0.2
done

mkdir -p "$out"
LIGHTHOUSE_URL="http://127.0.0.1:${port}/" node scripts/lighthouse.mjs "$out"
