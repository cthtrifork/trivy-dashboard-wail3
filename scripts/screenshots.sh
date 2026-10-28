#!/usr/bin/env bash
# Regenerates docs/screenshots/*.png from the recorded Trivy fixtures.
#
# It builds the app in headless server mode (no GTK needed), starts it with
# TRIVY_SCANNER_FAKE_PODMAN=1 so every scan replays internal/trivy/fixtures and
# nothing touches podman or the network, then drives the real UI with Playwright.
#
# Requirements: Go, Node 20+, and Playwright with Chromium
#   npm install --no-save playwright && npx playwright install chromium
# (a global Playwright install also works). With Google Chrome installed, `npm install --no-save
# playwright-core` and SCREENSHOT_BROWSER_CHANNEL=chrome skip the Chromium download. frontend/ has
# playwright-core as a dev dependency (Renovate keeps it current), so CI only sets the channel.
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-docs/screenshots}"
port="${SCREENSHOT_PORT:-18080}"
tmp="$(mktemp -d)"
pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  rm -rf "${tmp:?}"
}
trap cleanup EXIT

echo "building the frontend…"
make frontend

echo "building (server mode, dev tags)…"
CGO_ENABLED=0 go build -tags server -o "$tmp/app" .

# A throwaway VEX store and cache keep the screenshots independent of your own data.
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
node scripts/screenshots.mjs "http://127.0.0.1:${port}/" "$out"
