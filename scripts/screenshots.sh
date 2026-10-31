#!/usr/bin/env bash
# Regenerates docs/screenshots/*.png from the recorded fixtures (headless server, no podman).
# Needs Go, Node 20+ and Playwright with Chromium (or playwright-core + SCREENSHOT_BROWSER_CHANNEL=chrome).
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-docs/screenshots}"
port="${SCREENSHOT_PORT:-18080}"

# shellcheck source=lib/fake-app.sh
source scripts/lib/fake-app.sh

# The proxy variables are dropped for the app so the Help dialog's environment section looks the same
# on every machine.
start_fake_app "$port" env -u HTTPS_PROXY -u HTTP_PROXY -u NO_PROXY -u https_proxy -u http_proxy -u no_proxy

mkdir -p "$out"
node scripts/screenshots.mjs "http://127.0.0.1:${port}/" "$out"
