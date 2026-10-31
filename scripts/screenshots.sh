#!/usr/bin/env bash
# Regenerates docs/screenshots/*.png from the recorded fixtures (headless server, no podman).
# Needs Go, Node 20+ and Playwright with Chromium (or playwright-core + SCREENSHOT_BROWSER_CHANNEL=chrome).
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-docs/screenshots}"
port="${SCREENSHOT_PORT:-18080}"

# shellcheck source=lib/fake-app.sh
source scripts/lib/fake-app.sh

tmp="$(mktemp -d)"
trap 'fake_app_stop "$tmp"; rm -rf "$tmp"' EXIT

fake_app_build "$tmp"

# The proxy variables are dropped for the app so the Help dialog's environment section looks the same
# on every machine.
(
  unset HTTPS_PROXY HTTP_PROXY NO_PROXY https_proxy http_proxy no_proxy
  fake_app_start "$tmp" "$port"
)

mkdir -p "$out"
node scripts/screenshots.mjs "http://127.0.0.1:${port}/" "$out"
