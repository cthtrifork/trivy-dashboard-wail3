#!/usr/bin/env bash
# Regenerates docs/screenshots/*.png from the recorded Trivy fixtures.
#
# It builds the app in headless server mode (no GTK needed), starts it with
# TRIVY_SCANNER_FAKE_PODMAN=1 so every scan replays internal/trivy/fixtures and
# nothing touches podman or the network (scripts/lib/fake-app.sh), then drives the real UI with Playwright.
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

# shellcheck source=lib/fake-app.sh
source scripts/lib/fake-app.sh

# The proxy variables are dropped for the app so the Help dialog's environment section looks the same
# on every machine.
start_fake_app "$port" env -u HTTPS_PROXY -u HTTP_PROXY -u NO_PROXY -u https_proxy -u http_proxy -u no_proxy

mkdir -p "$out"
node scripts/screenshots.mjs "http://127.0.0.1:${port}/" "$out"
