#!/usr/bin/env bash
# Audits the UI with Lighthouse (mobile and desktop) and fails when a score drops below the
# thresholds in scripts/lighthouse.mjs.
#
# Like scripts/screenshots.sh it builds and starts the app with scripts/lib/fake-app.sh (headless server
# mode, no GTK, fixtures, nothing touches podman or the network). The page is served by the
# same asset middleware the headless release build uses (gzip, cache headers).
#
# Requirements: Go, Node 20+ and a Chrome or Chromium (CHROME_PATH, default: google-chrome).
# Lighthouse itself runs through `npx lighthouse@$LIGHTHOUSE_VERSION` (pinned in .github/workflows/lighthouse.yml; set it to run the script by hand).
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-lighthouse}"
port="${LIGHTHOUSE_PORT:-18081}"

# shellcheck source=lib/fake-app.sh
source scripts/lib/fake-app.sh

start_fake_app "$port"

mkdir -p "$out"
LIGHTHOUSE_URL="http://127.0.0.1:${port}/" node scripts/lighthouse.mjs "$out"
