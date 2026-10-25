#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

(cd frontend && npm ci --ignore-scripts --no-audit --no-fund)
go mod download
go install github.com/air-verse/air@v1.61.7
go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-beta.34
