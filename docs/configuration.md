# Configuration and notes
- The Trivy cache is a host directory (`~/.cache/trivy-scanner/trivy` on Linux); set `TRIVY_SCANNER_CACHE` to change it. The vulnerability DB is checked once per session and scans run with `--skip-db-update`. See [`architecture.md`](architecture.md#trivy-cache).
- The image field remembers the last 8 scanned images (with their Critical/High counts) in the browser/webview. Focus the field, pick one with ↑/↓ and press Enter to rescan, or Tab to fill it in.
- Private registries: pass credentials via *Options* (`TRIVY_USERNAME`/`TRIVY_PASSWORD`). Locally-built images not in a registry are not scanned.
- EPSS and KEV feeds can be overridden with `TRIVY_SCANNER_EPSS_URL` / `TRIVY_SCANNER_KEV_URL`; the VEX store with `TRIVY_SCANNER_VEX_FILE`.
- Release builds can self-update: [`self-update.md`](self-update.md).

