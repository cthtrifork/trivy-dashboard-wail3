# Network activity

What the app sends over the network, when, and what happens offline. There are no timers or background jobs: everything below is triggered by startup or by something you do.

| When | Network activity | If offline |
|---|---|---|
| App start | `podman search --list-tags` on `docker.io/aquasec/trivy`. It fills the Trivy version picker and sets the field to the newest version. | The list is empty. The field keeps the version of the last successful scan, or the pinned default (`DefaultTrivyImage`) if nothing has scanned yet. |
| Opening the image tag field (split view) | `podman search --list-tags` on that image's repository, once per repository. | The list is empty; a tag can still be typed. |
| First scan of a session | `trivy image --download-db-only` from `DefaultDBRepository` (`ghcr.io/aquasecurity/trivy-db:2`) or the `TRIVY_DB_REPOSITORY` mirror. Trivy downloads only if the cached DB is out of date. Podman first pulls the Trivy image if it is not local. | A warning is logged and the cached DB is used; the check is retried on the next scan. The scan fails if the Trivy image is not local. |
| Every scan | Trivy fetches the target image from its registry, in two runs (vulnerabilities, then SBOM). | Expected to fail: the container has no podman socket, so it needs the registry. |
| Every scan | EPSS from `api.first.org` (no cache) and the CISA KEV feed (cached on disk for 12 hours). | Both are skipped with a warning; a cached KEV copy is used if there is one. |
| Compare | The scan steps above, four times. The DB check still runs once. | Same as scan. |
| Options → Check vulnerability database | The same `--download-db-only` check, on demand. | An error is shown and the cached DB is kept. Nothing is deleted. |
| Options → App updates → Check for updates | GitHub Releases, looking only (release builds). | A status message shows the error. |
| Options → Install update | The release download, with its checksum verified. | A status message shows the error. |

## Notes

- **The DB is checked once per session** (one run of the app) when it succeeds. A failed check is retried on every scan until one succeeds. Changing the Trivy version does not trigger a check. Scans run with `--skip-db-update`. See [`architecture.md`](architecture.md#vulnerability-db).
- **Nothing at startup** touches the vulnerability DB, EPSS, KEV or GitHub.
- **The default Trivy version** is the newest plain version found by the startup lookup, else the last successful one, else the pinned constant. It is only saved once you edit the field, so an offline start reuses an image podman already has.
- **Offline with an earlier scan:** the last result is restored from browser storage, so it can be viewed. VEX, rescoring and presets are local. Scanning again needs the registry.
- **Mirrors and proxies:** `TRIVY_DB_REPOSITORY`, `TRIVY_JAVA_DB_REPOSITORY`, `TRIVY_SCANNER_EPSS_URL`, `TRIVY_SCANNER_KEV_URL`, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` and `TRIVY_SCANNER_CA_BUNDLE` redirect or secure these calls; see [`architecture.md`](architecture.md#vulnerability-db) and the help dialog.
