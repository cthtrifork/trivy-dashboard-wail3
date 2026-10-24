# CI design notes

Where the GitHub Actions workflows in `.github/workflows` come from, and what was deliberately left out.

Sources:
- Wails, [Crossplatform build with GitHub Actions](https://wails.io/docs/guides/crossplatform-build/) (a Wails **v2** guide).
- [`dAppServer/wails-build-action`](https://github.com/dAppServer/wails-build-action/blob/main/action.yml), the action that guide points to (also v2: it drives the `wails build` CLI).
- Wails v3's own `build-and-test-v3.yml`, for the test job. The two sources above contain **no test step at all**.

## What was taken from them

| Practice | Source | Where here |
|---|---|---|
| Build when a tag is pushed and keep the result as an Actions artifact | guide's example workflow | `release.yml` (semantic-version tags only, artifact `release-files`) |
| `setup-go` with `check-latest: true` and a cache keyed on `go.sum` | action's *Setup GoLang* step | every workflow that installs Go |
| Print `go version` so a run records its toolchain | action's `go version` step | CI, release, security (CI and release also print the GTK/WebKit versions) |
| Detect the distribution and **fail the run if it is unsupported** rather than build anyway | action's *Linux Discovery* step | `release.yml` *Check the build distribution*: the README promises a binary built on Ubuntu 24.04, which fixes the glibc and WebKitGTK baseline |
| Set the executable bit explicitly | action's *Add Linux perms* step | CI and release build steps |
| One named artifact per platform | action's `upload-artifact` step | CI uploads `trivy-scanner-linux-amd64` (unsigned, 7 days) so reviewers can try a PR build |
| Inject a version into the binary from the tag | guide's list of enhancements | `-X main.version=…` in release (and `ci-<sha>` in CI) |
| Cache dependencies | guide's list of enhancements | `setup-go` cache |
| Create the release when a tag is pushed | action's release step | `gh release create` in `release.yml`, instead of a third-party action |
| Test job: GTK4 + WebKitGTK 6 build dependencies, `GOTOOLCHAIN: local`, cancel superseded PR runs | Wails v3 `build-and-test-v3.yml` | `ci.yml` |

## What was left out, and why

- **Per-distro WebKit package and build tag** (the action picks `libwebkit2gtk-4.0` or `4.1` plus `-tags webkit2_41` by Ubuntu release). That is a Wails v2 / GTK3 concern. This app targets Wails v3's default GTK4 + WebKitGTK 6 backend only. A GTK3 build would be a separate asset and has not been asked for.
- **arm64 cross-compilation** (`gcc-aarch64-linux-gnu`), **Windows and macOS** matrix entries, **code signing and notarisation**: only a Linux amd64 binary is published. Provenance is covered by a build attestation and SHA-256 checksums instead.
- **The `wails build` CLI, obfuscation, Deno/Node build steps, `NODE_OPTIONS`**: the app is built with `go build` and its frontend is plain JavaScript with no build step.

## Screenshots

`screenshots.yml` keeps `docs/screenshots` in step with the UI.

- **Trigger:** a pull request that touches `frontend/**` (or the screenshot scripts), or a manual run on a non-default branch.
- **Who:** same-repository PRs only. Fork PRs get a read-only token and their code must not run with write access; Dependabot PRs likewise have a read-only token.
- **What:** builds the headless app with the recorded fixtures (`scripts/screenshots.sh`, Playwright pinned to one version), then `scripts/sync-screenshots.sh` copies only images that changed visibly (more than 200 pixels beyond a 3% colour fuzz). Rendering is not bit-identical between runs (a dialog's rounded corners antialias differently), so a byte comparison would churn files.
- **Result:** an `Update screenshots` commit pushed to the PR branch. If nothing changed visibly, nothing is committed.
- **CI on the new commit:** a push made with `GITHUB_TOKEN` starts no workflows, which would leave the PR head without the required "CI / test" result. The workflow therefore runs `gh workflow run ci.yml --ref <branch>` itself, which is why `ci.yml` has a `workflow_dispatch` trigger. If someone pushes to the branch while the job runs, the push fails and the next push re-runs it.
- **Reproducibility:** the screenshot script waits for the force-directed graph to come to rest instead of sleeping, pins the OpenVEX timestamps, disables animations, and the graph's tie-breaking random numbers are seeded (`frontend/graph.js`). Fonts on the runner may still differ from your machine, so prefer letting the workflow regenerate the images over committing locally generated ones.
