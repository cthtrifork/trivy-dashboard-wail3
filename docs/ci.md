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
- **The `wails build` CLI, obfuscation, Deno/Node build steps, `NODE_OPTIONS`**: the app is built with `go build`. The frontend is built first with `npm ci && npm run build` (Vite, see decision 14), using the runner's preinstalled Node instead of a `setup-node` action; the Go side only embeds `frontend/dist`. A separate step regenerates `frontend/bindings` with the `wails3` CLI at the go.mod version and fails on any diff.

## Screenshots

`screenshots.yml` keeps `docs/screenshots` in step with the UI: when a same-repository pull request changes `frontend/**` (or the screenshot scripts), it runs `scripts/screenshots.sh` on the recorded fixtures and, if any image changed, pushes an `Update screenshots` commit to the PR branch.

- Fork PRs and Dependabot PRs are skipped (read-only token).
- **No loop:** pushes made by `github-actions[bot]` are ignored (`github.actor` check). Without it the bot's commit re-triggers the workflow, and because rendering is never perfectly identical between runs, each run would commit again.
- The script is made as reproducible as it reasonably can be: it waits for the force-directed graph to rest instead of sleeping, pins the OpenVEX timestamps, disables animations, and the graph's tie-breaking random numbers are seeded. Fonts on the runner can differ from your machine, so let the workflow regenerate the images rather than committing locally generated ones.

`security.yml` also runs `npm audit --omit=dev --audit-level=high` in `frontend/` (weekly, and when the frontend lockfile changes): runtime dependencies only, HIGH and above. It is deliberately not part of `ci.yml`, so a newly published advisory cannot block unrelated pull requests.
