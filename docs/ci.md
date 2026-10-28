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
| Inject a version into the binary from the tag | guide's list of enhancements | `-X …/internal/app.version=…` in release (and `ci-<sha>` in CI) |
| Cache dependencies | guide's list of enhancements | `setup-go` cache |
| Create the release when a tag is pushed | action's release step | `gh release create` in `release.yml`, instead of a third-party action |
| Test job: GTK4 + WebKitGTK 6 build dependencies, `GOTOOLCHAIN: local`, cancel superseded PR runs | Wails v3 `build-and-test-v3.yml` | `ci.yml` |
| Job graph: `lint` (gofmt, tidy, bindings; no GTK) → `vet` → `test` and `build` in parallel, so cheap failures surface before the slow race tests | this repo | `ci.yml` |

## What was left out, and why

- **Per-distro WebKit package and build tag** (the action picks `libwebkit2gtk-4.0` or `4.1` plus `-tags webkit2_41` by Ubuntu release). That is a Wails v2 / GTK3 concern. This app targets Wails v3's default GTK4 + WebKitGTK 6 backend only. A GTK3 build would be a separate asset and has not been asked for.
- **arm64 cross-compilation** (`gcc-aarch64-linux-gnu`), **Windows and macOS** matrix entries, **code signing and notarisation**: only a Linux amd64 binary is published. Provenance is covered by a build attestation and SHA-256 checksums instead.
- **The `wails build` CLI, obfuscation, Deno/Node build steps, `NODE_OPTIONS`**: the app is built with `go build`. The frontend is built first with `make frontend` (`npm ci && npm run build`, Vite, see decision 14), using the runner's preinstalled Node instead of a `setup-node` action; the Go side only embeds `frontend/dist`. A separate step regenerates `frontend/bindings` with the `wails3` CLI at the go.mod version and fails on any diff.

## Lint and format checks

`ci.yml` also runs, in the `test` job: `make lint-frontend` (Biome lint and format check, config in `frontend/biome.json`) and `make lint-go` (golangci-lint with the config in `.golangci.yml`: default linters; staticcheck's tagged-switch quick fixes and unchecked `Close`/test-helper writes are excluded). golangci-lint and `govulncheck` run through `go run <module>@<version>` (`make lint-go`, `make govulncheck`), with the versions pinned in the `Makefile`, rather than through a third-party action. `make tools` installs them and `goimports` into `GOBIN` for editors. `make lint` runs both locally; `make fmt` and `make format-frontend` fix formatting.

## Dependency updates (Renovate)

Self-hosted Renovate (`renovate.yml`, the `renovatebot/github-action`) replaces Dependabot, with the config in `.github/renovate.json5`.

- **What it updates:** Go modules, the frontend npm packages, Docker base images (every `FROM` line, in `build/docker/headless.Dockerfile` and `.devcontainer/Dockerfile`), the default Trivy image in `internal/trivy/engine.go` (the same `renovate:` comment, written `//` above the `const`), the SHA-pinned Actions (`helpers:pinGitHubActionDigests` keeps the `# vX.Y.Z` comment), the Go version in the workflows, and anything marked with a `# renovate: datasource=<ds> depName=<name>` comment on the line above its version: the Go dev tools in the `Makefile`, zizmor and the `gh-pin-actions` extension in `actions-lint.yml`, and the `podman-remote` release (`ARG PODMAN_VERSION`) in `headless.Dockerfile`. Apart from that ARG, the container files need no such comment; apt and apk packages are left to the distribution.
- **When:** weekdays (cron) and on demand, on the default branch only, so a schedule only starts once the workflow is on `main`. It also keeps the "Dependency Dashboard" issue up to date.
- **Cooldown and automerge:** a release must be 2 days old before Renovate creates a branch for it (`minimumReleaseAge` with `internalChecksFilter: strict`). Patch and digest updates then automerge; minor and major updates wait for review. Minors are grouped per ecosystem (`actions`, `go-minor`, `frontend-minor`, `dev tools`) but patches never join a group, because a group merges as a whole. The Go version (workflows, `go.mod`, Dockerfiles) is one `go toolchain` PR that is never automerged. `@wailsio/runtime` and the runner image (`ubuntu-24.04`) are not updated.
- **Security:** advisories come from OSV.dev (`osvVulnerabilityAlerts`) and, in the real run, GitHub's own alerts (through the App's Dependabot alerts permission).
- **Config lint:** the `renovate config` job in `actions-lint.yml` runs `renovate-config-validator --strict` on `renovate.json5` (version pinned with a `# renovate:` comment).
- **Dry run:** a pull request that changes `renovate.json5` or `renovate.yml` runs Renovate with `RENOVATE_DRY_RUN=full` on its own branch. It writes nothing; the job summary lists the branches and updates it would create and the step log has the full debug output.
- **GitHub App:** the real run authenticates as a GitHub App ([renovatebot/github-action, "Example with GitHub App"](https://github.com/renovatebot/github-action#example-with-github-app)) through `actions/create-github-app-token`, not with `GITHUB_TOKEN`: PRs opened with `GITHUB_TOKEN` do not start CI, so an automerge would have no checks to wait for, and the workflow's own token stays read-only. Setup: create a GitHub App with repository permissions Contents, Pull requests, Issues, Workflows and Commit statuses (read and write; Renovate posts a `renovate/stability-days` status for `minimumReleaseAge`) and Checks and Dependabot alerts (read), install it on this repository, download its private key, then add the repository variable `RENOVATE_APP_CLIENT_ID` and the secret `RENOVATE_APP_PRIVATE_KEY`. Commits go through the API as the App (`platformCommit`), so they are verified. Require the CI checks in branch protection before relying on automerge. The dry run on pull requests mints a read-only token from the same App, so it also checks the App's credentials and installation (for pull requests from branches of this repository; forks get no secrets).

## Actions lint

`actions-lint.yml` runs on changes under `.github/`, on `main` and weekly: zizmor (pedantic persona, installed from PyPI at the version pinned in the workflow) audits workflows and composite actions, and `gh pin-actions workflows --latest` re-pins every `uses:` in the workflows a PR adds or changes. The check fails on an unpinned action or one with a newer release. The tool pins immutable releases to the tag instead of the SHA; that is the same version, so it is not a failure.

## Screenshots

Screenshots are not committed from a feature branch, with one exception (the dependency graph, below). Every PR that rewrote the PNGs conflicted with every other one (git cannot merge binary files), so `screenshots.yml` renders them in CI instead:

- **Pull request** (changes `frontend/**`, the fixtures or the screenshot scripts): runs `make screenshots` on the recorded fixtures, uploads each image as its own unzipped artifact (`actions/upload-artifact` with `archive: false`, which takes one file and names the artifact after it) and embeds them in one sticky PR comment as a heading plus the bare `artifact-url` per image (the layout of homeserver-bootc's screenshot action; no `<img>` or `<details>` wrapper) (marker `<!-- screenshots-preview -->`) that is updated on every push. Nothing is pushed to the repository. Viewers must be logged in and the images expire with the artifacts (14 days). Fork PRs have a read-only token, so they get the artifacts on the run page and no comment.
- **Adding or removing a screenshot** in `scripts/screenshots.mjs` needs a matching `Upload <name>` step (id `shot-<name>`) in `screenshots.yml`, because an action cannot be looped. The comment step fails with a message when the counts differ.
- **Dependency graph (06-09)** is rendered by a separate workflow, `screenshots-deps.yml`, not by `screenshots.yml`. The graph is a canvas whose anti-aliasing varies between runs, so rendering it on `main` opened PRs with no real change. `screenshots.yml` runs with `SCREENSHOT_VIEWS=core`, which skips these four images (so the PR comment lacks them too). `screenshots-deps.yml` runs on same-repo PRs that change `DepsPanel.vue`, `styles/deps.css` or `lib/graph.js`: it renders only the graph (`SCREENSHOT_VIEWS=deps`) and, if the images differ, commits them to the PR branch as `Update dependency graph screenshots`. It pushes with `GITHUB_TOKEN`, so no workflow starts on that commit (no loop, but also no CI on it: re-run CI or push again if a required check must report on the new head). A later push that does not touch the graph code does not render again, so render noise is never committed. Fork PRs cannot be pushed to and are skipped. If the graph comes to depend on another file, add it to both the `paths` and the `code` list in that workflow.
- **Push to `main`** (same paths): renders again and, if any image differs, force-pushes `bot/update-screenshots` (rebuilt from `main`, so it cannot conflict) and opens or updates a single `Update screenshots` PR. Merging it only touches `docs/screenshots`, which is outside the workflow's `paths`, so there is no loop.
- Setup: Settings > Actions > General > "Allow GitHub Actions to create and approve pull requests" must be on. PRs created with `GITHUB_TOKEN` do not start other workflows, so `ci.yml` does not run on the bot PR; close and reopen it, or use a PAT, if branch protection requires checks.
- Do not commit locally generated PNGs in a feature PR. Runner fonts differ from your machine, and the CI render is the reference.
- The script is made as reproducible as it reasonably can be: it waits for the force-directed graph to rest instead of sleeping, pins the OpenVEX timestamps, disables animations, the graph's tie-breaking random numbers are seeded, and demo mode reports a zero footprint.

`bindings.yml` keeps `frontend/bindings` in step with the Go code: when a same-repository pull request changes Go code, it regenerates the bindings with the `wails3` CLI at the go.mod version and, if anything changed, pushes a `Regenerate Wails bindings` commit to the PR branch. Commits pushed with `GITHUB_TOKEN` do not start new workflow runs, so close and reopen the PR or push once more if you need CI re-run on the bot commit. The CI bindings check stays as the backstop.

`security.yml` also runs `make audit-frontend` (`npm audit --omit=dev --audit-level=high` in `frontend/`; weekly, and when the frontend lockfile changes): runtime dependencies only, HIGH and above. It is deliberately not part of `ci.yml`, so a newly published advisory cannot block unrelated pull requests.
