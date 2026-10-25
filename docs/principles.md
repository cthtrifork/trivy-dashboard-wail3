# Principles

Standing rules for this repository. They come from the maintainer's instructions and from lessons learned while building it. If a task seems to conflict with one, say so instead of silently picking.

## Working agreement

1. **One change, one branch, one PR, from `main`.** Name branches `claude/<topic>`. Never commit to `main`.
2. **Do not wait for CI.** Open the PR, give the link, stop. The maintainer merges.
3. **Do the work asked, not adjacent work.** Parked ideas are mentioned in the PR description, not put in the diff. Scope that was dropped stays dropped (the Fedora/GTK3 build was cancelled; see `docs/decisions.md`).
4. **Ask only when blocked on a choice that is the maintainer's.** Otherwise pick a sensible default, say which, and continue.
5. **Report faithfully.** State what was verified and how. State what was *not* verified and why. A test you could not run is "unverified", never "should work".

## Product

6. **Real podman by default.** Every normal run, including `wails3 dev`, uses real podman. Recorded data is for Go tests and screenshots only, behind an explicit env flag, and is compiled out of production builds.
7. **Fewer, better findings.** The product's point is shortlisting the ten CVEs that matter, with a human-readable reason for each rank. Scores must stay explainable; do not add opaque weighting.
8. **Local and offline-tolerant.** Scans run locally. Network lookups (EPSS, KEV, tags) degrade gracefully and are overridable by env var for air-gapped mirrors.
9. **Quitting cleans up.** A scan in flight is cancelled and its container removed on shutdown and on cancel.

## Security

10. **No unauthenticated network exposure.** Server mode listens on loopback; access is by SSH tunnel. Do not bind `0.0.0.0` or publish ports in docs or defaults.
11. **Least surprise for updates.** The self-updater runs only when the user clicks, verifies SHA-256, and is disabled in dev and headless builds.
12. **Supply chain.** Pin Actions by SHA, keep `GOTOOLCHAIN=local` in CI, run `govulncheck` and Trivy on the repo, publish checksums and a build attestation.

## Code

13. **Match the surrounding code**: naming, comment density, idiom. Comments explain *why*.
14. **Tests replay fixtures**; they must not need podman, network or a display. Prefer testing `internal/trivy` behaviour over UI plumbing.
15. **Keep the frontend small.** Vue 3 + Vite with `@wailsio/runtime` and nothing else at runtime; the dependency graph stays a hand-written canvas. Add an npm dependency only with a decision record (see decision 14).
16. **Small files of docs next to the feature** (`docs/<feature>.md`), linked from the README.

## Verification checklist before opening a PR

- [ ] `gofmt -l .`, `go vet ./...` and `go vet -tags production ./...` are clean
- [ ] `go test -race -count=1 ./...` passes
- [ ] `go mod tidy -diff` is empty if dependencies changed
- [ ] Headless build compiles: `CGO_ENABLED=0 go build -tags server,production .`
- [ ] Behaviour you touched was exercised, not only compiled (run it, curl it, drive it)
- [ ] Docs and README updated; the PR body lists verified and unverified items
