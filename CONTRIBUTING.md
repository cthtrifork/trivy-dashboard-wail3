# Contributing

1. Branch from `main`: `git checkout -b <topic> origin/main`.
2. Make the change with tests. Tests replay recorded fixtures; they need no podman or network.
3. Run what CI runs: `make check` (gofmt, `go mod tidy -diff`, vet, tests and the headless build, all GTK-free), plus `make lint` for the linters.
4. Update docs and the README for user-visible changes.
5. Open a PR using the template.

Standing rules and the architecture overview: [`AGENTS.md`](AGENTS.md), [`docs/principles.md`](docs/principles.md), [`docs/architecture.md`](docs/architecture.md).

Report security issues privately to the maintainers rather than in a public issue.
