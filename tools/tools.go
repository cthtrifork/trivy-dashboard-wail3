//go:build tools

// Package tools pins the dev tools this repository runs (see the Makefile). The blank imports make
// them direct requirements in go.mod, which Dependabot updates; `// indirect` ones it skips. The
// tool directive in go.mod is what `go tool -modfile=tools/go.mod` runs.
package tools

import (
	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
	_ "golang.org/x/tools/cmd/goimports"
	_ "golang.org/x/vuln/cmd/govulncheck"
)
