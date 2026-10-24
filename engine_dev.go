//go:build !production

package main

import (
	"context"
	"os"
	"strings"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

// newEngine picks how scans run in a development build, which is any build
// without -tags production (`go run .`, `wails3 dev`, plain `go build`).
// Recorded scans are replayed so the UI works without podman, a registry or
// network. Set TRIVY_SCANNER_REAL_PODMAN=1 to use the real podman instead.
func newEngine() (trivy.Engine, Mode) {
	if v := strings.ToLower(os.Getenv("TRIVY_SCANNER_REAL_PODMAN")); v != "" && v != "0" && v != "false" {
		return nil, Mode{Detail: "Development build using real podman (TRIVY_SCANNER_REAL_PODMAN is set)."}
	}
	e := trivy.NewFixtureEngine()
	m := Mode{
		Fixtures: true,
		Detail: "Demo mode: scans replay recorded Trivy output for traefik, not a live scan. " +
			"Set TRIVY_SCANNER_REAL_PODMAN=1 to use podman, or build with -tags production.",
		Repo: "traefik",
	}
	if tags, err := e.ListTags(context.Background(), m.Repo); err == nil { // newest first, then "latest"
		if versions := tags[:len(tags)-1]; len(versions) > 0 {
			m.TagB = versions[0]
			m.TagA = versions[len(versions)-1]
			m.Image = m.Repo + ":" + m.TagA
		}
	}
	return e, m
}
