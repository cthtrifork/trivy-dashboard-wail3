//go:build !production

package app

import (
	"context"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

// fakePodmanFlag switches a development build to recorded scan data.
const fakePodmanFlag = "TRIVY_SCANNER_FAKE_PODMAN"

// newEngine picks how scans run. By default every build, `wails dev` and
// `go run .` included, uses the real podman. Only when TRIVY_SCANNER_FAKE_PODMAN
// is set does a development build (one without -tags production) replay the
// recorded Trivy output in internal/trivy/fixtures, which is what the Go tests
// and the screenshot script use. Fake mode also turns off the live EPSS/KEV
// lookups so its output is deterministic and offline.
func newEngine() (trivy.Engine, Mode) {
	if !loadSettings().FakePodman {
		return nil, Mode{}
	}
	e := trivy.NewFixtureEngine()
	m := Mode{
		Fixtures: true,
		Detail: "Demo mode (" + fakePodmanFlag + " is set): scans replay recorded Trivy output for traefik, " +
			"not a live scan, and EPSS/KEV lookups are off.",
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
