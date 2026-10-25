//go:build production

package main

import (
	"log"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

// newEngine returns nil, which makes the scanner use real podman. Production
// builds contain no fixture data and no code path that could replay it, so the
// fake-podman flag cannot do anything here; say so rather than ignore it silently.
func newEngine() (trivy.Engine, Mode) {
	if loadSettings().FakePodman {
		log.Print("trivy-scanner: TRIVY_SCANNER_FAKE_PODMAN is ignored: this is a production build and always uses podman")
	}
	return nil, Mode{}
}
