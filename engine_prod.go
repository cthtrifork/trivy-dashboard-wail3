//go:build production

package main

import "github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"

// newEngine returns nil, which makes the scanner use real podman. Production
// builds contain no fixture data and no code path that could replay it.
func newEngine() (trivy.Engine, Mode) {
	return nil, Mode{}
}
