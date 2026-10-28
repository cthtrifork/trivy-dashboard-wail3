package app

import (
	"strings"
	"testing"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/selfupdate"
)

// A build that does not identify as a release must never be able to replace itself:
// the updater would treat "dev" as older than every release (see selfupdate.Enabled).
func TestNonReleaseBuildsCannotUpdate(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	for _, v := range []string{"dev", "", "ci-0123456", "v1.2", "latest"} {
		version = v
		s := &ScanService{}
		InitUpdater(s, nil) // never reaches the updater, so no app is needed

		info := s.UpdateInfo()
		if info.Enabled || info.Reason == "" || info.Version != v {
			t.Errorf("version %q: %+v", v, info)
		}
		for name, err := range map[string]error{
			"CheckForUpdates": func() error { _, err := s.CheckForUpdates(); return err }(),
			"InstallUpdate":   s.InstallUpdate(),
			"RestartToUpdate": s.RestartToUpdate(),
		} {
			if err == nil || !strings.Contains(err.Error(), "development build") {
				t.Errorf("version %q: %s() = %v, want the reason it is disabled", v, name, err)
			}
		}
	}
}

// A build with no update signing key (the repository before docs/releasing.md is followed) must have no
// release feed at all, not fall back to unsigned releases.
func TestNoUpdateProviderWithoutSigningKey(t *testing.T) {
	if _, err := selfupdate.SigningKey(); err == nil {
		t.Skip("a signing key is committed")
	}
	if p, err := newUpdateProvider(); err == nil || p != nil || !strings.Contains(err.Error(), "signing key") {
		t.Errorf("newUpdateProvider() = %v, %v", p, err)
	}
}
