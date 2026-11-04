package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A build that does not identify as a release must never be able to replace itself:
// the updater would treat "dev" as older than every release (see selfupdate.Enabled).
func TestNonReleaseBuildsCannotUpdate(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	for _, v := range []string{"dev", "", "ci-0123456", "1.2.3", "latest"} {
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

// A release build in a directory the updater cannot write to (a package in /usr/bin, the
// image of an immutable OS) explains itself up front, with the way to update it.
func TestReadOnlyInstallExplainsItself(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	t.Setenv("APPIMAGE", "")
	oldExe := executablePath
	t.Cleanup(func() { executablePath = oldExe })

	ro := t.TempDir()
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	executablePath = func() (string, error) { return filepath.Join(ro, "trivy-scanner"), nil }

	reason := readOnlyReason()
	if !strings.Contains(reason, "read-only") || !strings.Contains(reason, "bootc upgrade") || !strings.Contains(reason, ro) {
		t.Errorf("read-only install: %q", reason)
	}

	writable := t.TempDir()
	executablePath = func() (string, error) { return filepath.Join(writable, "trivy-scanner"), nil }
	if reason := readOnlyReason(); reason != "" {
		t.Errorf("writable install reported as read-only: %q", reason)
	}
}
