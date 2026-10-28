package trivy

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func resetLatest(t *testing.T) {
	t.Helper()
	old := fetchLatestTag
	t.Cleanup(func() {
		fetchLatestTag = old
		latest.Lock()
		latest.tag, latest.expires = "", time.Time{}
		latest.Unlock()
	})
	latest.Lock()
	latest.tag, latest.expires = "", time.Time{}
	latest.Unlock()
}

func TestNewestRelease(t *testing.T) {
	got := newestRelease([]string{"latest", "0.9.0", "0.76.1-amd64", "0.76.1", "0.100.2", "0.76.10", "0.77.0-rc1"})
	if got != "0.100.2" {
		t.Errorf("newest = %q", got)
	}
	if newestRelease([]string{"latest", "0.1.0-arm64"}) != "" {
		t.Error("no release tag should give an empty result")
	}
}

func TestDefaultImageFollowsLatestAndFallsBack(t *testing.T) {
	resetLatest(t)
	fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("offline") }
	refreshLatest(context.Background())
	if DefaultTrivyImage() != defaultTrivyImage {
		t.Errorf("offline must use the pinned fallback, got %q", DefaultTrivyImage())
	}
	latest.Lock()
	latest.expires = time.Time{}
	latest.Unlock()
	fetchLatestTag = func(context.Context) (string, error) { return "9.9.9", nil }
	refreshLatest(context.Background())
	if want := defaultTrivyRepo + ":9.9.9"; DefaultTrivyImage() != want {
		t.Errorf("default = %q, want %q", DefaultTrivyImage(), want)
	}
	calls := 0
	fetchLatestTag = func(context.Context) (string, error) { calls++; return "1.0.0", nil }
	refreshLatest(context.Background())
	if calls != 0 {
		t.Error("a fresh cache must not trigger another lookup")
	}
}

// TestMain keeps every test off the network: the Docker Hub lookup always fails, so the pinned
// fallback is the default image.
func TestMain(m *testing.M) {
	fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("no network in tests") }
	os.Exit(m.Run())
}
