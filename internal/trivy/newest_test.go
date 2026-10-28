package trivy

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func resetNewest(t *testing.T) {
	t.Helper()
	old := fetchNewestTag
	t.Cleanup(func() {
		fetchNewestTag = old
		newest.Lock()
		newest.tag, newest.expires = "", time.Time{}
		newest.Unlock()
	})
	newest.Lock()
	newest.tag, newest.expires = "", time.Time{}
	newest.Unlock()
}

func TestDefaultImageFollowsLatestAndFallsBack(t *testing.T) {
	resetNewest(t)
	fetchNewestTag = func(context.Context, Engine) (string, error) { return "", errors.New("offline") }
	refreshNewest(context.Background(), nil)
	if DefaultTrivyImage() != defaultTrivyImage {
		t.Errorf("offline must use the pinned fallback, got %q", DefaultTrivyImage())
	}
	newest.Lock()
	newest.expires = time.Time{}
	newest.Unlock()
	fetchNewestTag = func(context.Context, Engine) (string, error) { return "9.9.9", nil }
	refreshNewest(context.Background(), nil)
	if want := defaultTrivyRepo + ":9.9.9"; DefaultTrivyImage() != want {
		t.Errorf("default = %q, want %q", DefaultTrivyImage(), want)
	}
	calls := 0
	fetchNewestTag = func(context.Context, Engine) (string, error) { calls++; return "1.0.0", nil }
	refreshNewest(context.Background(), nil)
	if calls != 0 {
		t.Error("a fresh cache must not trigger another lookup")
	}
}

// TestMain keeps every test off the network: the lookup always fails, so the pinned
// fallback is the default image.
func TestMain(m *testing.M) {
	fetchNewestTag = func(context.Context, Engine) (string, error) { return "", errors.New("no network in tests") }
	os.Exit(m.Run())
}
