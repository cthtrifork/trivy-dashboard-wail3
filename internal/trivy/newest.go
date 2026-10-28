package trivy

import (
	"context"
	"sync"
	"time"
)

const (
	newestTTL   = 6 * time.Hour
	newestRetry = 10 * time.Minute
	// newestLookup bounds the `podman search --list-tags` call.
	newestLookup = 15 * time.Second
)

// newest caches the newest Trivy release tag. defaultTrivyImage stays the fallback when the
// registry cannot be reached, so scans keep working offline.
var newest struct {
	sync.Mutex
	tag     string
	expires time.Time
}

// fetchNewestTag asks Scanner.LatestTag (the tag picker's semver logic over the engine's
// `podman search --list-tags`) for the newest plain version of the default repository. Tests
// replace it.
var fetchNewestTag = func(ctx context.Context, e Engine) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, newestLookup)
	defer cancel()
	return (&Scanner{Engine: e}).LatestTag(ctx, defaultTrivyRepo, "")
}

// currentDefault returns the default image from the cache, or the pinned fallback.
func currentDefault() string {
	newest.Lock()
	defer newest.Unlock()
	if newest.tag != "" {
		return defaultTrivyRepo + ":" + newest.tag
	}
	return defaultTrivyImage
}

// refreshNewest looks up the newest release tag when the cached one has expired. A failed lookup
// is retried after newestRetry and leaves the previous (or pinned) version in place.
func refreshNewest(ctx context.Context, e Engine) {
	newest.Lock()
	if time.Now().Before(newest.expires) {
		newest.Unlock()
		return
	}
	newest.Unlock()
	tag, err := fetchNewestTag(ctx, e)
	newest.Lock()
	defer newest.Unlock()
	if err != nil || tag == "" {
		newest.expires = time.Now().Add(newestRetry)
		return
	}
	newest.tag, newest.expires = tag, time.Now().Add(newestTTL)
}
