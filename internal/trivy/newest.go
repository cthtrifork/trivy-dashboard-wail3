package trivy

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	newestTTL   = 6 * time.Hour
	newestRetry = 10 * time.Minute
	// newestLookup bounds the `podman search --list-tags` call.
	newestLookup = 15 * time.Second
)

// releaseTag matches a plain release tag such as 0.76.1 (no -amd64, -rc or latest).
var releaseTag = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

// newest caches the newest Trivy release tag. defaultTrivyImage stays the fallback when the
// registry cannot be reached, so scans keep working offline.
var newest struct {
	sync.Mutex
	tag     string
	expires time.Time
}

// fetchNewestTag lists the tags of the default repository through the engine (podman search
// --list-tags, like the tag picker) and returns the newest release. Tests replace it.
var fetchNewestTag = func(ctx context.Context, e Engine) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, newestLookup)
	defer cancel()
	tags, err := e.ListTags(ctx, defaultTrivyRepo)
	if err != nil {
		return "", err
	}
	return newestRelease(tags), nil
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

// newestRelease returns the highest X.Y.Z tag in names, or "" if there is none.
func newestRelease(names []string) string {
	best, bestV := "", [3]int{}
	for _, n := range names {
		m := releaseTag.FindStringSubmatch(strings.TrimSpace(n))
		if m == nil {
			continue
		}
		var v [3]int
		for i := range v {
			v[i], _ = strconv.Atoi(m[i+1])
		}
		if best == "" || v[0] > bestV[0] || v[0] == bestV[0] && (v[1] > bestV[1] || v[1] == bestV[1] && v[2] > bestV[2]) {
			best, bestV = n, v
		}
	}
	return best
}
