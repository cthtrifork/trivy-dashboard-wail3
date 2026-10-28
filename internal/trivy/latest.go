package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// latestTagsURL lists the tags of defaultTrivyRepo on Docker Hub, newest push first.
	latestTagsURL = "https://hub.docker.com/v2/repositories/aquasec/trivy/tags?page_size=100&ordering=last_updated"
	latestTTL     = 6 * time.Hour
	latestRetry   = 10 * time.Minute
)

// releaseTag matches a plain release tag such as 0.76.1 (no -amd64, -rc or latest).
var releaseTag = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

// latest caches the newest Trivy release tag. defaultTrivyImage stays the fallback when Docker
// Hub cannot be reached, so scans keep working offline.
var latest struct {
	sync.Mutex
	tag     string
	expires time.Time
}

// fetchLatestTag is replaced in tests.
var fetchLatestTag = fetchLatestFromHub

// currentDefault returns the default image from the cache, or the pinned fallback.
func currentDefault() string {
	latest.Lock()
	defer latest.Unlock()
	if latest.tag != "" {
		return defaultTrivyRepo + ":" + latest.tag
	}
	return defaultTrivyImage
}

// refreshLatest looks up the newest release tag when the cached one has expired. A failed lookup
// is retried after latestRetry and leaves the previous (or pinned) version in place.
func refreshLatest(ctx context.Context) {
	latest.Lock()
	if time.Now().Before(latest.expires) {
		latest.Unlock()
		return
	}
	latest.Unlock()
	tag, err := fetchLatestTag(ctx)
	latest.Lock()
	defer latest.Unlock()
	if err != nil || tag == "" {
		latest.expires = time.Now().Add(latestRetry)
		return
	}
	latest.tag, latest.expires = tag, time.Now().Add(latestTTL)
}

func fetchLatestFromHub(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestTagsURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("docker hub: %s", resp.Status)
	}
	var page struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return "", err
	}
	names := make([]string, len(page.Results))
	for i, r := range page.Results {
		names[i] = r.Name
	}
	return newestRelease(names), nil
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
