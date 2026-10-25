package main

import (
	"testing"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

// The def tags are literals, so keep the two URL defaults in step with the real ones.
func TestEnvDocsDefaults(t *testing.T) {
	want := map[string]string{
		"TRIVY_SCANNER_EPSS_URL": trivy.DefaultEPSSURL,
		"TRIVY_SCANNER_KEV_URL":  trivy.DefaultKEVURL,
	}
	seen := 0
	for _, e := range envDocs() {
		if d, ok := want[e.Name]; ok {
			seen++
			if e.Default != d {
				t.Errorf("%s default = %q, want %q", e.Name, e.Default, d)
			}
		}
	}
	if seen != len(want) {
		t.Errorf("found %d of %d URL variables in envDocs", seen, len(want))
	}
}
