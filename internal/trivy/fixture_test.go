//go:build !production

package trivy

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests replay the recorded Trivy output in fixtures/ (real scans of
// traefik 3.7.13 and 3.7.16), so they also guard the fixtures themselves.
// If the fixtures are re-recorded, update the pinned numbers below.

func fixtureScanner() *Scanner {
	e := NewFixtureEngine()
	e.Delay = 0
	return &Scanner{Engine: e}
}

func TestFixtureFilesPresent(t *testing.T) {
	for _, name := range []string{"traefik_3.7.13.json", "trivy_3.7.16.sbom.json", "traefik_3.7.16.json"} {
		if _, err := fs.Stat(NewFixtureEngine().FS, name); err != nil {
			t.Errorf("fixture %s is missing: %v", name, err)
		}
	}
}

func TestFixtureScanOldVersion(t *testing.T) {
	res, err := fixtureScanner().Scan(context.Background(), ScanRequest{Image: "docker.io/library/traefik:3.7.13"})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Vulnerabilities); got != 29 {
		t.Fatalf("vulnerabilities = %d, want 29", got)
	}
	want := map[string]int{"CRITICAL": 0, "HIGH": 5, "MEDIUM": 16, "LOW": 5, "UNKNOWN": 3}
	for sev, n := range want {
		if res.SeverityCounts[sev] != n {
			t.Errorf("%s = %d, want %d (all: %v)", sev, res.SeverityCounts[sev], n, res.SeverityCounts)
		}
	}
	if res.OS != "alpine 3.24.2" || len(res.Components) != 378 {
		t.Errorf("os=%q components=%d", res.OS, len(res.Components))
	}
	if !strings.HasPrefix(res.ProductPURL, "pkg:oci/traefik@sha256%3A") {
		t.Errorf("product purl: %s", res.ProductPURL)
	}
	// Priority ordering and rule engine ran on real data.
	top := res.Vulnerabilities[0]
	if top.Priority == 0 || top.Attack == "" || len(top.Reasons) == 0 || top.Tier == "" {
		t.Errorf("top finding not assessed: %+v", top)
	}
	for i := 1; i < len(res.Vulnerabilities); i++ {
		if res.Vulnerabilities[i].Priority > res.Vulnerabilities[i-1].Priority {
			t.Fatalf("findings not sorted by priority at %d", i)
		}
	}
}

func TestFixtureDependencyGraph(t *testing.T) {
	res, err := fixtureScanner().Scan(context.Background(), ScanRequest{Image: "traefik:3.7.16"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.DepNodes) != 380 || len(res.DepRoots) != 2 {
		t.Fatalf("nodes=%d roots=%d", len(res.DepNodes), len(res.DepRoots))
	}
	cats := map[string]int{}
	for _, n := range res.DepNodes {
		cats[n.Category]++
	}
	if cats["OS"] != 19 || cats["Application"] != 361 {
		t.Errorf("categories: %v", cats)
	}
	// Every finding must attach to a component (purl match against the real SBOM).
	attached := 0
	for _, n := range res.DepNodes {
		attached += len(n.Own)
	}
	if attached != len(res.Vulnerabilities) || attached != 1 {
		t.Errorf("attached %d of %d findings", attached, len(res.Vulnerabilities))
	}
	// The one finding bubbles up to the application root, and the OS root is clean.
	for _, r := range res.DepRoots {
		n := res.DepNodes[r]
		switch n.Type {
		case "application":
			if n.TotalCounts["UNKNOWN"] != 1 {
				t.Errorf("application root counts: %v", n.TotalCounts)
			}
		case "operating-system":
			if len(n.TotalCounts) != 0 || len(n.Children) == 0 {
				t.Errorf("os root: %+v", n)
			}
		}
	}
}

func TestFixtureCompare(t *testing.T) {
	d, err := fixtureScanner().Compare(context.Background(), CompareRequest{Repo: "docker.io/library/traefik", TagA: "3.7.13", TagB: "3.7.16"})
	if err != nil {
		t.Fatal(err)
	}
	if d.A.OS != "alpine 3.24.2" || d.B.OS != "alpine 3.24.3" || d.A.Total != 29 || d.B.Total != 1 {
		t.Fatalf("sides: %+v %+v", d.A, d.B)
	}
	if sum(d.Added) != 0 || sum(d.Removed) != 28 || sum(d.Unchanged) != 1 || d.Removed["HIGH"] != 5 {
		t.Errorf("added %v removed %v unchanged %v", d.Added, d.Removed, d.Unchanged)
	}
	if !strings.Contains(d.Verdict, "better") || !strings.Contains(d.Verdict, "Critical+High: 5 → 0") {
		t.Errorf("verdict: %s", d.Verdict)
	}
	// Removals are explained by the package upgrade that fixed them.
	explained := 0
	for _, v := range d.Vulns {
		if v.Change == "removed" && v.Vuln.Package == "golang.org/x/net" && strings.Contains(v.Cause, "v0.58.0 → v0.60.0") {
			explained++
		}
	}
	if explained == 0 {
		t.Error("no x/net removal explained by its upgrade")
	}
	kinds := map[string]int{}
	for _, p := range d.Packages {
		kinds[p.Change]++
	}
	if kinds["upgraded"] != 95 || kinds["added"] != 4 || kinds["removed"] != 2 || kinds["downgraded"] != 1 {
		t.Errorf("package changes: %v", kinds)
	}
}

func TestFixtureTagResolution(t *testing.T) {
	s := fixtureScanner()
	for image, wantOS := range map[string]string{
		"traefik:3.7.13":                "alpine 3.24.2",
		"traefik:v3.7.13":               "alpine 3.24.2",
		"ghcr.io/acme/traefik:3.7.16":   "alpine 3.24.3",
		"traefik:3.7":                   "alpine 3.24.3", // newest 3.7.x
		"traefik:latest":                "alpine 3.24.3",
		"traefik":                       "alpine 3.24.3", // no tag means latest
		"localhost:5000/traefik:3.7.13": "alpine 3.24.2", // registry port is not a tag
	} {
		res, err := s.Scan(context.Background(), ScanRequest{Image: image})
		if err != nil {
			t.Errorf("%s: %v", image, err)
			continue
		}
		if res.OS != wantOS {
			t.Errorf("%s resolved to %q, want %q", image, res.OS, wantOS)
		}
	}

	_, err := s.Scan(context.Background(), ScanRequest{Image: "nginx:1.27"})
	if err == nil || !strings.Contains(err.Error(), "3.7.16, 3.7.13") || !strings.Contains(err.Error(), "TRIVY_SCANNER_FAKE_PODMAN") {
		t.Errorf("unknown tag error should list versions and the escape hatch: %v", err)
	}

	tags, err := s.ListTags(context.Background(), "traefik")
	if err != nil || strings.Join(tags, ",") != "3.7.16,3.7.13,latest" {
		t.Errorf("tags: %v %v", tags, err)
	}
	if v, err := s.Version(); err != nil || !strings.Contains(v, "demo mode") {
		t.Errorf("version should announce demo mode: %q %v", v, err)
	}
}

func TestFixtureIgnoreUnfixed(t *testing.T) {
	res, err := fixtureScanner().Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13", IgnoreUnfixed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vulnerabilities) != 28 { // the one persistent finding has no fix
		t.Errorf("with --ignore-unfixed: %d findings", len(res.Vulnerabilities))
	}
	for _, v := range res.Vulnerabilities {
		if v.Fixed == "" {
			t.Errorf("unfixed finding survived: %s", v.ID)
		}
	}
}

func TestFixtureSBOMFallback(t *testing.T) {
	set, err := NewFixtureEngine().index()
	if err != nil {
		t.Fatal(err)
	}
	if set.sbomFor("3.7.13") != "traefik_3.7.13.sbom.json" || set.sbomFor("3.7.16") != "trivy_3.7.16.sbom.json" {
		t.Errorf("exact matches: %q %q", set.sbomFor("3.7.13"), set.sbomFor("3.7.16"))
	}
	if got := set.sbomFor("3.7.14"); got != "traefik_3.7.13.sbom.json" { // newest at or below
		t.Errorf("3.7.14 -> %s", got)
	}
	if got := set.sbomFor("3.6.0"); got != "traefik_3.7.13.sbom.json" { // nothing below: oldest
		t.Errorf("3.6.0 -> %s", got)
	}
}

// A real-world OpenVEX file (versionless subcomponent PURLs) is applied to the
// recorded scan: zlib, musl + musl-utils, stdlib and (no subcomponents) all four
// otel packages match; the docker/cli statement matches nothing and is skipped.
func TestImportOpenVEXAgainstFixture(t *testing.T) {
	res, err := fixtureScanner().Scan(context.Background(), ScanRequest{Image: "docker.io/library/traefik:3.7.13"})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("testdata/traefik-vex.json")
	if err != nil {
		t.Fatal(err)
	}
	entries, rep, err := ParseOpenVEX(doc, res.Vulnerabilities)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 8 || rep.Imported != 8 || rep.Skipped != 1 {
		t.Fatalf("entries=%d report=%+v", len(entries), rep)
	}
	for _, e := range entries {
		if e.Status != "not_affected" || e.Key == "" || e.PURL == "" || e.Updated == "" {
			t.Errorf("bad entry %+v", e)
		}
	}
	st := &VEXStore{Path: filepath.Join(t.TempDir(), "vex.json")}
	if err := st.SetMany("docker.io/library/traefik:3.7.16", entries); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.List("docker.io/library/traefik:3.7.13"); len(got) != len(entries) {
		t.Fatalf("stored %d, want %d", len(got), len(entries))
	}
	if _, _, err := ParseOpenVEX([]byte(`{"statements":[]}`), res.Vulnerabilities); err == nil {
		t.Error("non-OpenVEX document should fail")
	}
}

func TestPURLMatching(t *testing.T) {
	v := Vulnerability{ID: "CVE-1", PURL: "pkg:apk/alpine/zlib@1.3.1-r2?arch=x86_64&distro=3.22.2"}
	for sub, want := range map[string]bool{
		"pkg:apk/alpine/zlib":          true,
		"pkg:apk/alpine/zlib@1.3.1-r2": true,
		"pkg:apk/alpine/zlib@1.2.0":    false,
		"pkg:apk/alpine/zlib-dev":      false,
		"pkg:golang/stdlib":            false,
	} {
		if got := anyPURLMatches([]string{sub}, v); got != want {
			t.Errorf("%s: got %v", sub, got)
		}
	}
}
