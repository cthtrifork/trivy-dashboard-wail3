package trivy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanFixture builds trivy JSON for the fake podman: pkgs are "name version vulnIDs..." lines.
func scanFixture(os_ string, pkgs ...[]string) (vulnJSON, sbomJSON string) {
	var vs, cs, deps []string
	for i, p := range pkgs {
		name, ver := p[0], p[1]
		purl := fmt.Sprintf("pkg:deb/debian/%s@%s", name, ver)
		cs = append(cs, fmt.Sprintf(`{"bom-ref":"c%d","type":"library","name":%q,"version":%q,"purl":%q}`, i, name, ver, purl))
		deps = append(deps, fmt.Sprintf("%q", fmt.Sprintf("c%d", i)))
		for _, id := range p[2:] {
			sev := "HIGH"
			if strings.HasSuffix(id, "C") {
				sev = "CRITICAL"
			}
			vs = append(vs, fmt.Sprintf(`{"VulnerabilityID":%q,"PkgName":%q,"InstalledVersion":%q,"Severity":%q,"PkgIdentifier":{"PURL":%q}}`, id, name, ver, sev, purl))
		}
	}
	// trivy names the target after the image ("app:1.0 (debian 12.4)"), so it differs per tag.
	vulnJSON = fmt.Sprintf(`{"Metadata":{"OS":{"Family":"debian","Name":%q}},"Results":[{"Target":"app:%s (debian %s)","Vulnerabilities":[%s]}]}`, os_, os_, os_, strings.Join(vs, ","))
	sbomJSON = fmt.Sprintf(`{"metadata":{"component":{"bom-ref":"img"}},"components":[%s],"dependencies":[{"ref":"img","dependsOn":[%s]}]}`, strings.Join(cs, ","), strings.Join(deps, ","))
	return
}

func result(t *testing.T, os_ string, pkgs ...[]string) *ScanResult {
	v, s := scanFixture(os_, pkgs...)
	r := &ScanResult{Image: "app"}
	if err := parseVulns([]byte(v), r); err != nil {
		t.Fatal(err)
	}
	if err := parseSBOM([]byte(s), r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDiff(t *testing.T) {
	a := result(t, "12.4",
		[]string{"openssl", "3.0.1", "CVE-1C", "CVE-2"}, // upgraded: CVE-1C fixed, CVE-2 remains, CVE-3 appears
		[]string{"zlib", "1.2", "CVE-4"},                // removed pkg
		[]string{"bash", "5.2", "CVE-5"},                // unchanged
		[]string{"curl", "8.0"},                         // upgraded & clean
		[]string{"gz", "2.0"},                           // downgraded
	)
	b := result(t, "12.5",
		[]string{"openssl", "3.0.9", "CVE-2", "CVE-3"},
		[]string{"bash", "5.2", "CVE-5", "CVE-6"}, // CVE-6 newly disclosed on same version
		[]string{"curl", "8.1"},
		[]string{"gz", "1.9"},
		[]string{"newlib", "1.0", "CVE-7C"}, // new package
	)
	d := Diff(a, b)

	by := map[string]VulnChange{}
	for _, v := range d.Vulns {
		by[v.Vuln.ID] = v
	}
	check := func(id, change, cause string) {
		t.Helper()
		v, ok := by[id]
		if !ok || v.Change != change || !strings.Contains(v.Cause, cause) {
			t.Errorf("%s: %+v (want %s / %q)", id, v, change, cause)
		}
	}
	check("CVE-1C", "removed", "fixed by changing 3.0.1 → 3.0.9")
	check("CVE-2", "unchanged", "")
	check("CVE-3", "added", "package changed 3.0.1 → 3.0.9")
	check("CVE-4", "removed", "package was removed")
	check("CVE-5", "unchanged", "")
	check("CVE-6", "added", "newly disclosed")
	check("CVE-7C", "added", "new in the target")

	if d.Added["HIGH"] != 2 || d.Added["CRITICAL"] != 1 || d.Removed["CRITICAL"] != 1 || d.Removed["HIGH"] != 1 || d.Unchanged["HIGH"] != 2 {
		t.Errorf("counts: +%v -%v =%v", d.Added, d.Removed, d.Unchanged)
	}
	if d.Vulns[0].Change != "added" || d.Vulns[0].Vuln.ID != "CVE-7C" { // added first, highest priority first
		t.Errorf("order: %+v", d.Vulns[0])
	}

	pk := map[string]PkgChange{}
	for _, p := range d.Packages {
		pk[p.Name] = p
	}
	if pk["openssl"].Change != "upgraded" || pk["openssl"].VulnsA != 2 || pk["openssl"].VulnsB != 2 ||
		pk["zlib"].Change != "removed" || pk["newlib"].Change != "added" || pk["gz"].Change != "downgraded" ||
		pk["curl"].Change != "upgraded" || pk["bash"].Change != "" {
		t.Errorf("packages: %+v", pk)
	}
	if d.A.OS != "debian 12.4" || d.B.OS != "debian 12.5" || d.A.Total != 4 || d.B.Total != 5 || d.B.Packages != 5 {
		t.Errorf("sides: %+v %+v", d.A, d.B)
	}
	if !strings.Contains(d.Verdict, "worse: 1 more") || !strings.Contains(d.Verdict, "Critical+High") {
		t.Errorf("verdict: %s", d.Verdict)
	}
	if v := Diff(a, a).Verdict; !strings.HasPrefix(v, "No vulnerability differences") {
		t.Errorf("same: %s", v)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.10", "1.9", 1}, {"3.0.9", "3.0.1", 1}, {"1.2", "1.2", 0}, {"1.2", "1.2.1", -1}, {"2.0", "latest", 1}, {"5.2.15-2", "5.2.9-1", 1}} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareEndToEnd(t *testing.T) {
	dir := t.TempDir()
	va, sa := scanFixture("12.4", []string{"openssl", "3.0.1", "CVE-1C"})
	vb, sb := scanFixture("12.5", []string{"openssl", "3.0.9"})
	for name, body := range map[string]string{"vuln-1.0": va, "sbom-1.0": sa, "vuln-2.0": vb, "sbom-2.0": sb} {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	}
	script := `#!/bin/sh
for last; do :; done
tag=${last##*:}
case "$*" in
*"search --list-tags"*) printf 'TAG\n1.9\n2.0\n1.10\n2.0\nlatest\n' ;;
*cyclonedx*) cat ` + dir + `/sbom-$tag ;;
*) cat ` + dir + `/vuln-$tag ;;
esac
`
	p := filepath.Join(dir, "podman")
	os.WriteFile(p, []byte(script), 0o755)

	var logs []string
	s := &Scanner{Podman: p, Log: func(l string) { logs = append(logs, l) }}
	d, err := s.Compare(context.Background(), CompareRequest{Repo: "ghcr.io/acme/app:ignored", TagA: "1.0", TagB: "2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if d.A.Ref != "ghcr.io/acme/app:1.0" || d.B.Ref != "ghcr.io/acme/app:2.0" || sum(d.Removed) != 1 || sum(d.Added) != 0 || !strings.Contains(d.Verdict, "better") {
		t.Fatalf("%+v", d)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "=== Target: ghcr.io/acme/app:2.0 ===") {
		t.Errorf("logs: %v", logs)
	}

	for _, bad := range []CompareRequest{{Repo: "x", TagA: "1", TagB: "1"}, {Repo: "x", TagA: "1"}, {Repo: "x", TagA: "1", TagB: "--bad"}, {TagA: "1", TagB: "2"}} {
		if _, err := s.Compare(context.Background(), bad); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
	if r, err := tagRef("a/b", "sha256:abc"); err != nil || r != "a/b@sha256:abc" {
		t.Errorf("digest ref: %s %v", r, err)
	}

	tags, err := s.ListTags(context.Background(), "ghcr.io/acme/app:whatever")
	if err != nil || strings.Join(tags, ",") != "2.0,1.10,1.9,latest" {
		t.Fatalf("tags: %v %v", tags, err)
	}
	// the slot must be free again after Compare
	if _, err := s.Scan(context.Background(), ScanRequest{Image: "ghcr.io/acme/app:1.0"}); err != nil {
		t.Fatal(err)
	}
}

func TestQualifyRepo(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                       "docker.io/library/nginx",
		"traefik":                     "docker.io/library/traefik",
		"aquasec/trivy":               "docker.io/aquasec/trivy",
		"docker.io/library/nginx":     "docker.io/library/nginx",
		"ghcr.io/acme/app":            "ghcr.io/acme/app",
		"quay.io/fedora/fedora":       "quay.io/fedora/fedora",
		"localhost/app":               "localhost/app",
		"localhost:5000/team/app":     "localhost:5000/team/app",
		"registry.example.com:8443/a": "registry.example.com:8443/a",
	} {
		if got := qualifyRepo(in); got != want {
			t.Errorf("qualifyRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

// recordingEngine captures what ListTags is asked for.
type recordingEngine struct {
	Engine
	asked string
}

func (r *recordingEngine) ListTags(_ context.Context, repo string) ([]string, error) {
	r.asked = repo
	return []string{"1.0"}, nil
}

func TestListTagsAsksForAnExplicitRegistry(t *testing.T) {
	rec := &recordingEngine{}
	s := &Scanner{Engine: rec}
	if _, err := s.ListTags(context.Background(), "traefik:3.7.13"); err != nil {
		t.Fatal(err)
	}
	if rec.asked != "docker.io/library/traefik" { // tag stripped, registry made explicit
		t.Errorf("engine was asked for %q", rec.asked)
	}
}
