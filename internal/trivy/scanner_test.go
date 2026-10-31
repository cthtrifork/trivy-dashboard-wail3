package trivy

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const vulnReport = `{"Metadata":{"OS":{"Family":"debian","Name":"12.5"}},"Results":[{"Target":"nginx (debian 12.5)","Vulnerabilities":[
{"VulnerabilityID":"CVE-1","PkgName":"zlib","InstalledVersion":"1.0","Severity":"LOW","CVSS":{"nvd":{"V3Score":3.1}}},
{"VulnerabilityID":"CVE-2","PkgName":"openssl","InstalledVersion":"3.0","FixedVersion":"3.1","Severity":"CRITICAL","Title":"bad","CVSS":{"nvd":{"V3Score":9.8},"redhat":{"V3Score":8.1}}},
{"VulnerabilityID":"CVE-3","PkgName":"x","InstalledVersion":"1","Severity":"weird"}]}]}`

const sbom = `{"components":[{"type":"library","name":"zlib","version":"1.0","purl":"pkg:deb/zlib@1.0","licenses":[{"license":{"id":"Zlib"}}]},
{"type":"operating-system","name":"debian","version":"12.5"},
{"type":"library","name":"a","group":"g","licenses":[{"expression":"MIT OR Apache-2.0"}]}]}`

// fakePodman writes a script that mimics `podman run ... trivy image --format X`.
func fakePodman(t *testing.T, fail bool) string {
	dir := t.TempDir()
	body := "#!/bin/sh\n"
	if fail {
		body += "echo 'FATAL boom' >&2; exit 1\n"
	} else {
		body += `case "$*" in
*cyclonedx*) cat ` + filepath.Join(dir, "sbom.json") + ` ;;
*) echo "INFO scanning" >&2; cat ` + filepath.Join(dir, "vuln.json") + ` ;;
esac
echo "args: $*" >&2
`
	}
	os.WriteFile(filepath.Join(dir, "vuln.json"), []byte(vulnReport), 0o644)
	os.WriteFile(filepath.Join(dir, "sbom.json"), []byte(sbom), 0o644)
	p := filepath.Join(dir, "podman")
	os.WriteFile(p, []byte(body), 0o755)
	return p
}

func TestScan(t *testing.T) {
	var logs []string
	s := &Scanner{Podman: fakePodman(t, false), Log: func(l string) { logs = append(logs, l) }}
	res, err := s.Scan(context.Background(), ScanRequest{Image: " docker://nginx:1.27 ", IgnoreUnfixed: true, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Image != "nginx:1.27" || res.OS != "debian 12.5" {
		t.Fatalf("meta: %+v", res)
	}
	v := res.Vulnerabilities
	if len(v) != 3 || v[0].ID != "CVE-2" || v[0].Score != 8.1 || v[0].ScoreSource != "redhat" || v[2].Severity != "UNKNOWN" && v[1].Severity != "UNKNOWN" {
		t.Fatalf("vulns: %+v", v)
	}
	if res.SeverityCounts["CRITICAL"] != 1 || res.SeverityCounts["UNKNOWN"] != 1 {
		t.Fatalf("counts: %v", res.SeverityCounts)
	}
	if len(res.Components) != 3 || res.ComponentTypes["library"] != 2 || res.Components[0].Name != "a" || res.Components[0].Licenses[0] != "MIT OR Apache-2.0" {
		t.Fatalf("sbom: %+v", res.Components)
	}
	all := strings.Join(logs, "\n")
	for _, want := range []string{"--ignore-unfixed", "-e TRIVY_USERNAME", pinnedTrivyImage, "nginx:1.27"} {
		if !strings.Contains(all, want) {
			t.Errorf("podman args missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "TRIVY_PASSWORD=p") {
		t.Error("password leaked into args")
	}
}

func TestScanFailure(t *testing.T) {
	s := &Scanner{Podman: fakePodman(t, true)}
	_, err := s.Scan(context.Background(), ScanRequest{Image: "x"})
	if err == nil || !strings.Contains(err.Error(), "FATAL boom") {
		t.Fatalf("err = %v", err)
	}
	// scanner must be reusable after a failure
	if _, err := s.Scan(context.Background(), ScanRequest{Image: "-bad"}); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("err = %v", err)
	}
}

func TestDependencyGraph(t *testing.T) {
	res := &ScanResult{}
	vulns := `{"Results":[{"Target":"t","Vulnerabilities":[
{"VulnerabilityID":"CVE-A","PkgName":"libssl3","InstalledVersion":"3.0","Severity":"HIGH","PkgIdentifier":{"PURL":"pkg:deb/debian/libssl3@3.0"}},
{"VulnerabilityID":"CVE-B","PkgName":"lodash","InstalledVersion":"4.0","Severity":"CRITICAL","PkgIdentifier":{"PURL":"pkg:npm/lodash@4.0"}},
{"VulnerabilityID":"CVE-C","PkgName":"left-pad","InstalledVersion":"1.0","Severity":"LOW"}]}]}`
	if err := parseVulns([]byte(vulns), res); err != nil {
		t.Fatal(err)
	}
	bom := `{"metadata":{"component":{"bom-ref":"img"}},"components":[
{"bom-ref":"os","type":"operating-system","name":"debian","version":"12"},
{"bom-ref":"ssl","type":"library","name":"libssl3","version":"3.0","purl":"pkg:deb/debian/libssl3@3.0"},
{"bom-ref":"app","type":"application","name":"package-lock.json"},
{"bom-ref":"lo","type":"library","name":"lodash","version":"4.0","purl":"pkg:npm/lodash@4.0"},
{"bom-ref":"lp","type":"library","name":"left-pad","version":"1.0","purl":"pkg:npm/left-pad@1.0"},
{"bom-ref":"orphan","type":"library","name":"zzz","version":"1"}],
"dependencies":[{"ref":"img","dependsOn":["os","app"]},{"ref":"os","dependsOn":["ssl"]},
{"ref":"app","dependsOn":["lo"]},{"ref":"lo","dependsOn":["lp"]},{"ref":"lp","dependsOn":["lo"]}]}`
	if err := parseSBOM([]byte(bom), res); err != nil {
		t.Fatal(err)
	}
	n := res.DepNodes
	if got := strings.Join(res.DepRoots, ","); got != "app,orphan,os" { // by category, then name
		t.Fatalf("roots: %s", got)
	}
	if n["os"].Category != "OS" || n["ssl"].Category != "OS" || n["lo"].Category != "Application" {
		t.Fatalf("categories: %+v", n)
	}
	if n["ssl"].OwnCounts["HIGH"] != 1 || n["os"].TotalCounts["HIGH"] != 1 || n["os"].OwnCounts["HIGH"] != 0 {
		t.Fatalf("os counts: %+v %+v", n["ssl"], n["os"])
	}
	// name@version fallback + cycle safety: app -> lo -> lp -> lo
	if n["lp"].OwnCounts["LOW"] != 1 || n["app"].TotalCounts["CRITICAL"] != 1 || n["app"].TotalCounts["LOW"] != 1 {
		t.Fatalf("app counts: %+v", n["app"])
	}
	if n["lp"].TotalCounts["CRITICAL"] != 1 { // cycle: lp reaches lo
		t.Fatalf("lp: %+v", n["lp"])
	}
	if len(n["lo"].Parents) != 2 {
		t.Fatalf("lo parents: %v", n["lo"].Parents)
	}
}

func TestScanFlagsHideNoiseByDefault(t *testing.T) {
	for _, tc := range []struct {
		req  ScanRequest
		want string
	}{
		{ScanRequest{}, "will_not_fix,not_affected"},
		{ScanRequest{IgnoreStatus: []string{"not_affected"}}, "not_affected"},
		{ScanRequest{IgnoreStatus: []string{"end_of_life", "fix_deferred"}}, "end_of_life,fix_deferred"},
		{ScanRequest{IgnoreStatus: []string{}}, ""},
	} {
		if got := tc.req.ignoreStatus(); got != tc.want {
			t.Errorf("%+v: ignoreStatus = %q, want %q", tc.req, got, tc.want)
		}
	}
}

func TestRunArgsDisableTelemetryAndGoOffline(t *testing.T) {
	t.Setenv("CONTAINER_HOST", "unix:///run/podman/podman.sock")
	args, err := (&PodmanEngine{}).runArgs(TrivyJob{Image: "alpine:3"}, "n")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"--disable-telemetry", "--offline-scan", "--vuln-severity-source", "--skip-version-check"} {
		if !slices.Contains(args, f) {
			t.Errorf("missing %s in %v", f, args)
		}
	}
}

// Real data from actions/actions-runner:2.338.2 (CVE-2026-59873): Trivy took CRITICAL from GHSA while
// Red Hat, NVD and the distros said HIGH and every CVSS score was 7.5. Severity must follow the score's
// source (Red Hat) for language packages, so the finding is HIGH and is not boosted by the outlier.
func TestSeverityFollowsScoreSource(t *testing.T) {
	const vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
	report := func(class string, sev string, vendor string, cvss string) []byte {
		return []byte(`{"Results":[{"Target":"t","Class":"` + class + `","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-59873","PkgName":"tar","InstalledVersion":"6.2.1","FixedVersion":"7.5.19","Severity":"` + sev + `",` +
			`"VendorSeverity":` + vendor + `,"CVSS":` + cvss + `}]}]}`)
	}
	scores := `{"ghsa":{"V3Vector":"` + vec + `","V3Score":7.5},"nvd":{"V3Vector":"` + vec + `","V3Score":7.5},"redhat":{"V3Vector":"` + vec + `","V3Score":7.5}}`
	vendors := `{"ghsa":4,"nvd":3,"redhat":3,"alma":3}`
	scan := func(data []byte) Vulnerability {
		res := &ScanResult{}
		if err := parseVulns(data, res); err != nil || len(res.Vulnerabilities) != 1 {
			t.Fatalf("parse: %v %+v", err, res)
		}
		return res.Vulnerabilities[0]
	}

	lang := scan(report("lang-pkgs", "CRITICAL", vendors, scores))
	if lang.Severity != "HIGH" || lang.ScoreSource != "redhat" {
		t.Errorf("language package: severity %s from score source %s, want HIGH from redhat", lang.Severity, lang.ScoreSource)
	}
	// It must now rank like every other HIGH 7.5, not 5 points above them.
	high := scan(report("lang-pkgs", "HIGH", vendors, scores))
	if lang.Priority != high.Priority {
		t.Errorf("priority %d, want %d (same as a plain HIGH)", lang.Priority, high.Priority)
	}
	counts := &ScanResult{}
	_ = parseVulns(report("lang-pkgs", "CRITICAL", vendors, scores), counts)
	if counts.SeverityCounts["HIGH"] != 1 || counts.SeverityCounts["CRITICAL"] != 0 {
		t.Errorf("severity counts follow the aligned severity: %v", counts.SeverityCounts)
	}

	// OS packages keep the distribution's own severity, even when it differs from the CVSS band.
	if os := scan(report("os-pkgs", "LOW", `{"ubuntu":1,"nvd":4,"redhat":3}`, scores)); os.Severity != "LOW" {
		t.Errorf("os package: severity %s, want the distro's LOW", os.Severity)
	}
	// The score's source has no severity: Trivy's stays.
	if v := scan(report("lang-pkgs", "CRITICAL", `{"ghsa":4}`, scores)); v.Severity != "CRITICAL" {
		t.Errorf("no severity from the score source: got %s, want Trivy's CRITICAL", v.Severity)
	}
	// No score at all: Trivy's severity stays.
	if v := scan(report("lang-pkgs", "MEDIUM", `{"ghsa":2}`, `{}`)); v.Severity != "MEDIUM" {
		t.Errorf("no score: got %s, want MEDIUM", v.Severity)
	}
}

// ScoreEstimate is the one default for a missing score, carried to the UI: the severity band's
// floor, and only when no score was published.
func TestScoreEstimate(t *testing.T) {
	res := &ScanResult{}
	data := []byte(`{"Results":[{"Target":"t","Class":"lang-pkgs","Vulnerabilities":[
	 {"VulnerabilityID":"A","PkgName":"a","Severity":"HIGH"},
	 {"VulnerabilityID":"B","PkgName":"b","Severity":"HIGH","VendorSeverity":{"nvd":3},"CVSS":{"nvd":{"V3Score":7.5}}},
	 {"VulnerabilityID":"C","PkgName":"c","Severity":"UNKNOWN"}]}]}`)
	if err := parseVulns(data, res); err != nil {
		t.Fatal(err)
	}
	got := map[string]Vulnerability{}
	for _, v := range res.Vulnerabilities {
		got[v.ID] = v
	}
	if got["A"].ScoreEstimate != 7 || got["B"].ScoreEstimate != 0 || got["C"].ScoreEstimate != 0 {
		t.Errorf("estimates A=%v B=%v C=%v, want 7, 0, 0", got["A"].ScoreEstimate, got["B"].ScoreEstimate, got["C"].ScoreEstimate)
	}
	// The rules score from the same number the UI shows.
	if a := got["A"]; effectiveScore(&a) != a.ScoreEstimate {
		t.Errorf("effectiveScore %v differs from the estimate %v", effectiveScore(&a), a.ScoreEstimate)
	}
}
