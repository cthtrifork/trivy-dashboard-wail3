package trivy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAssessRules(t *testing.T) {
	remote := Vulnerability{ID: "CVE-1", Severity: "CRITICAL", Score: 9.8, Fixed: "2.0",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Title: "Remote code execution in foo"}
	Assess(&remote)
	for _, want := range []string{"remotely over the network", "low complexity", "no authentication", "no user interaction", "confidentiality, integrity and availability", "arbitrary code execution"} {
		if !strings.Contains(remote.Attack, want) {
			t.Errorf("attack text missing %q: %s", want, remote.Attack)
		}
	}
	if remote.Tier != TierSoon { // 20 + 22 vector + 5 fix, no exploitation signal
		t.Errorf("tier %s priority %d", remote.Tier, remote.Priority)
	}

	local := Vulnerability{ID: "CVE-2", Severity: "HIGH", Vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N"}
	Assess(&local)
	if !strings.Contains(local.Attack, "local access") || !strings.Contains(local.Attack, "boundary") || local.Priority >= remote.Priority {
		t.Errorf("local: %d %s", local.Priority, local.Attack)
	}

	kev := remote
	kev.KEV, kev.KEVRansomware = true, true
	Assess(&kev)
	if kev.Priority != 100 {
		t.Errorf("score should be capped at 100, got %d", kev.Priority)
	}
	if kev.Tier != TierNow || kev.Reasons[0].Signal != "KEV" || !strings.Contains(kev.Attack, "exploited in the real world") {
		t.Errorf("kev: %+v", kev)
	}

	// low severity with high EPSS must outrank a medium without signals
	a := Vulnerability{ID: "CVE-3", Severity: "LOW", HasEPSS: true, EPSS: 0.9, EPSSPercentile: 0.99}
	b := Vulnerability{ID: "CVE-4", Severity: "MEDIUM"}
	Assess(&a)
	Assess(&b)
	if a.Priority <= b.Priority || a.Tier != TierSoon {
		t.Errorf("epss: %d vs %d (%s)", a.Priority, b.Priority, a.Tier)
	}

	none := Vulnerability{ID: "GHSA-x", Severity: "LOW"}
	Assess(&none)
	if none.Tier != TierMonitor || !strings.Contains(none.Attack, "No CVSS vector") {
		t.Errorf("none: %+v", none)
	}
	if v := ParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:P"); v.Version != 2 || v.M["Au"] != "N" {
		t.Errorf("v2: %+v", v)
	}
}

func TestEnrich(t *testing.T) {
	epssCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		epssCalls++
		if !strings.Contains(r.URL.Query().Get("cve"), "CVE-2021-44228") {
			t.Errorf("query: %s", r.URL.RawQuery)
		}
		w.Write([]byte(`{"status":"OK","data":[{"cve":"CVE-2021-44228","epss":"0.97565","percentile":"0.99993"}]}`))
	})
	mux.HandleFunc("/kev", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"catalogVersion":"2025.01.01","vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10","dueDate":"2021-12-24","requiredAction":"Apply updates","knownRansomwareCampaignUse":"Known"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	e := &Enricher{EPSSURL: srv.URL + "/epss", KEVURL: srv.URL + "/kev", CacheDir: t.TempDir()}
	vulns := []Vulnerability{{ID: "CVE-2021-44228", Severity: "CRITICAL"}, {ID: "CVE-2000-1", Severity: "LOW"}, {ID: "GHSA-1", Severity: "LOW"}}
	info := e.Enrich(context.Background(), vulns)
	if !info.EPSS || !info.KEV || info.KEVDate != "2025.01.01" || len(info.Warnings) != 0 {
		t.Fatalf("info: %+v", info)
	}
	v := vulns[0]
	if !v.KEV || !v.KEVRansomware || v.KEVDue != "2021-12-24" || !v.HasEPSS || v.EPSS != 0.97565 || v.Tier != TierNow {
		t.Fatalf("vuln: %+v", v)
	}
	if vulns[1].KEV || vulns[1].HasEPSS {
		t.Fatalf("unexpected signals: %+v", vulns[1])
	}

	// Second enricher with a dead KEV URL falls back to the on-disk cache.
	srv.Close()
	e2 := &Enricher{EPSSURL: srv.URL + "/epss", KEVURL: srv.URL + "/kev", CacheDir: e.CacheDir}
	vs := []Vulnerability{{ID: "CVE-2021-44228", Severity: "CRITICAL"}}
	info = e2.Enrich(context.Background(), vs)
	if !info.KEV || !vs[0].KEV || info.EPSS || len(info.Warnings) != 1 || !strings.Contains(info.Warnings[0], "EPSS") {
		t.Fatalf("fallback: %+v %+v", info, vs[0])
	}
}

func TestVEX(t *testing.T) {
	st := &VEXStore{Path: filepath.Join(t.TempDir(), "sub", "vex.json")}
	img := "ghcr.io/acme/app:1.2"
	base := VEXEntry{Vulnerability: "CVE-1", Package: "libssl3", Version: "3.0", PURL: "pkg:deb/debian/libssl3@3.0"}

	bad := base
	bad.Status = "not_affected"
	if _, err := st.Set(img, bad); err == nil {
		t.Error("not_affected without justification should fail")
	}
	bad.Status = "affected"
	if _, err := st.Set(img, bad); err == nil {
		t.Error("affected without action should fail")
	}
	bad.Status, bad.Justification = "bogus", ""
	if _, err := st.Set(img, bad); err == nil {
		t.Error("bad status should fail")
	}

	ok := base
	ok.Status, ok.Justification, ok.Impact = "not_affected", "vulnerable_code_not_in_execute_path", "TLS is terminated at the proxy"
	if _, err := st.Set(img, ok); err != nil {
		t.Fatal(err)
	}
	inv := VEXEntry{Vulnerability: "CVE-2", Package: "lodash", Version: "4", Status: "under_investigation", Justification: "ignored"}
	if e, err := st.Set(img, inv); err != nil || e.Justification != "" {
		t.Fatalf("%+v %v", e, err)
	}

	// New tag of the same repository sees the same assessments.
	got, err := st.List("ghcr.io/acme/app:1.3")
	if err != nil || len(got) != 2 {
		t.Fatalf("list: %v %v", got, err)
	}

	product := ProductPURL(img)
	raw, err := ExportOpenVEX(got, product, DocMeta{Author: "Jane", Role: "Security"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Context    string `json:"@context"`
		ID         string `json:"@id"`
		Author     string
		Role       string
		Version    int
		Timestamp  string
		Statements []struct {
			Vulnerability struct{ Name string }
			Products      []struct {
				ID            string `json:"@id"`
				Subcomponents []struct {
					ID string `json:"@id"`
				}
			}
			Status, Justification string
			ImpactStatement       string `json:"impact_statement"`
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Context != "https://openvex.dev/ns/v0.2.0" || !strings.HasPrefix(doc.ID, "https://openvex.dev/docs/public/vex-") || doc.Author != "Jane" || doc.Version != 1 || doc.Timestamp == "" || len(doc.Statements) != 2 {
		t.Fatalf("doc: %s", raw)
	}
	s0 := doc.Statements[0]
	if s0.Vulnerability.Name != "CVE-1" || s0.Status != "not_affected" || s0.Justification != "vulnerable_code_not_in_execute_path" ||
		s0.Products[0].ID != "pkg:oci/app" ||
		s0.Products[0].Subcomponents[0].ID != base.PURL {
		t.Fatalf("stmt: %+v", s0)
	}
	if !strings.Contains(string(raw), "pkg:generic/lodash@4") {
		t.Error("fallback subcomponent id missing")
	}
	ph, err := ExportOpenVEX(got, product, DocMeta{ID: "https://example.com/vex.json", Author: " "})
	if err != nil || !strings.Contains(string(ph), `"author": "<author>"`) || !strings.Contains(string(ph), `"@id": "https://example.com/vex.json"`) {
		t.Errorf("placeholder author / kept id: %v %s", err, ph)
	}

	if err := st.Delete(img, got[0].Key); err != nil {
		t.Fatal(err)
	}
	if l, _ := st.List(img); len(l) != 1 {
		t.Fatalf("after delete: %v", l)
	}
	if p := ProductPURL("nginx:1.27"); p != "pkg:oci/nginx" {
		t.Errorf("tag purl: %s", p)
	}
	if ImageRepo("docker://localhost:5000/a/b:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") != "localhost:5000/a/b" {
		t.Errorf("repo: %s", ImageRepo("docker://localhost:5000/a/b:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	}
}

func TestVEXExpiry(t *testing.T) {
	st := &VEXStore{Path: filepath.Join(t.TempDir(), "vex.json")}
	e := VEXEntry{
		Vulnerability: "CVE-1", Package: "zlib", Version: "1", Status: "not_affected",
		Impact: "not reachable", Author: "  Jane ", Expires: "2026-06-30",
	}

	bad := e
	bad.Expires = "30/06/2026"
	if _, err := st.Set("app:1", bad); err == nil {
		t.Error("malformed expiry should fail")
	}

	got, err := st.Set("app:1", e)
	if err != nil || got.Author != "Jane" {
		t.Fatalf("%+v %v", got, err)
	}
	day := func(s string) time.Time { d, _ := time.Parse(expiryLayout, s); return d.Add(23 * time.Hour) }
	if got.Expired(day("2026-06-30")) {
		t.Error("the expiry day itself is still valid")
	}
	if !got.Expired(day("2026-07-01")) {
		t.Error("the day after the expiry date is expired")
	}
	if (VEXEntry{}).Expired(day("2099-01-01")) {
		t.Error("no expiry never expires")
	}
	listed, _ := st.List("app:2")
	if len(listed) != 1 || listed[0].Expires != "2026-06-30" || listed[0].Author != "Jane" {
		t.Errorf("author/expiry not persisted: %+v", listed)
	}
}

func TestRulesTuning(t *testing.T) {
	// Fix-less KEV finding with a middling EPSS; MEDIUM keeps the sum under the 100 cap so each rule moves it.
	v := Vulnerability{ID: "CVE-9", Severity: "MEDIUM", KEV: true, HasEPSS: true, EPSS: 0.03, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}

	bal := v
	AssessWith(&bal, DefaultRules())
	if bal.Tier != TierNow || !strings.Contains(bal.TierWhy, "KEV") || bal.Reasons[0].Rule != "listed in KEV → +50" {
		t.Errorf("balanced: %+v", bal)
	}
	for _, r := range bal.Reasons {
		if r.Rule == "" {
			t.Errorf("reason without rule: %+v", r)
		}
	}

	// KEV off: the score loses 50 and the tier is decided by the score alone.
	r := DefaultRules()
	r.KEVEnabled = false
	off := v
	AssessWith(&off, r)
	if off.Priority != bal.Priority-PointsKEV || off.Tier == TierNow {
		t.Errorf("kev off: %d (%s) vs %d", off.Priority, off.Tier, bal.Priority)
	}

	// KEV on but not forcing: the same finding needs the score.
	r = DefaultRules()
	r.KEVForceNow, r.TierNow = false, 100
	nf := v
	AssessWith(&nf, r)
	if nf.Tier == TierNow || nf.Priority != bal.Priority {
		t.Errorf("no force: %+v", nf)
	}

	// EPSS cutoff: 3% scores +10 at the default 1% cutoff and nothing at 5%.
	hi := DefaultRules()
	hi.EPSSCutoff = 0.05
	cut := v
	AssessWith(&cut, hi)
	if cut.Priority != bal.Priority-PointsEPSSLow || !strings.Contains(cut.Reasons[len(cut.Reasons)-1].Rule, "EPSS < 5%") {
		t.Errorf("cutoff: %d vs %d %+v", cut.Priority, bal.Priority, cut.Reasons)
	}

	// Fixed-only drops an unfixed finding even when it is on KEV.
	fo := DefaultRules()
	fo.FixedOnly = true
	drop := v
	AssessWith(&drop, fo)
	if drop.Priority != 0 || drop.Tier != TierMonitor || drop.Reasons[0].Rule != "fixed-only → score 0" {
		t.Errorf("fixed-only: %+v", drop)
	}
	fixed := v
	fixed.Fixed = "1.2"
	AssessWith(&fixed, fo)
	if fixed.Tier != TierNow {
		t.Errorf("fixed finding must stay ranked: %+v", fixed)
	}

	// Disabling a rule removes its reason.
	none := Rules{}
	n := v
	AssessWith(&n, none)
	if len(n.Reasons) != 0 || n.Priority != 0 {
		t.Errorf("all off: %+v", n)
	}

	// Out-of-order thresholds are repaired rather than producing a nonsense ranking.
	bad := Rules{EPSSEnabled: true, EPSSCutoff: 0.9, EPSSHigh: 0.1, EPSSVeryHigh: 5, TierNow: 10, TierSoon: 50, TierPlan: 70}.Normalize()
	if bad.EPSSHigh != 0.9 || bad.EPSSVeryHigh != 1 || bad.TierSoon != 70 || bad.TierNow != 70 {
		t.Errorf("normalize: %+v", bad)
	}
}

func TestRescoreOrder(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "A", Severity: "CRITICAL"},
		{ID: "B", Severity: "LOW", HasEPSS: true, EPSS: 0.9},
		{ID: "C", Severity: "HIGH", Fixed: "2"},
	}
	for i := range vulns {
		Assess(&vulns[i])
	}
	bal := Rescore(vulns, DefaultRules())
	if bal[0].Index != 1 { // EPSS 90% outranks a critical without exploitation evidence
		t.Errorf("balanced order: %+v", bal)
	}
	sev := Rules{SeverityEnabled: true, TierNow: 70, TierSoon: 45, TierPlan: 25}
	got := Rescore(vulns, sev)
	if got[0].Index != 0 || got[1].Index != 2 || got[2].Index != 1 {
		t.Errorf("severity-only order: %+v", got)
	}
	if vulns[1].Priority == 0 || len(vulns[1].Reasons) == 0 {
		t.Error("Rescore must not modify its input")
	}
	// Balanced must reproduce what the scan computed.
	for n, r := range bal {
		if r.Priority != vulns[r.Index].Priority || r.Tier != vulns[r.Index].Tier {
			t.Errorf("row %d differs from Assess: %+v vs %+v", n, r, vulns[r.Index])
		}
	}
	if len(Presets()) < 2 || Presets()[0].Name != "balanced" || Presets()[0].Rules != DefaultRules() {
		t.Error("balanced must be the first preset and equal the default rules")
	}
}

func TestParseVectorVersions(t *testing.T) {
	for _, c := range []struct {
		raw     string
		version int
		av, ui  string
	}{
		{"CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 3, "A", "R"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 3, "N", "N"},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 4, "N", "N"},
		{"AV:L/AC:L/Au:N/C:P/I:P/A:P", 2, "L", ""},
		{"CVSS:3.1/AV:N", 0, "", ""}, // incomplete: rejected, so no rule reads it
		{"garbage", 0, "", ""},
	} {
		v := ParseVector(c.raw)
		if v.Version != c.version || v.M["AV"] != c.av || v.M["UI"] != c.ui {
			t.Errorf("%s: version %d AV %q UI %q", c.raw, v.Version, v.M["AV"], v.M["UI"])
		}
	}
}

// A re-export of an imported document is its next version: untouched
// statements keep their timestamp and description, and no tooling is invented.
func TestVEXReimportKeepsDocument(t *testing.T) {
	src := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/oci.openvex.json",
  "author": "Kube-kraken",
  "version": 4,
  "statements": [{
    "vulnerability": {"name": "CVE-2023-2953", "description": "openldap: null pointer dereference"},
    "products": [{"@id": "pkg:oci/fluent-bit", "subcomponents": [{"@id": "pkg:deb/debian/libldap-2.5-0"}]}],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "impact_statement": "No LDAP.",
    "timestamp": "2026-01-15T19:59:23.564560549Z"
  }],
  "timestamp": "2026-01-15T19:59:23Z",
  "last_updated": "2026-09-09T00:00:00Z"
}`
	entries, rep, err := ParseOpenVEX([]byte(src), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ExportOpenVEX(entries, "pkg:oci/fluent-bit", rep.Doc)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, want := range []string{
		`"version": 5`,
		`"description": "openldap: null pointer dereference"`,
		`"timestamp": "2026-01-15T19:59:23.564560549Z"`,
		`"timestamp": "2026-01-15T19:59:23Z"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tooling") {
		t.Errorf("tooling must not be added:\n%s", out)
	}
}

func TestMatchingEntries(t *testing.T) {
	entries := []VEXEntry{{Key: "CVE-1|a"}, {Key: "CVE-2|b"}}
	got := MatchingEntries(entries, []Vulnerability{{Key: "CVE-2|b"}})
	if len(got) != 1 || got[0].Key != "CVE-2|b" {
		t.Fatalf("got %+v", got)
	}
}
