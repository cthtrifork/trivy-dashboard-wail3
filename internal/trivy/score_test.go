package trivy

import "testing"

func TestPickScore(t *testing.T) {
	type entry = cvssEntry
	cases := []struct {
		name string
		in   map[string]entry
		want float64
	}{
		{"red hat wins over a higher score", map[string]entry{"bitnami": {V3Score: 9.1}, "redhat": {V3Score: 5.3}, "nvd": {V3Score: 7.5}}, 5.3},
		{"red hat v2 when it has no v3", map[string]entry{"redhat": {V2Score: 4.3}, "nvd": {V3Score: 7.5}}, 4.3},
		{"nvd when red hat is absent", map[string]entry{"bitnami": {V3Score: 9.1}, "nvd": {V3Score: 7.5}}, 7.5},
		{"red hat without a score falls through", map[string]entry{"redhat": {}, "nvd": {V3Score: 7.5}}, 7.5},
		{"maximum otherwise", map[string]entry{"bitnami": {V3Score: 9.1}, "ghsa": {V3Score: 8.0}}, 9.1},
		{"none", nil, 0},
	}
	for _, c := range cases {
		if got, _ := pickScore(c.in); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPickScoreSource(t *testing.T) {
	type entry = cvssEntry
	_, src := pickScore(map[string]entry{"bitnami": {V3Score: 9.1}, "redhat": {V3Score: 5.3}})
	if src != "redhat" {
		t.Errorf("preferred source: %q", src)
	}
	if _, src = pickScore(map[string]entry{"ghsa": {V3Score: 8}, "bitnami": {V3Score: 9.1}}); src != "bitnami" {
		t.Errorf("highest source: %q", src)
	}
	r := ratings(map[string]int{"redhat": 2, "alma": 3, "bitnami": 4, "ubuntu": 0}, map[string]entry{"bitnami": {V3Score: 9.1}, "redhat": {V3Score: 5.3}})
	want := []Rating{{"redhat", "MEDIUM", 5.3}, {"alma", "HIGH", 0}, {"bitnami", "CRITICAL", 9.1}}
	if len(r) != len(want) {
		t.Fatalf("ratings: %+v", r)
	}
	for i := range want {
		if r[i] != want[i] {
			t.Errorf("ratings[%d]: %+v, want %+v", i, r[i], want[i])
		}
	}
}

func TestPickVectorFollowsScoreSource(t *testing.T) {
	type entry = cvssEntry
	cvss := map[string]entry{
		"nvd":    {V3Vector: "CVSS:3.1/AV:N/AC:L", V3Score: 9.1},
		"redhat": {V3Vector: "CVSS:3.1/AV:L/AC:H", V3Score: 5.3},
		"old":    {V2Vector: "AV:A/AC:L"},
	}
	if got := pickVector(cvss, "redhat"); got != "CVSS:3.1/AV:L/AC:H" {
		t.Errorf("score source's vector: %q", got)
	}
	if got := pickVector(cvss, "ghsa"); got != "CVSS:3.1/AV:N/AC:L" {
		t.Errorf("fallback to NVD: %q", got)
	}
	if got := pickVector(map[string]entry{"redhat": {V3Score: 5.3}, "nvd": {V3Vector: "CVSS:3.1/AV:N"}}, "redhat"); got != "CVSS:3.1/AV:N" {
		t.Errorf("source without a vector falls back: %q", got)
	}
}
