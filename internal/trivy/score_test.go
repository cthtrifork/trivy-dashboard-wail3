package trivy

import "testing"

func TestPickScore(t *testing.T) {
	type entry = struct {
		V3Vector string
		V2Vector string
		V3Score  float64
		V2Score  float64
	}
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
		if got := pickScore(c.in); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
