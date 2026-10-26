package trivy

import "testing"

func TestWithDefaultCredentials(t *testing.T) {
	t.Setenv("GITHUB_ACTOR", "")
	t.Setenv("GITHUB_USER", "")
	t.Setenv("GITHUB_TOKEN", "tok")
	cases := []struct{ name, image, user, pass, wantUser, wantPass string }{
		{"ghcr filled", "ghcr.io/o/r:1", "", "", "github", "tok"},
		{"ghcr keeps typed user", "ghcr.io/o/r:1", "me", "", "me", "tok"},
		{"typed password wins", "ghcr.io/o/r:1", "me", "pw", "me", "pw"},
		{"other registry untouched", "docker.io/library/alpine", "", "", "", ""},
		{"lookalike host untouched", "ghcr.io.evil.test/o/r", "", "", "", ""},
	}
	for _, c := range cases {
		u, p := withDefaultCredentials(c.image, c.user, c.pass)
		if u != c.wantUser || p != c.wantPass {
			t.Errorf("%s: got %q/%q, want %q/%q", c.name, u, p, c.wantUser, c.wantPass)
		}
	}
	t.Setenv("GITHUB_TOKEN", "")
	if u, p := withDefaultCredentials("ghcr.io/o/r", "", ""); u != "" || p != "" {
		t.Errorf("no token set: got %q/%q", u, p)
	}
}
