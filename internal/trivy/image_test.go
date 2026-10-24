package trivy

import (
	"strings"
	"testing"
)

func TestDefaultTrivyImageIsPinned(t *testing.T) {
	img := DefaultTrivyImage()
	repo, tag, ok := strings.Cut(img, ":")
	if !ok || repo != defaultTrivyRepo {
		t.Fatalf("default image = %q", img)
	}
	if tag == "latest" || !bareVersion.MatchString(tag) {
		t.Errorf("default must be a pinned version, got tag %q", tag)
	}
}

func TestResolveTrivyImage(t *testing.T) {
	def := DefaultTrivyImage()
	for in, want := range map[string]string{
		"":                                  def,
		"  ":                                def,
		"0.77.0":                            "docker.io/aquasec/trivy:0.77.0",
		"v0.77.0":                           "docker.io/aquasec/trivy:0.77.0",
		"registry.local/mirror/trivy:0.7":   "registry.local/mirror/trivy:0.7",
		"docker.io/aquasec/trivy@sha256:ab": "docker.io/aquasec/trivy@sha256:ab",
	} {
		if got, err := resolveTrivyImage(in); err != nil || got != want {
			t.Errorf("resolve(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"--privileged", "a b", "x\ny"} {
		if _, err := resolveTrivyImage(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestRunArgsUseConfiguredImage(t *testing.T) {
	t.Setenv(TrivyImageEnv, "0.99.0")
	args, err := (&PodmanEngine{Cache: "c"}).runArgs(TrivyJob{Image: "x"}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, " "), "docker.io/aquasec/trivy:0.99.0 image") {
		t.Errorf("env image not used: %v", args)
	}
	args, _ = (&PodmanEngine{Cache: "c", Image: "1.0.0"}).runArgs(TrivyJob{Image: "x"}, "n")
	if !strings.Contains(strings.Join(args, " "), "trivy:1.0.0 image") {
		t.Errorf("field must win over env: %v", args)
	}
	t.Setenv(TrivyImageEnv, "--rm")
	if _, err := (&PodmanEngine{Cache: "c"}).runArgs(TrivyJob{Image: "x"}, "n"); err == nil {
		t.Error("a flag-like image must be refused")
	}
}
