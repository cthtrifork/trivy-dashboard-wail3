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
		if got, err := ResolveTrivyImage(in); err != nil || got != want {
			t.Errorf("resolve(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"--privileged", "a b", "x\ny"} {
		if _, err := ResolveTrivyImage(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestRunArgsUseJobImageThenEngineImage(t *testing.T) {
	line := func(e *PodmanEngine, j TrivyJob) string {
		args, err := e.runArgs(j, "n")
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(args, " ")
	}
	if got := line(&PodmanEngine{Cache: "c"}, TrivyJob{Image: "x"}); !strings.Contains(got, DefaultTrivyImage()+" image") {
		t.Errorf("default not used: %s", got)
	}
	if got := line(&PodmanEngine{Cache: "c", Image: "1.0.0"}, TrivyJob{Image: "x"}); !strings.Contains(got, "trivy:1.0.0 image") {
		t.Errorf("engine image not used: %s", got)
	}
	if got := line(&PodmanEngine{Cache: "c", Image: "1.0.0"}, TrivyJob{Image: "x", TrivyImage: "v0.99.0"}); !strings.Contains(got, "trivy:0.99.0 image") {
		t.Errorf("job image must win: %s", got)
	}
	if _, err := (&PodmanEngine{Cache: "c"}).runArgs(TrivyJob{Image: "x", TrivyImage: "--rm"}, "n"); err == nil {
		t.Error("a flag-like image must be refused")
	}
}
