package trivy

import (
	"regexp"
	"strings"
	"testing"
)

func TestDefaultTrivyImageIsPinned(t *testing.T) {
	img := DefaultTrivyImage
	repo, tag, ok := strings.Cut(img, ":")
	if !ok || repo != "docker.io/aquasec/trivy" {
		t.Fatalf("default image = %q", img)
	}
	if _, err := ResolveTrivyImage(tag); err != nil {
		t.Errorf("default must be a pinned version, got tag %q", tag)
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(defaultTrivyDigest) {
		t.Errorf("default image must carry a sha256 digest, got %q", defaultTrivyDigest)
	}
	if pinnedTrivyImage != DefaultTrivyImage+"@"+defaultTrivyDigest {
		t.Errorf("pinned = %q", pinnedTrivyImage)
	}
}

func TestDefaultDBRepositoryIsPinned(t *testing.T) {
	repo, digest, ok := strings.Cut(DefaultDBRepository, "@")
	if !ok || !strings.HasPrefix(repo, "ghcr.io/aquasecurity/trivy-db:") {
		t.Fatalf("default DB repository = %q", DefaultDBRepository)
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(digest) {
		t.Errorf("default DB repository must carry a sha256 digest, got %q", digest)
	}
}

func TestRunArgsPassPinnedDBRepository(t *testing.T) {
	args, err := (&PodmanEngine{Cache: "c"}).runArgs(TrivyJob{Image: "x"}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, " "), "-e TRIVY_DB_REPOSITORY="+DefaultDBRepository) {
		t.Errorf("the pinned DB repository is not passed: %v", args)
	}
	// A mirror from the environment replaces it and is forwarded untouched, not pinned.
	t.Setenv("TRIVY_DB_REPOSITORY", "mirror.example/trivy-db")
	args, _ = (&PodmanEngine{Cache: "c"}).runArgs(TrivyJob{Image: "x"}, "n")
	if line := strings.Join(args, " "); strings.Contains(line, "ghcr.io/aquasecurity/trivy-db") || !strings.Contains(line, "-e TRIVY_DB_REPOSITORY ") {
		t.Errorf("a mirror must replace the default: %v", args)
	}
}

func TestResolveTrivyImage(t *testing.T) {
	def := DefaultTrivyImage
	for in, want := range map[string]string{
		"":   pinnedTrivyImage,
		"  ": pinnedTrivyImage,
		// the default's own tag keeps its digest, whichever way it is spelled
		strings.TrimPrefix(def, "docker.io/aquasec/trivy:"):       pinnedTrivyImage,
		"v" + strings.TrimPrefix(def, "docker.io/aquasec/trivy:"): pinnedTrivyImage,
		"0.77.0":  "docker.io/aquasec/trivy:0.77.0",
		"v0.77.0": "docker.io/aquasec/trivy:0.77.0",
	} {
		if got, err := ResolveTrivyImage(in); err != nil || got != want {
			t.Errorf("resolve(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"--privileged", "a b", "x\ny", "nginx", "registry.local/mirror/trivy:0.7", "docker.io/aquasec/trivy@sha256:ab"} {
		if _, err := ResolveTrivyImage(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestRunArgsUseJobVersionElseDefault(t *testing.T) {
	line := func(e *PodmanEngine, j TrivyJob) string {
		args, err := e.runArgs(j, "n")
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(args, " ")
	}
	if got := line(&PodmanEngine{Cache: "c"}, TrivyJob{Image: "x"}); !strings.Contains(got, pinnedTrivyImage+" image") {
		t.Errorf("default not used: %s", got)
	}
	if got := line(&PodmanEngine{Cache: "c"}, TrivyJob{Image: "x", TrivyImage: "v0.99.0"}); !strings.Contains(got, "trivy:0.99.0 image") {
		t.Errorf("job version must be used: %s", got)
	}
	if _, err := (&PodmanEngine{Cache: "c"}).runArgs(TrivyJob{Image: "x", TrivyImage: "--rm"}, "n"); err == nil {
		t.Error("a flag-like image must be refused")
	}
}
