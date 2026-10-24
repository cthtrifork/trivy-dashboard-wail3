package trivy

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func flagValue(args []string, flag string) string {
	if i := slices.Index(args, flag); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

func TestDefaultCacheIsHostDirectoryWhenPodmanIsLocal(t *testing.T) {
	cache := t.TempDir()
	t.Setenv(CacheEnv, "")
	t.Setenv("CONTAINER_HOST", "")
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", cache)
	args, err := (&PodmanEngine{}).runArgs(TrivyJob{Image: "alpine:3", Flags: []string{"--format", "json"}}, "n")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cache, "trivy-scanner", "trivy")
	if runtime.GOOS == "windows" {
		t.Skip("windows uses the volume")
	}
	if got := flagValue(args, "-v"); got != want+":"+cacheMount {
		t.Errorf("mount = %q, want %q", got, want)
	}
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Errorf("cache dir not created: %v", err)
	}
	if got := flagValue(args, "--cache-dir"); got != cacheMount {
		t.Errorf("--cache-dir = %q", got)
	}
	// Image comes last, after trivy's flags; --cache-dir comes after the subcommand.
	if args[len(args)-1] != "alpine:3" || slices.Index(args, "--cache-dir") < slices.Index(args, "image") {
		t.Errorf("unexpected order: %v", args)
	}
}

func TestDefaultCacheIsVolumeWhenPodmanIsRemote(t *testing.T) {
	t.Setenv(CacheEnv, "")
	t.Setenv("CONTAINER_HOST", "unix:///run/podman/podman.sock")
	args, err := (&PodmanEngine{}).runArgs(TrivyJob{Image: "x"}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if got := flagValue(args, "-v"); got != DefaultCacheSource+":"+cacheMount {
		t.Errorf("mount = %q", got)
	}
	if slices.Contains(args, "label=disable") {
		t.Error("a named volume does not need SELinux relabelling off")
	}
}

func TestVolumeNameOverridesHostDefault(t *testing.T) {
	t.Setenv(CacheEnv, "my-cache")
	t.Setenv("CONTAINER_HOST", "")
	args, _ := (&PodmanEngine{}).runArgs(TrivyJob{Image: "x"}, "n")
	if got := flagValue(args, "-v"); got != "my-cache:"+cacheMount {
		t.Errorf("mount = %q", got)
	}
}

func TestRunArgsHostDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache", "trivy")
	t.Setenv("CONTAINER_HOST", "")
	t.Setenv("DOCKER_HOST", "")
	args, err := (&PodmanEngine{Cache: dir}).runArgs(TrivyJob{Image: "x"}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if got := flagValue(args, "-v"); got != dir+":"+cacheMount {
		t.Errorf("mount = %q", got)
	}
	if !slices.Contains(args, "label=disable") {
		t.Error("host directory needs label=disable for SELinux")
	}
	if _, err := filepath.Glob(dir); err != nil {
		t.Fatal(err)
	}
}

func TestRunArgsRemoteDoesNotCreateHostPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	t.Setenv("CONTAINER_HOST", "unix:///run/podman/podman.sock")
	if _, err := (&PodmanEngine{Cache: dir}).runArgs(TrivyJob{Image: "x"}, "n"); err != nil {
		t.Fatal(err)
	}
	if matches, _ := filepath.Glob(dir); len(matches) != 0 {
		t.Errorf("created %v on the wrong machine", matches)
	}
}

func TestCacheSourceRejectsAmbiguousValues(t *testing.T) {
	for _, bad := range []string{"./cache", "cache/dir", "a:b"} {
		if _, err := (&PodmanEngine{Cache: bad}).cacheSource(); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	t.Setenv(CacheEnv, "my-cache")
	if got, err := (&PodmanEngine{}).cacheSource(); err != nil || got != "my-cache" {
		t.Errorf("env volume = %q, %v", got, err)
	}
}

func TestCredentialsStayOffTheCommandLine(t *testing.T) {
	args, _ := (&PodmanEngine{}).runArgs(TrivyJob{Image: "x", Username: "u", Password: "secret"}, "n")
	if strings.Contains(strings.Join(args, " "), "secret") {
		t.Error("password leaked into args")
	}
}
