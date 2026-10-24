// Package release tests the scripts behind the "Tag and release" workflow against real git
// repositories: scripts/next-version.sh decides the tag, scripts/create-release-tag.sh
// creates and pushes it.
package release

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func script(name string) string {
	p, _ := filepath.Abs(filepath.Join("..", "..", "scripts", name))
	return p
}

func need(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	for _, tool := range []string{"bash", "git", "sort"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// repo is a clone with a bare "origin" holding the given tags.
type repo struct {
	work, origin string
}

func newRepo(t *testing.T, tags ...string) repo {
	t.Helper()
	need(t)
	base := t.TempDir()
	r := repo{work: filepath.Join(base, "work"), origin: filepath.Join(base, "origin.git")}
	git(t, base, "init", "-q", "--bare", "-b", "main", r.origin)
	git(t, base, "init", "-q", "-b", "main", r.work)
	git(t, r.work, "config", "user.name", "test")
	git(t, r.work, "config", "user.email", "test@example.com")
	git(t, r.work, "remote", "add", "origin", r.origin)
	git(t, r.work, "commit", "-q", "--allow-empty", "-m", "first")
	for _, tag := range tags {
		git(t, r.work, "tag", tag)
	}
	git(t, r.work, "push", "-q", "origin", "main", "--tags")
	git(t, r.work, "commit", "-q", "--allow-empty", "-m", "second") // HEAD is ahead of every tag
	return r
}

func (r repo) remoteTags(t *testing.T) string {
	return git(t, r.origin, "tag", "--list")
}

func nextVersion(t *testing.T, r repo, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script("next-version.sh")}, args...)...)
	cmd.Dir = r.work
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return errb.String(), err
	}
	return strings.TrimSpace(out.String()), nil
}

func TestNextVersion(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		args []string
		want string
	}{
		{"first release, patch", nil, []string{"patch"}, "v0.0.1"},
		{"first release, minor", nil, []string{"minor"}, "v0.1.0"},
		{"first release, major", nil, []string{"major"}, "v1.0.0"},
		{"patch", []string{"v0.1.0"}, []string{"patch"}, "v0.1.1"},
		{"minor resets patch", []string{"v1.2.3"}, []string{"minor"}, "v1.3.0"},
		{"major resets minor and patch", []string{"v1.2.3"}, []string{"major"}, "v2.0.0"},
		{"numeric, not lexical, ordering", []string{"v1.2.3", "v1.10.0", "v1.9.9"}, []string{"patch"}, "v1.10.1"},
		{"pre-releases are not a base", []string{"v1.2.3", "v2.0.0-rc.1"}, []string{"minor"}, "v1.3.0"},
		{"unrelated tags are ignored", []string{"v1.2.3", "nightly", "v3", "release-9"}, []string{"patch"}, "v1.2.4"},
		{"an explicit tag wins over the bump", []string{"v1.2.3"}, []string{"major", "v1.4.0"}, "v1.4.0"},
		{"explicit pre-release", []string{"v1.2.3"}, []string{"patch", "v1.3.0-rc.1"}, "v1.3.0-rc.1"},
		{"bump defaults to patch", []string{"v1.2.3"}, nil, "v1.2.4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := nextVersion(t, newRepo(t, c.tags...), c.args...)
			if err != nil || got != c.want {
				t.Errorf("got %q (err %v), want %q", got, err, c.want)
			}
		})
	}
}

func TestNextVersionRejectsBadInput(t *testing.T) {
	r := newRepo(t, "v1.2.3")
	for name, args := range map[string][]string{
		"no leading v":      {"patch", "1.4.0"},
		"too few parts":     {"patch", "v1.4"},
		"shell metachars":   {"patch", "v1.4.0;touch pwned"},
		"command injection": {"patch", "v1.4.0 $(id)"},
		"unknown bump":      {"huge"},
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := nextVersion(t, r, args...); err == nil {
				t.Errorf("accepted %v, printed %q", args, out)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(r.work, "pwned")); err == nil {
		t.Error("an input was executed as a command")
	}
}

// ---- create-release-tag.sh ----

// fakeGH writes a gh that answers `release view` according to mode.
func fakeGH(t *testing.T, mode string) (binDir string) {
	t.Helper()
	binDir = t.TempDir()
	body := map[string]string{
		"missing": "echo 'release not found' >&2; exit 1",
		"exists":  `echo '{"tagName":"x"}'; exit 0`,
		"broken":  "echo 'HTTP 502: Bad Gateway' >&2; exit 1",
	}[mode]
	if err := os.WriteFile(filepath.Join(binDir, "gh"), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return binDir
}

type result struct {
	outputs map[string]string
	log     string
	err     error
}

func createTag(t *testing.T, r repo, ghMode, bump, tagInput string) result {
	t.Helper()
	outFile := filepath.Join(t.TempDir(), "github_output")
	cmd := exec.Command("bash", script("create-release-tag.sh"))
	cmd.Dir = r.work
	cmd.Env = append(os.Environ(),
		"PATH="+fakeGH(t, ghMode)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GITHUB_OUTPUT="+outFile, "BUMP="+bump, "TAG_INPUT="+tagInput)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	res := result{outputs: map[string]string{}, log: buf.String(), err: err}
	if b, rerr := os.ReadFile(outFile); rerr == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				res.outputs[k] = v
			}
		}
	}
	return res
}

func TestCreatesAnAnnotatedTagAndPushesIt(t *testing.T) {
	r := newRepo(t, "v0.1.0")
	res := createTag(t, r, "missing", "minor", "")
	if res.err != nil {
		t.Fatalf("%v\n%s", res.err, res.log)
	}
	if res.outputs["tag"] != "v0.2.0" || res.outputs["created"] != "true" {
		t.Fatalf("outputs: %v\n%s", res.outputs, res.log)
	}
	if got := r.remoteTags(t); !strings.Contains(got, "v0.2.0") {
		t.Fatalf("v0.2.0 was not pushed to origin; origin has %q", got)
	}
	if kind := git(t, r.origin, "cat-file", "-t", "refs/tags/v0.2.0"); kind != "tag" {
		t.Errorf("the tag should be annotated, got a %s object", kind)
	}
	if tagged, head := git(t, r.origin, "rev-list", "-n1", "v0.2.0"), git(t, r.work, "rev-parse", "HEAD"); tagged != head {
		t.Errorf("tag points at %s, want HEAD %s", tagged, head)
	}
}

func TestExplicitTagOverridesTheBump(t *testing.T) {
	r := newRepo(t, "v0.1.0")
	res := createTag(t, r, "missing", "major", "v0.5.0")
	if res.err != nil || res.outputs["tag"] != "v0.5.0" {
		t.Fatalf("%v %v\n%s", res.err, res.outputs, res.log)
	}
	if strings.Contains(r.remoteTags(t), "v1.0.0") {
		t.Error("the bump was applied as well as the explicit tag")
	}
}

// An earlier run tagged but failed before releasing: running again must finish the job.
func TestExistingTagWithoutReleaseIsReused(t *testing.T) {
	r := newRepo(t, "v0.1.0", "v0.2.0")
	before := git(t, r.origin, "rev-parse", "refs/tags/v0.2.0")
	res := createTag(t, r, "missing", "patch", "v0.2.0")
	if res.err != nil {
		t.Fatalf("%v\n%s", res.err, res.log)
	}
	if res.outputs["tag"] != "v0.2.0" || res.outputs["created"] != "false" {
		t.Fatalf("outputs: %v", res.outputs)
	}
	if after := git(t, r.origin, "rev-parse", "refs/tags/v0.2.0"); after != before {
		t.Error("the existing tag was moved")
	}
}

func TestRefusesToReleaseTwice(t *testing.T) {
	r := newRepo(t, "v0.1.0")
	res := createTag(t, r, "exists", "patch", "")
	if res.err == nil || !strings.Contains(res.log, "already exists") {
		t.Fatalf("want a refusal, got err=%v\n%s", res.err, res.log)
	}
	if strings.Contains(r.remoteTags(t), "v0.1.1") {
		t.Error("a tag was pushed even though the release exists")
	}
}

// A failing `gh` (auth, network) must not be mistaken for "no release yet".
func TestDoesNotTagWhenReleasesCannotBeChecked(t *testing.T) {
	r := newRepo(t, "v0.1.0")
	res := createTag(t, r, "broken", "patch", "")
	if res.err == nil || !strings.Contains(res.log, "Could not check") {
		t.Fatalf("want the check failure reported, got err=%v\n%s", res.err, res.log)
	}
	if strings.Contains(r.remoteTags(t), "v0.1.1") {
		t.Error("a tag was pushed although the release lookup failed")
	}
}

func TestInvalidInputCreatesNothing(t *testing.T) {
	r := newRepo(t, "v0.1.0")
	res := createTag(t, r, "missing", "patch", "v1.0;rm -rf /")
	if res.err == nil {
		t.Fatal("an invalid tag was accepted")
	}
	if got := r.remoteTags(t); got != "v0.1.0" {
		t.Errorf("origin tags changed: %q", got)
	}
}
