//go:build !production

package trivy

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Recorded Trivy output for two real Traefik releases, replayed instead of
// running podman. Used by the Go tests and, when TRIVY_SCANNER_FAKE_PODMAN is
// set, by the screenshot script. Compiled out of production builds
// (-tags production), so a release binary contains neither the data nor a code
// path that uses it.
//
//go:embed fixtures/*.json
var fixtureFiles embed.FS

var (
	// <name>_<version>.json is a `trivy image --format json` report;
	// <name>_<version>.sbom.json is `trivy image --format cyclonedx`.
	vulnFixtureRE = regexp.MustCompile(`^[A-Za-z0-9-]+_(\d+\.\d+\.\d+)\.json$`)
	sbomFixtureRE = regexp.MustCompile(`^[A-Za-z0-9-]+_(\d+\.\d+\.\d+)\.sbom\.json$`)
)

// FixtureEngine implements Engine by replaying the files in fixtures/. It
// ignores the repository part of an image reference and picks the recording by
// tag: "3.7.13", "v3.7.13", "3.7" (newest 3.7.x) or "latest" (newest).
type FixtureEngine struct {
	// FS holds the fixture files; NewFixtureEngine points it at the embedded set.
	FS fs.FS
	// Delay simulates scan time so spinners and the Cancel button are visible.
	Delay time.Duration
}

// NewFixtureEngine returns an engine backed by the embedded fixtures.
func NewFixtureEngine() *FixtureEngine {
	sub, err := fs.Sub(fixtureFiles, "fixtures")
	if err != nil {
		panic(err) // the directory is embedded at compile time
	}
	return &FixtureEngine{FS: sub, Delay: 400 * time.Millisecond}
}

type fixtureSet struct {
	vuln, sbom map[string]string // version -> file name
	versions   []string          // versions with vulnerability data, newest first
}

func (f *FixtureEngine) index() (fixtureSet, error) {
	set := fixtureSet{vuln: map[string]string{}, sbom: map[string]string{}}
	entries, err := fs.ReadDir(f.FS, ".")
	if err != nil {
		return set, err
	}
	for _, e := range entries {
		if m := sbomFixtureRE.FindStringSubmatch(e.Name()); m != nil {
			set.sbom[m[1]] = e.Name()
		} else if m := vulnFixtureRE.FindStringSubmatch(e.Name()); m != nil {
			set.vuln[m[1]] = e.Name()
		}
	}
	for v := range set.vuln {
		set.versions = append(set.versions, v)
	}
	sort.Slice(set.versions, func(i, j int) bool { return compareVersions(set.versions[i], set.versions[j]) > 0 })
	return set, nil
}

// Version identifies the engine, and makes it obvious that scans are not real.
func (f *FixtureEngine) Version(context.Context) (string, error) {
	return "demo mode: replaying recorded Trivy scans, podman is not used", nil
}

// ListTags offers every recorded version plus "latest".
func (f *FixtureEngine) ListTags(context.Context, string) ([]string, error) {
	set, err := f.index()
	if err != nil {
		return nil, err
	}
	return append(append([]string{}, set.versions...), "latest"), nil
}

// RunTrivy returns the recording for the image's tag.
func (f *FixtureEngine) RunTrivy(ctx context.Context, job TrivyJob, log func(string)) ([]byte, error) {
	if slices.Contains(job.Flags, "--download-db-only") {
		return nil, nil // recordings need no vulnerability DB
	}
	set, err := f.index()
	if err != nil {
		return nil, err
	}
	version, err := set.resolve(job.Image)
	if err != nil {
		return nil, err
	}
	wantSBOM := strings.Contains(strings.Join(job.Flags, " "), "cyclonedx")
	name := set.vuln[version]
	if wantSBOM {
		if name = set.sbomFor(version); name == "" {
			return nil, fmt.Errorf("fixture engine: no SBOM fixtures in the bundle")
		}
	}
	log("INFO\t[fixtures] replaying " + name + " for " + job.Image + " (no podman involved)")
	if f.Delay > 0 {
		select {
		case <-time.After(f.Delay):
		case <-ctx.Done():
			return nil, fmt.Errorf("cancelled")
		}
	}
	data, err := fs.ReadFile(f.FS, name)
	if err != nil {
		return nil, err
	}
	if !wantSBOM && strings.Contains(strings.Join(job.Flags, " "), "--ignore-unfixed") {
		return dropUnfixed(data)
	}
	return data, nil
}

// resolve maps an image reference to a recorded version.
func (s fixtureSet) resolve(image string) (string, error) {
	tag := "latest"
	if ref, _, _ := strings.Cut(image, "@"); ref != "" {
		if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
			tag = ref[i+1:]
		}
	}
	tag = strings.TrimPrefix(tag, "v")
	if len(s.versions) > 0 {
		if tag == "latest" {
			return s.versions[0], nil
		}
		if _, ok := s.vuln[tag]; ok {
			return tag, nil
		}
		for _, v := range s.versions { // "3.7" -> newest 3.7.x
			if strings.HasPrefix(v, tag+".") {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("demo mode has no recorded scan for %q. Recorded versions: %s. "+
		"Unset TRIVY_SCANNER_FAKE_PODMAN to scan real images with podman",
		image, strings.Join(s.versions, ", "))
}

// sbomFor returns the SBOM recorded for version. If there is none, it falls
// back to the newest SBOM at or below that version, else to the oldest one.
func (s fixtureSet) sbomFor(version string) string {
	if n, ok := s.sbom[version]; ok {
		return n
	}
	var versions []string
	for v := range s.sbom {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return compareVersions(versions[i], versions[j]) > 0 })
	for _, v := range versions {
		if compareVersions(v, version) <= 0 {
			return s.sbom[v]
		}
	}
	if len(versions) > 0 {
		return s.sbom[versions[len(versions)-1]]
	}
	return ""
}

// dropUnfixed mimics `--ignore-unfixed` by removing findings without a fix.
func dropUnfixed(data []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	results, _ := doc["Results"].([]any)
	for _, r := range results {
		res, ok := r.(map[string]any)
		if !ok {
			continue
		}
		vulns, _ := res["Vulnerabilities"].([]any)
		kept := make([]any, 0, len(vulns))
		for _, v := range vulns {
			if vm, ok := v.(map[string]any); ok {
				if fixed, _ := vm["FixedVersion"].(string); fixed != "" {
					kept = append(kept, v)
				}
			}
		}
		res["Vulnerabilities"] = kept
	}
	return json.Marshal(doc)
}
