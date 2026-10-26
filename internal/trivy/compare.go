package trivy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/distribution/reference"
)

// CompareRequest asks for two tags (or digests) of one image to be compared.
type CompareRequest struct {
	Repo          string `json:"repo"`
	TagA          string `json:"tagA"` // base
	TagB          string `json:"tagB"` // target
	Username      string `json:"username"`
	Password      string `json:"password"`
	IgnoreUnfixed bool   `json:"ignoreUnfixed"`
	TrivyImage    string `json:"trivyImage"`   // see ScanRequest.TrivyImage
	IgnorePolicy  string `json:"ignorePolicy"` // see ScanRequest.IgnorePolicy
}

// CompareSide summarises one scanned image.
type CompareSide struct {
	Ref      string         `json:"ref"`
	OS       string         `json:"os"`
	Counts   map[string]int `json:"counts"`
	Total    int            `json:"total"`
	Packages int            `json:"packages"`
	KEV      int            `json:"kev"`
}

// VulnChange is one finding's fate between A and B.
type VulnChange struct {
	Change   string        `json:"change"` // added | removed | unchanged
	Vuln     Vulnerability `json:"vuln"`
	VersionA string        `json:"versionA"`
	VersionB string        `json:"versionB"`
	Cause    string        `json:"cause"`
}

// PkgChange is one package's fate between A and B.
type PkgChange struct {
	Change   string `json:"change"` // added | removed | upgraded | downgraded
	Name     string `json:"name"`
	Type     string `json:"type"`
	Category string `json:"category"`
	PURL     string `json:"purl"`
	VersionA string `json:"versionA"`
	VersionB string `json:"versionB"`
	VulnsA   int    `json:"vulnsA"`
	VulnsB   int    `json:"vulnsB"`
}

// CompareResult is the docker-scout-style comparison of two images.
type CompareResult struct {
	A         CompareSide    `json:"a"`
	B         CompareSide    `json:"b"`
	Vulns     []VulnChange   `json:"vulns"`
	Packages  []PkgChange    `json:"packages"`
	Added     map[string]int `json:"added"`     // vulnerabilities only in B, by severity
	Removed   map[string]int `json:"removed"`   // vulnerabilities only in A, by severity
	Unchanged map[string]int `json:"unchanged"` // in both
	Verdict   string         `json:"verdict"`
}

// Compare scans both images (one cancellable job) and diffs the results.
func (s *Scanner) Compare(parent context.Context, req CompareRequest) (*CompareResult, error) {
	refA, err := tagRef(req.Repo, req.TagA)
	if err != nil {
		return nil, err
	}
	refB, err := tagRef(req.Repo, req.TagB)
	if err != nil {
		return nil, err
	}
	if refA == refB {
		return nil, errors.New("choose two different tags")
	}
	ctx, release, err := s.begin(parent)
	if err != nil {
		return nil, err
	}
	defer release()

	scan := func(label, ref string) (*ScanResult, error) {
		s.logf("=== %s: %s ===", label, ref)
		return s.scanImage(ctx, ScanRequest{Image: ref, Username: req.Username, Password: req.Password, IgnoreUnfixed: req.IgnoreUnfixed, TrivyImage: req.TrivyImage, IgnorePolicy: req.IgnorePolicy})
	}
	a, err := scan("Base", refA)
	if err != nil {
		return nil, fmt.Errorf("scanning %s: %w", refA, err)
	}
	b, err := scan("Target", refB)
	if err != nil {
		return nil, fmt.Errorf("scanning %s: %w", refB, err)
	}
	return Diff(a, b), nil
}

// tagRef joins a repository and a tag or digest.
func tagRef(repo, tag string) (string, error) {
	repo = ImageRepo(repo)
	tag = strings.TrimSpace(tag)
	if repo == "" || tag == "" {
		return "", errors.New("image repository and both tags are required")
	}
	ref := repo + ":" + tag
	if strings.HasPrefix(tag, "sha256:") {
		ref = repo + "@" + tag
	}
	if _, err := reference.ParseNormalizedNamed(ref); err != nil {
		return "", fmt.Errorf("invalid tag %q: %w", tag, err)
	}
	return ref, nil
}

// ListTags returns the tags the engine can offer for repo, newest first.
func (s *Scanner) ListTags(ctx context.Context, repo string) ([]string, error) {
	repo = ImageRepo(repo)
	if _, err := validImage(repo); err != nil {
		return nil, err
	}
	raw, err := s.engine().ListTags(ctx, qualifyRepo(repo))
	if err != nil {
		return nil, err
	}
	var tags []string
	seen := map[string]bool{}
	for _, t := range raw {
		if t != "" && t != "TAG" && !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}
	sort.Slice(tags, func(i, j int) bool { return compareVersions("", tags[i], tags[j]) > 0 })
	return tags, nil
}

// qualifyRepo makes the registry explicit, defaulting to Docker Hub. `podman search`
// with an unqualified name searches every registry in the host's
// unqualified-search-registries, and on Fedora/RHEL that list starts with
// registry.fedoraproject.org and registry.access.redhat.com, so "nginx" would list
// tags from the wrong registry. Trivy resolves bare names to Docker Hub itself.
func qualifyRepo(repo string) string {
	named, err := reference.ParseNormalizedNamed(repo)
	if err != nil {
		return repo
	}
	return named.Name()
}

// pkgKey identifies a package independent of its version.
func pkgKey(purl, name string) string {
	if purl != "" {
		if n, _ := splitPURL(purl); n != "" {
			return n
		}
		p, _, _ := strings.Cut(purl, "@")
		return p
	}
	return name
}

type pkgInfo struct {
	version string
	comp    Component
	vulns   int
}

func packagesOf(r *ScanResult) map[string]*pkgInfo {
	m := map[string]*pkgInfo{}
	for _, c := range r.Components {
		if c.Type == "operating-system" || c.Type == "application" || c.Type == "container" {
			continue
		}
		name := c.Name
		if c.Group != "" {
			name = c.Group + "/" + name
		}
		k := pkgKey(c.PURL, name)
		if _, ok := m[k]; !ok {
			m[k] = &pkgInfo{version: c.Version, comp: c}
		}
	}
	for _, v := range r.Vulnerabilities {
		if p := m[pkgKey(v.PURL, v.Package)]; p != nil {
			p.vulns++
		}
	}
	return m
}

func side(ref string, r *ScanResult, pk map[string]*pkgInfo) CompareSide {
	s := CompareSide{Ref: ref, OS: r.OS, Counts: r.SeverityCounts, Total: len(r.Vulnerabilities), Packages: len(pk)}
	for _, v := range r.Vulnerabilities {
		if v.KEV {
			s.KEV++
		}
	}
	return s
}

// Diff compares scan results a (base) and b (target).
func Diff(a, b *ScanResult) *CompareResult {
	pa, pb := packagesOf(a), packagesOf(b)
	res := &CompareResult{
		A: side(a.Image, a, pa), B: side(b.Image, b, pb),
		Vulns: []VulnChange{}, Packages: []PkgChange{},
		Added: map[string]int{}, Removed: map[string]int{}, Unchanged: map[string]int{},
	}

	// The scan target is deliberately not part of the key: trivy names it after the
	// image reference ("web:1.0 (debian 12.5)"), so it differs between tags.
	vkey := func(v Vulnerability) string { return v.ID + "|" + pkgKey(v.PURL, v.Package) }
	inA := map[string][]int{}
	for i, v := range a.Vulnerabilities {
		inA[vkey(v)] = append(inA[vkey(v)], i)
	}
	matchedA := map[int]bool{}
	for _, v := range b.Vulnerabilities {
		k := vkey(v)
		if q := inA[k]; len(q) > 0 {
			av := a.Vulnerabilities[q[0]]
			inA[k] = q[1:]
			matchedA[q[0]] = true
			res.Unchanged[v.Severity]++
			res.Vulns = append(res.Vulns, VulnChange{Change: "unchanged", Vuln: v, VersionA: av.Installed, VersionB: v.Installed})
			continue
		}
		pk := pkgKey(v.PURL, v.Package)
		cause := "reported now but not in the base image (newly disclosed or newly detected)"
		if p, ok := pa[pk]; !ok {
			cause = "comes from a package that is new in the target"
		} else if p.version != v.Installed {
			cause = fmt.Sprintf("package changed %s → %s", p.version, v.Installed)
		}
		res.Added[v.Severity]++
		res.Vulns = append(res.Vulns, VulnChange{Change: "added", Vuln: v, VersionB: v.Installed, Cause: cause})
	}
	for i, v := range a.Vulnerabilities {
		if matchedA[i] {
			continue
		}
		pk := pkgKey(v.PURL, v.Package)
		cause := "no longer reported in the target"
		if p, ok := pb[pk]; !ok {
			cause = "the vulnerable package was removed"
		} else if p.version != v.Installed {
			cause = fmt.Sprintf("fixed by changing %s → %s", v.Installed, p.version)
		}
		res.Removed[v.Severity]++
		res.Vulns = append(res.Vulns, VulnChange{Change: "removed", Vuln: v, VersionA: v.Installed, Cause: cause})
	}
	rank := map[string]int{"added": 0, "removed": 1, "unchanged": 2}
	sort.SliceStable(res.Vulns, func(i, j int) bool {
		x, y := res.Vulns[i], res.Vulns[j]
		if rank[x.Change] != rank[y.Change] {
			return rank[x.Change] < rank[y.Change]
		}
		if x.Vuln.Priority != y.Vuln.Priority {
			return x.Vuln.Priority > y.Vuln.Priority
		}
		return severityRank[x.Vuln.Severity] < severityRank[y.Vuln.Severity]
	})

	for k, p := range pa {
		q, ok := pb[k]
		switch {
		case !ok:
			res.Packages = append(res.Packages, pkgChange("removed", p, nil))
		case p.version != q.version:
			ch := "upgraded"
			if compareVersions(p.comp.PURL, q.version, p.version) < 0 {
				ch = "downgraded"
			}
			res.Packages = append(res.Packages, pkgChange(ch, p, q))
		}
	}
	for k, q := range pb {
		if _, ok := pa[k]; !ok {
			res.Packages = append(res.Packages, pkgChange("added", nil, q))
		}
	}
	sort.Slice(res.Packages, func(i, j int) bool {
		x, y := res.Packages[i], res.Packages[j]
		if x.Change != y.Change {
			return x.Change < y.Change
		}
		return x.Name < y.Name
	})
	res.Verdict = verdict(res)
	return res
}

func pkgChange(change string, a, b *pkgInfo) PkgChange {
	c := PkgChange{Change: change}
	ref := b
	if ref == nil {
		ref = a
	}
	c.Name, c.Type, c.PURL = ref.comp.Name, ref.comp.Type, ref.comp.PURL
	if ref.comp.Group != "" {
		c.Name = ref.comp.Group + "/" + c.Name
	}
	c.Category = categoryOf(ref.comp.Type, ref.comp.PURL)
	if a != nil {
		c.VersionA, c.VulnsA = a.version, a.vulns
	}
	if b != nil {
		c.VersionB, c.VulnsB = b.version, b.vulns
	}
	return c
}

func sum(m map[string]int) (n int) {
	for _, v := range m {
		n += v
	}
	return
}

func verdict(r *CompareResult) string {
	add, rem := sum(r.Added), sum(r.Removed)
	net := add - rem
	ch := func(m map[string]int) int { return m["CRITICAL"] + m["HIGH"] }
	var out string
	switch {
	case add == 0 && rem == 0:
		out = "No vulnerability differences between the two images."
	case net < 0:
		out = fmt.Sprintf("The target is better: %d fewer vulnerabilities (%d removed, %d introduced).", -net, rem, add)
	case net > 0:
		out = fmt.Sprintf("The target is worse: %d more vulnerabilities (%d introduced, %d removed).", net, add, rem)
	default:
		out = fmt.Sprintf("The total is unchanged, but %d vulnerabilities were swapped for %d others.", rem, add)
	}
	if d := ch(r.Added) - ch(r.Removed); d != 0 || ch(r.Added) > 0 {
		out += fmt.Sprintf(" Critical+High: %d → %d.", ch(r.A.Counts), ch(r.B.Counts))
	}
	if r.B.KEV > r.A.KEV {
		out += fmt.Sprintf(" ⚠ %d more known-exploited (KEV) finding(s).", r.B.KEV-r.A.KEV)
	}
	return out
}
