package trivy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

// TrivyImage is the container image used to run the scanner.
const TrivyImage = "docker.io/aquasec/trivy:latest"

// ScanRequest is what the UI sends to start a scan.
type ScanRequest struct {
	Image         string `json:"image"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IgnoreUnfixed bool   `json:"ignoreUnfixed"`
}

// Vulnerability is one finding, flattened from trivy's JSON report.
type Vulnerability struct {
	ID          string  `json:"id"`
	Package     string  `json:"package"`
	Installed   string  `json:"installed"`
	Fixed       string  `json:"fixed"`
	Severity    string  `json:"severity"`
	Status      string  `json:"status"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	URL         string  `json:"url"`
	Target      string  `json:"target"`
	Score       float64 `json:"score"`
	PURL        string  `json:"purl"`

	// Exploitation signals and prioritisation (see enrich.go / assess.go).
	Vector         string   `json:"vector"`
	HasEPSS        bool     `json:"hasEpss"`
	EPSS           float64  `json:"epss"`
	EPSSPercentile float64  `json:"epssPercentile"`
	KEV            bool     `json:"kev"`
	KEVRansomware  bool     `json:"kevRansomware"`
	KEVAdded       string   `json:"kevAdded"`
	KEVDue         string   `json:"kevDue"`
	KEVAction      string   `json:"kevAction"`
	Priority       int      `json:"priority"`
	Tier           string   `json:"tier"`
	Reasons        []Reason `json:"reasons"`
	Attack         string   `json:"attack"`
	Key            string   `json:"key"` // VEX key
}

// Component is one SBOM entry, flattened from CycloneDX JSON.
type Component struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"`
	PURL     string   `json:"purl"`
	Licenses []string `json:"licenses"`
	Group    string   `json:"group"`
}

// ScanResult is returned to the UI.
type ScanResult struct {
	Image           string          `json:"image"`
	OS              string          `json:"os"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	SeverityCounts  map[string]int  `json:"severityCounts"`
	Components      []Component     `json:"components"`
	ComponentTypes  map[string]int  `json:"componentTypes"`
	SBOMFormat      string          `json:"sbomFormat"`
	// Dependency graph. Nodes are keyed by CycloneDX bom-ref; DepRoots are the
	// entry points to start navigating from.
	DepNodes map[string]*DepNode `json:"depNodes"`
	DepRoots []string            `json:"depRoots"`

	// ProductPURL identifies the scanned image in VEX documents.
	ProductPURL string     `json:"productPurl"`
	Enrichment  EnrichInfo `json:"enrichment"`
}

// DepNode is one component in the dependency graph with its vulnerability data.
type DepNode struct {
	Ref      string   `json:"ref"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"`
	Category string   `json:"category"` // "OS" or "Application"
	PURL     string   `json:"purl"`
	Children []string `json:"children"` // depends on
	Parents  []string `json:"parents"`  // required by
	// Own lists indexes into ScanResult.Vulnerabilities affecting this component.
	Own []int `json:"own"`
	// OwnCounts / TotalCounts are per-severity counts for the component itself
	// and for the component plus everything beneath it (distinct findings).
	OwnCounts   map[string]int `json:"ownCounts"`
	TotalCounts map[string]int `json:"totalCounts"`
}

// Scanner runs trivy inside a podman container.
type Scanner struct {
	// Podman is the podman binary; defaults to $PODMAN or "podman".
	Podman string
	// Log receives progress lines (trivy stderr and status messages).
	Log func(string)
	// Enricher adds EPSS/KEV data; nil disables enrichment.
	Enricher *Enricher

	mu     sync.Mutex
	cancel context.CancelFunc
}

func (s *Scanner) podman() string {
	if s.Podman != "" {
		return s.Podman
	}
	if p := os.Getenv("PODMAN"); p != "" {
		return p
	}
	return "podman"
}

func (s *Scanner) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log(fmt.Sprintf(format, a...))
	}
}

// Version reports the podman version, proving podman is usable.
func (s *Scanner) Version() (string, error) {
	out, err := exec.Command(s.podman(), "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("podman not available: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Cancel aborts a running scan, if any.
func (s *Scanner) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

// NormalizeImage trims whitespace and common URL-ish prefixes.
func NormalizeImage(ref string) string {
	ref = strings.TrimSpace(ref)
	for _, p := range []string{"docker://", "https://", "http://"} {
		ref = strings.TrimPrefix(ref, p)
	}
	return ref
}

// validImage normalises ref and rejects values that could be read as flags.
func validImage(ref string) (string, error) {
	image := NormalizeImage(ref)
	if image == "" {
		return "", errors.New("image reference is empty")
	}
	if strings.HasPrefix(image, "-") || strings.ContainsAny(image, " \t\r\n") {
		return "", errors.New("invalid image reference")
	}
	return image, nil
}

// begin claims the single job slot; release must be called when the job ends.
func (s *Scanner) begin(parent context.Context) (context.Context, func(), error) {
	ctx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		cancel()
		return nil, nil, errors.New("a scan is already running")
	}
	s.cancel = cancel
	s.mu.Unlock()
	return ctx, func() {
		cancel()
		s.mu.Lock()
		s.cancel = nil
		s.mu.Unlock()
	}, nil
}

// Scan runs a vulnerability scan and an SBOM generation for the image.
func (s *Scanner) Scan(parent context.Context, req ScanRequest) (*ScanResult, error) {
	if _, err := validImage(req.Image); err != nil {
		return nil, err
	}
	ctx, release, err := s.begin(parent)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.scanImage(ctx, req)
}

func (s *Scanner) scanImage(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	image, err := validImage(req.Image)
	if err != nil {
		return nil, err
	}
	env := os.Environ()
	if req.Username != "" {
		env = append(env, "TRIVY_USERNAME="+req.Username, "TRIVY_PASSWORD="+req.Password)
	}

	s.logf("Scanning %s for vulnerabilities…", image)
	vulnArgs := []string{"--format", "json", "--scanners", "vuln"}
	if req.IgnoreUnfixed {
		vulnArgs = append(vulnArgs, "--ignore-unfixed")
	}
	vulnJSON, err := s.runTrivy(ctx, env, req.Username != "", image, vulnArgs)
	if err != nil {
		return nil, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	s.logf("Generating SBOM…")
	sbomJSON, err := s.runTrivy(ctx, env, req.Username != "", image, []string{"--format", "cyclonedx"})
	if err != nil {
		return nil, fmt.Errorf("SBOM generation failed: %w", err)
	}

	res := &ScanResult{Image: image, SBOMFormat: "CycloneDX"}
	if err := parseVulns(vulnJSON, res); err != nil {
		return nil, fmt.Errorf("parsing vulnerability report: %w", err)
	}
	if s.Enricher != nil {
		s.logf("Fetching EPSS and CISA KEV data…")
		res.Enrichment = s.Enricher.Enrich(ctx, res.Vulnerabilities)
		for _, w := range res.Enrichment.Warnings {
			s.logf("warning: %s", w)
		}
	}
	sortVulns(res.Vulnerabilities)
	if err := parseSBOM(sbomJSON, res); err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}
	s.logf("Done: %d vulnerabilities, %d components.", len(res.Vulnerabilities), len(res.Components))
	return res, nil
}

// runTrivy runs `trivy image <flags> <image>` in a throwaway container and
// returns stdout. A named volume caches the vulnerability DB between runs.
func (s *Scanner) runTrivy(ctx context.Context, env []string, creds bool, image string, flags []string) ([]byte, error) {
	args := []string{"run", "--rm", "-v", "trivy-cache:/root/.cache/trivy"}
	if creds {
		args = append(args, "-e", "TRIVY_USERNAME", "-e", "TRIVY_PASSWORD")
	}
	args = append(args, TrivyImage, "image")
	args = append(args, flags...)
	args = append(args, image)

	cmd := exec.CommandContext(ctx, s.podman(), args...)
	cmd.Env = env
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting podman: %w", err)
	}

	var tail []string
	sc := bufio.NewScanner(io.Reader(stderr))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		s.logf("%s", line)
		if tail = append(tail, line); len(tail) > 5 {
			tail = tail[1:]
		}
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("cancelled")
		}
		return nil, fmt.Errorf("%w: %s", err, strings.Join(tail, "\n"))
	}
	return stdout.Bytes(), nil
}

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

func parseVulns(data []byte, res *ScanResult) error {
	var rep struct {
		Metadata struct {
			OS          *struct{ Family, Name string }
			RepoDigests []string
		}
		Results []struct {
			Target          string
			Vulnerabilities []struct {
				VulnerabilityID  string
				PkgName          string
				InstalledVersion string
				FixedVersion     string
				Status           string
				Severity         string
				Title            string
				Description      string
				PrimaryURL       string
				PkgIdentifier    struct{ PURL string }
				CVSS             map[string]struct {
					V3Vector string
					V2Vector string
					V3Score  float64
					V2Score  float64
				}
			}
		}
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		return err
	}
	if o := rep.Metadata.OS; o != nil {
		res.OS = strings.TrimSpace(o.Family + " " + o.Name)
	}
	res.Vulnerabilities = []Vulnerability{}
	res.SeverityCounts = map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			sev := strings.ToUpper(v.Severity)
			if _, ok := severityRank[sev]; !ok {
				sev = "UNKNOWN"
			}
			var score float64
			for _, c := range v.CVSS {
				score = max(score, c.V3Score, c.V2Score)
			}
			vector := pickVector(v.CVSS)
			res.SeverityCounts[sev]++
			res.Vulnerabilities = append(res.Vulnerabilities, Vulnerability{
				ID: v.VulnerabilityID, Package: v.PkgName, Installed: v.InstalledVersion,
				Fixed: v.FixedVersion, Severity: sev, Status: v.Status, Title: v.Title,
				Description: v.Description, URL: v.PrimaryURL, Target: r.Target, Score: score,
				PURL: v.PkgIdentifier.PURL, Vector: vector,
				Key: VEXKey(v.VulnerabilityID, v.PkgIdentifier.PURL, v.PkgName, v.InstalledVersion),
			})
		}
	}
	res.ProductPURL = ProductPURL(res.Image, rep.Metadata.RepoDigests)
	for i := range res.Vulnerabilities {
		Assess(&res.Vulnerabilities[i])
	}
	sortVulns(res.Vulnerabilities)
	return nil
}

// sortVulns orders by priority, then severity and CVSS.
func sortVulns(v []Vulnerability) {
	sort.SliceStable(v, func(i, j int) bool {
		a, b := v[i], v[j]
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.EPSS != b.EPSS { // scores are capped at 100, so break ties by exploitation odds
			return a.EPSS > b.EPSS
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		return a.Score > b.Score
	})
}

// pickVector prefers NVD's CVSS v3 vector, then any v3, then v2.
func pickVector(cvss map[string]struct {
	V3Vector string
	V2Vector string
	V3Score  float64
	V2Score  float64
}) string {
	keys := make([]string, 0, len(cvss))
	for k := range cvss {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if c, ok := cvss["nvd"]; ok && c.V3Vector != "" {
		return c.V3Vector
	}
	for _, k := range keys {
		if cvss[k].V3Vector != "" {
			return cvss[k].V3Vector
		}
	}
	for _, k := range keys {
		if cvss[k].V2Vector != "" {
			return cvss[k].V2Vector
		}
	}
	return ""
}

var osPURLTypes = map[string]bool{"deb": true, "apk": true, "rpm": true, "alpm": true}

func categoryOf(typ, purl string) string {
	if typ == "operating-system" {
		return "OS"
	}
	if rest, ok := strings.CutPrefix(purl, "pkg:"); ok {
		t, _, _ := strings.Cut(rest, "/")
		if osPURLTypes[t] {
			return "OS"
		}
	}
	return "Application"
}

func parseSBOM(data []byte, res *ScanResult) error {
	var bom struct {
		Metadata struct {
			Component struct {
				BOMRef string `json:"bom-ref"`
			}
		}
		Components []struct {
			BOMRef   string `json:"bom-ref"`
			Type     string
			Group    string
			Name     string
			Version  string
			PURL     string `json:"purl"`
			Licenses []struct {
				License    *struct{ ID, Name string }
				Expression string
			}
		}
		Dependencies []struct {
			Ref       string
			DependsOn []string
		}
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		return err
	}
	res.Components = []Component{}
	res.ComponentTypes = map[string]int{}
	res.DepNodes = map[string]*DepNode{}
	for i, c := range bom.Components {
		comp := Component{Name: c.Name, Version: c.Version, Type: c.Type, PURL: c.PURL, Group: c.Group, Licenses: []string{}}
		for _, l := range c.Licenses {
			switch {
			case l.License != nil && l.License.ID != "":
				comp.Licenses = append(comp.Licenses, l.License.ID)
			case l.License != nil && l.License.Name != "":
				comp.Licenses = append(comp.Licenses, l.License.Name)
			case l.Expression != "":
				comp.Licenses = append(comp.Licenses, l.Expression)
			}
		}
		res.ComponentTypes[c.Type]++
		res.Components = append(res.Components, comp)

		ref := c.BOMRef
		if ref == "" {
			ref = fmt.Sprintf("component-%d", i)
		}
		name := c.Name
		if c.Group != "" {
			name = c.Group + "/" + name
		}
		res.DepNodes[ref] = &DepNode{
			Ref: ref, Name: name, Version: c.Version, Type: c.Type, PURL: c.PURL,
			Category: categoryOf(c.Type, c.PURL),
			Children: []string{}, Parents: []string{}, Own: []int{},
			OwnCounts: map[string]int{}, TotalCounts: map[string]int{},
		}
	}
	sort.SliceStable(res.Components, func(i, j int) bool { return res.Components[i].Name < res.Components[j].Name })
	buildDepGraph(res, bom.Metadata.Component.BOMRef, func(yield func(string, []string)) {
		for _, d := range bom.Dependencies {
			yield(d.Ref, d.DependsOn)
		}
	})
	return nil
}

// buildDepGraph links nodes, attaches vulnerabilities and aggregates counts.
func buildDepGraph(res *ScanResult, rootRef string, edges func(func(string, []string))) {
	nodes := res.DepNodes
	var rootChildren []string
	edges(func(ref string, deps []string) {
		for _, d := range deps {
			if nodes[d] == nil {
				continue
			}
			if ref == rootRef {
				rootChildren = append(rootChildren, d)
				continue
			}
			if p := nodes[ref]; p != nil {
				p.Children = append(p.Children, d)
				nodes[d].Parents = append(nodes[d].Parents, ref)
			}
		}
	})

	// Roots: the image's direct dependencies plus anything nothing else points to.
	seen := map[string]bool{}
	res.DepRoots = []string{}
	for _, r := range rootChildren {
		if !seen[r] {
			seen[r] = true
			res.DepRoots = append(res.DepRoots, r)
		}
	}
	for ref, n := range nodes {
		if len(n.Parents) == 0 && !seen[ref] {
			seen[ref] = true
			res.DepRoots = append(res.DepRoots, ref)
		}
	}
	less := func(a, b string) bool {
		na, nb := nodes[a], nodes[b]
		if na.Category != nb.Category {
			return na.Category < nb.Category
		}
		return na.Name < nb.Name
	}
	sort.Slice(res.DepRoots, func(i, j int) bool { return less(res.DepRoots[i], res.DepRoots[j]) })
	for _, n := range nodes {
		sort.Slice(n.Children, func(i, j int) bool { return less(n.Children[i], n.Children[j]) })
		sort.Strings(n.Parents)
	}

	// Attach vulnerabilities by purl, falling back to name@version.
	byPURL, byNV := map[string]*DepNode{}, map[string]*DepNode{}
	for _, n := range nodes {
		if n.PURL != "" {
			byPURL[n.PURL] = n
		}
		byNV[strings.ToLower(n.Name+"@"+n.Version)] = n
	}
	for i, v := range res.Vulnerabilities {
		n := byPURL[v.PURL]
		if n == nil {
			n = byNV[strings.ToLower(v.Package+"@"+v.Installed)]
		}
		if n != nil {
			n.Own = append(n.Own, i)
			n.OwnCounts[v.Severity]++
		}
	}

	// Total = distinct findings in the node's subtree (cycle-safe).
	for _, n := range nodes {
		visited := map[string]bool{}
		distinct := map[int]bool{}
		var walk func(*DepNode)
		walk = func(x *DepNode) {
			if visited[x.Ref] {
				return
			}
			visited[x.Ref] = true
			for _, i := range x.Own {
				distinct[i] = true
			}
			for _, c := range x.Children {
				walk(nodes[c])
			}
		}
		walk(n)
		for i := range distinct {
			n.TotalCounts[res.Vulnerabilities[i].Severity]++
		}
	}
}
