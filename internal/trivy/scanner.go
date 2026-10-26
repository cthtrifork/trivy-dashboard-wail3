package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/distribution/reference"
)

// ScanRequest is what the UI sends to start a scan.
type ScanRequest struct {
	Image         string `json:"image"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IgnoreUnfixed bool   `json:"ignoreUnfixed"`
	// Findings Trivy hides by default. These are "show" flags so the zero value is the default:
	// suppressed (VEX/ignore-file) findings and the will_not_fix and not_affected statuses stay out.
	ShowSuppressed  bool `json:"showSuppressed"`
	ShowWillNotFix  bool `json:"showWillNotFix"`
	ShowNotAffected bool `json:"showNotAffected"`
	// TrivyImage selects the Trivy image or version to scan with. Empty means the default.
	TrivyImage string `json:"trivyImage"`
	// IgnorePolicy is the source of a Rego policy passed to Trivy's --ignore-policy: findings for
	// which it defines `ignore` are left out of the report. Empty means none.
	IgnorePolicy string `json:"ignorePolicy"`
	// IgnoreFile is the source of a .trivyignore.yaml passed to Trivy's --ignorefile: the listed
	// vulnerabilities (with optional statements) are left out of the report. Empty means none.
	IgnoreFile string `json:"ignoreFile"`
	// MarkUnderInvestigation records an under_investigation VEX assessment for every
	// finding that has none after the scan (handled by the service, which owns the store).
	MarkUnderInvestigation bool `json:"markUnderInvestigation"`
}

// ignoreStatus is the --ignore-status value: will_not_fix and not_affected unless shown.
func (r ScanRequest) ignoreStatus() string {
	var ignore []string
	if !r.ShowWillNotFix {
		ignore = append(ignore, "will_not_fix")
	}
	if !r.ShowNotAffected {
		ignore = append(ignore, "not_affected")
	}
	return strings.Join(ignore, ",")
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
	TierWhy        string   `json:"tierWhy"` // the threshold or rule that decided the tier
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
	Summary         *SBOMSummary    `json:"summary"`
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
	// Engine runs Trivy. When nil, real podman is used (see Podman).
	Engine Engine
	// Podman is the podman binary used when Engine is nil; defaults to
	// $PODMAN or "podman".
	Podman string
	// Log receives progress lines (trivy stderr and status messages).
	Log func(string)
	// Enricher adds EPSS/KEV data; nil disables enrichment.
	Enricher *Enricher

	dbMu    sync.Mutex
	dbFresh time.Time // when the vulnerability DB was last confirmed up to date...
	dbImage string    // ...by this Trivy image (another version may want another DB schema)
	dbErr   error     // why the last refresh failed, so a scan that then fails can say so

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{} // closed when the running job has fully finished
}

func (s *Scanner) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log(fmt.Sprintf(format, a...))
	}
}

// Version reports the container engine version, proving it is usable.
func (s *Scanner) Version() (string, error) {
	return s.engine().Version(context.Background())
}

// engine returns the configured Engine, defaulting to real podman.
func (s *Scanner) engine() Engine {
	if s.Engine != nil {
		return s.Engine
	}
	return &PodmanEngine{Bin: s.Podman}
}

// Cancel aborts a running scan, if any.
func (s *Scanner) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

// Running reports whether a scan or comparison is in progress.
func (s *Scanner) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancel != nil
}

// CancelAndWait aborts a running job and waits for it to finish cleaning up (the engine
// stops its container while handling the cancellation), but no longer than grace. It
// reports whether nothing is running any more. Shutdown uses it so quitting never leaves
// a scan behind, while staying within the fast-shutdown budget Wails asks for.
func (s *Scanner) CancelAndWait(grace time.Duration) bool {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return true
	}
	cancel()
	select {
	case <-done:
		return true
	case <-time.After(grace):
		return false
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

// validImage normalises ref and rejects anything that is not a container image
// reference (which also rules out values that could be read as flags).
func validImage(ref string) (string, error) {
	image := NormalizeImage(ref)
	if image == "" {
		return "", errors.New("image reference is empty")
	}
	if _, err := reference.ParseAnyReference(image); err != nil {
		return "", fmt.Errorf("invalid image reference: %w", err)
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
	done := make(chan struct{})
	s.cancel, s.done = cancel, done
	s.mu.Unlock()
	return ctx, func() {
		cancel()
		s.mu.Lock()
		s.cancel, s.done = nil, nil
		s.mu.Unlock()
		close(done)
	}, nil
}

// dbRefresh is how long a confirmed vulnerability DB is trusted before Trivy is asked to check
// for a newer one. Trivy itself only downloads when the DB is past its NextUpdate, so a check is
// cheap, but each one costs a container start and (when stale) a download.
const dbRefresh = time.Hour

// ensureDB makes sure the cached vulnerability DB is current, once per dbRefresh, so that the scans
// themselves can run with --skip-db-update. That means the DB is checked once per session instead
// of once per scan (a comparison is four scans), and a scan with an existing cache still works
// offline: a failed refresh only logs a warning. It returns an error only if ctx was cancelled.
func (s *Scanner) ensureDB(ctx context.Context, trivyImage string, log func(string)) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	if s.dbImage == trivyImage && !s.dbFresh.IsZero() && time.Since(s.dbFresh) < dbRefresh {
		return nil
	}
	s.logf("Checking the vulnerability database (cached between scans)…")
	if _, err := s.engine().RunTrivy(ctx, TrivyJob{TrivyImage: trivyImage, Flags: []string{"--download-db-only"}}, log); err != nil {
		if ctx.Err() != nil {
			return errors.New("cancelled")
		}
		s.logf("Could not update the vulnerability database (%v); using the cached copy if there is one.", err)
		s.dbErr = err
		return nil
	}
	s.dbErr = nil
	s.dbFresh, s.dbImage = time.Now(), trivyImage
	return nil
}

func (s *Scanner) lastDBError() error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	return s.dbErr
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
	policy, err := checkIgnoreText("ignore policy", req.IgnorePolicy, CheckIgnorePolicy)
	if err != nil {
		return nil, err
	}
	ignoreFile, err := checkIgnoreText("ignore file", req.IgnoreFile, CheckIgnoreFile)
	if err != nil {
		return nil, err
	}
	trivyImage, err := ResolveTrivyImage(req.TrivyImage)
	if err != nil {
		return nil, err
	}
	job := TrivyJob{Image: image, Username: req.Username, Password: req.Password, TrivyImage: trivyImage}
	logLine := func(l string) { s.logf("%s", l) }

	if err := s.ensureDB(ctx, trivyImage, logLine); err != nil {
		return nil, err
	}
	s.logf("Scanning %s for vulnerabilities with %s…", image, trivyImage)
	// --list-all-pkgs puts every installed package in the report, not just the vulnerable ones.
	job.Flags = []string{"--skip-db-update", "--format", "json", "--scanners", "vuln", "--list-all-pkgs"}
	if req.IgnoreUnfixed {
		job.Flags = append(job.Flags, "--ignore-unfixed")
	}
	if req.ShowSuppressed {
		job.Flags = append(job.Flags, "--show-suppressed")
	}
	if ignore := req.ignoreStatus(); ignore != "" {
		job.Flags = append(job.Flags, "--ignore-status", ignore)
	}
	job.IgnorePolicy, job.IgnoreFile = policy, ignoreFile // only the vulnerability report is filtered, not the SBOM
	vulnJSON, err := s.engine().RunTrivy(ctx, job, logLine)
	if err != nil {
		if dbErr := s.lastDBError(); dbErr != nil {
			// With an empty cache Trivy only says --skip-db-update is not allowed on a first run;
			// the download error is the actual cause.
			return nil, fmt.Errorf("vulnerability scan failed: %w (the database update had failed: %v)", err, dbErr)
		}
		return nil, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	s.logf("Generating SBOM…")
	job.Flags, job.IgnorePolicy, job.IgnoreFile = []string{"--skip-db-update", "--format", "cyclonedx"}, "", ""
	sbomJSON, err := s.engine().RunTrivy(ctx, job, logLine)
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

// maxIgnoreText bounds the ignore policy and the ignore file: each travels in an environment
// variable, and Windows limits a whole environment block to 32 KiB.
const maxIgnoreText = 24 * 1024

// checkIgnoreText returns the policy or ignore file to use, or "" when it is blank. validate is the
// quick sanity check from ignore.go; Rego and YAML themselves are checked by Trivy, whose error
// reaches the user through the scan log.
func checkIgnoreText(what, src string, validate func(string) error) (string, error) {
	if strings.TrimSpace(src) == "" {
		return "", nil
	}
	if len(src) > maxIgnoreText {
		return "", fmt.Errorf("%s is too large (%d bytes, at most %d)", what, len(src), maxIgnoreText)
	}
	if strings.ContainsRune(src, 0) {
		return "", fmt.Errorf("%s contains a NUL byte", what)
	}
	if err := validate(src); err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	return src, nil
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
	res.ProductPURL = ProductPURL(res.Image)
	for i := range res.Vulnerabilities {
		Assess(&res.Vulnerabilities[i])
	}
	sortVulns(res.Vulnerabilities)
	return nil
}

// sortVulns orders by priority, then severity and CVSS.
func sortVulns(v []Vulnerability) {
	sort.SliceStable(v, func(i, j int) bool { return ranksBefore(&v[i], &v[j]) })
}

func ranksBefore(a, b *Vulnerability) bool {
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
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return err
	}
	var components []cdx.Component
	if bom.Components != nil {
		components = *bom.Components
	}
	res.Components = []Component{}
	res.ComponentTypes = map[string]int{}
	res.DepNodes = map[string]*DepNode{}
	apps := map[string]string{}
	osFamily, osVersion := "", ""
	for i, c := range components {
		var props []cdx.Property
		if c.Properties != nil {
			props = *c.Properties
		}
		typ := string(c.Type)
		for _, p := range props {
			if p.Name != "aquasecurity:trivy:Type" {
				continue
			}
			switch typ {
			case "application":
				apps[c.Name] = p.Value
			case "operating-system":
				osFamily, osVersion = p.Value, c.Version
			}
		}
		comp := Component{Name: c.Name, Version: c.Version, Type: typ, PURL: c.PackageURL, Group: c.Group, Licenses: []string{}}
		var licenses cdx.Licenses
		if c.Licenses != nil {
			licenses = *c.Licenses
		}
		for _, l := range licenses {
			switch {
			case l.License != nil && l.License.ID != "":
				comp.Licenses = append(comp.Licenses, l.License.ID)
			case l.License != nil && l.License.Name != "":
				comp.Licenses = append(comp.Licenses, l.License.Name)
			case l.Expression != "":
				comp.Licenses = append(comp.Licenses, l.Expression)
			}
		}
		res.ComponentTypes[typ]++
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
			Ref: ref, Name: name, Version: c.Version, Type: typ, PURL: c.PackageURL,
			Category: categoryOf(typ, c.PackageURL),
			Children: []string{}, Parents: []string{}, Own: []int{},
			OwnCounts: map[string]int{}, TotalCounts: map[string]int{},
		}
	}
	sort.SliceStable(res.Components, func(i, j int) bool { return res.Components[i].Name < res.Components[j].Name })
	res.Summary = summarize(res, apps, osFamily, osVersion)
	rootRef := ""
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		rootRef = bom.Metadata.Component.BOMRef
	}
	buildDepGraph(res, rootRef, func(yield func(string, []string)) {
		if bom.Dependencies == nil {
			return
		}
		for _, d := range *bom.Dependencies {
			var on []string
			if d.Dependencies != nil {
				on = *d.Dependencies
			}
			yield(d.Ref, on)
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
