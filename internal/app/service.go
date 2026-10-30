package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// ScanService is bound to the frontend. Its exported methods are callable
// from JavaScript as main.ScanService.<Method>.
type ScanService struct {
	mode    Mode
	update  UpdateInfo
	app     *application.App
	scanner *trivy.Scanner
	vex     *trivy.VEXStore

	// ctx is the application context from ServiceStartup, cancelled when shutdown begins.
	ctx context.Context

	mu      sync.Mutex
	product map[string]string                // image repo -> product purl from the latest scan
	found   map[string][]trivy.Vulnerability // image repo -> findings from the latest scan, for VEX import
	last    *trivy.ScanResult                // the most recent scan and the options it ran with, so Compare can reuse it as the base
	lastReq trivy.ScanRequest
	latest  []trivy.Vulnerability // findings of the most recent scan, in the order the UI holds them, for Rescore
}

// Mode tells the UI whether scans are real. Fixtures is true in development
// builds that replay recorded scans; the other fields are demo defaults for
// the input boxes.
type Mode struct {
	Fixtures bool   `json:"fixtures"`
	Detail   string `json:"detail"`
	Image    string `json:"image"` // example image to scan
	Repo     string `json:"repo"`  // example repository for Compare
	TagA     string `json:"tagA"`
	TagB     string `json:"tagB"`
	// TrivyImage is the default Trivy image, the fallback for the Options field.
	TrivyImage string `json:"trivyImage"`
	// RegistryToken is true when GITHUB_TOKEN is set; the token itself never leaves Go.
	// RegistryUser is the login that goes with it. Both only prefill the Options fields (ghcr.io).
	RegistryToken bool   `json:"registryToken"`
	RegistryUser  string `json:"registryUser"`
}

// enrichCacheDir holds the downloaded EPSS and KEV data.
func enrichCacheDir() string {
	cache, _ := os.UserCacheDir()
	return filepath.Join(cache, "trivy-scanner")
}

// vexFile is where VEX assessments are stored: $TRIVY_SCANNER_VEX_FILE or the user config dir.
func vexFile() string {
	if p := loadSettings().VEXFile; p != "" {
		return p
	}
	cfg, _ := os.UserConfigDir()
	return filepath.Join(cfg, "trivy-scanner", "vex.json")
}

func NewScanService() *ScanService {
	engine, mode := newEngine()
	mode.TrivyImage = trivy.DefaultTrivyImage
	if user, _, ok := trivy.GithubLogin(); ok {
		mode.RegistryToken, mode.RegistryUser = true, user
	}
	if mode.Fixtures {
		log.Print("trivy-scanner: " + mode.Detail)
	}
	cfg := loadSettings()
	svc := &ScanService{
		mode: mode,
		scanner: &trivy.Scanner{Engine: engine, Enricher: &trivy.Enricher{
			CacheDir: enrichCacheDir(),
			// Overridable for air-gapped mirrors and tests.
			EPSSURL: cfg.EPSSURL,
			KEVURL:  cfg.KEVURL,
		}},
		vex:     &trivy.VEXStore{Path: vexFile()},
		product: map[string]string{},
		found:   map[string][]trivy.Vulnerability{},
	}
	if mode.Fixtures {
		svc.scanner.Enricher = nil // recorded scans stay offline and deterministic
	}
	return svc
}

// ServiceStartup runs during app.Run, before the event loop. It keeps the application context
// (cancelled when shutdown begins) and gives the service the app so it can emit events. It stays
// fast and cannot fail: a missing podman is reported to the UI, not by aborting startup.
func (s *ScanService) ServiceStartup(ctx context.Context, _ application.ServiceOptions) error {
	// Keep the application context: every scan derives from it, so quitting stops them
	// instead of leaving their podman containers running.
	s.ctx = ctx
	s.app = application.Get()
	s.scanner.Log = func(line string) {
		if ctx.Err() != nil {
			return // shutting down: the window that would show it is going away
		}
		s.app.Event.Emit("scan:log", line)
	}
	s.logInfo("starting", "version", version, "demoMode", s.mode.Fixtures)
	return nil
}

// shutdownGrace is how long ServiceShutdown waits for a running scan to clean up. Wails asks
// for shutdown to stay under about a second, because the OS may kill a slow quitter.
var shutdownGrace = time.Second

// ServiceShutdown runs when the application quits, after the application context has been
// cancelled. A scan in flight is already stopping; this waits (briefly) for its container to be
// removed so closing the window never leaves a scan running in the background.
func (s *ScanService) ServiceShutdown() error {
	if s.scanner.Running() {
		s.logInfo("quitting while a scan is running: stopping it")
	}
	if !s.scanner.CancelAndWait(shutdownGrace) {
		err := fmt.Errorf("a scan did not stop within %v of quitting", shutdownGrace)
		s.logInfo(err.Error())
		return err
	}
	s.logInfo("stopped")
	return nil
}

// appCtx is the context for work started by a binding. It falls back to Background when the
// service has not been started by an application (tests).
func (s *ScanService) appCtx() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// logInfo logs a lifecycle event with Wails' logger when there is one.
func (s *ScanService) logInfo(msg string, args ...any) {
	if s.app != nil && s.app.Logger != nil {
		s.app.Logger.Info("scan service: "+msg, args...)
		return
	}
	log.Print("scan service: " + msg)
}

// Mode reports whether scans are real or replayed demo data.
func (s *ScanService) Mode() Mode { return s.mode }

// Footprint is what the app keeps on disk, for the footer note.
type Footprint struct {
	// Remote is true when podman runs on another host: the cache cannot be measured from here, so
	// the UI shows no footprint at all.
	Remote bool `json:"remote"`
	// CacheBytes is the Trivy cache (vulnerability DB); -1 when it is a podman volume the app
	// cannot measure. CacheLocation names the directory or volume.
	CacheBytes    int64  `json:"cacheBytes"`
	CacheLocation string `json:"cacheLocation"`
	// Parts breaks the footprint down: the Trivy cache by subdirectory (db, java-db, fanal, ...),
	// then the EPSS/KEV data and the VEX file. Empty when the cache is a podman volume.
	Parts []FootprintPart `json:"parts"`
}

// FootprintPart is one named share of the on-disk footprint.
type FootprintPart struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

// Footprint measures the cache directories.
func (s *ScanService) Footprint() Footprint {
	// Demo mode reports zero so the screenshots do not change with the machine or the run.
	if s.mode.Fixtures {
		return Footprint{CacheLocation: "demo"}
	}
	if trivy.Remote() {
		return Footprint{Remote: true, CacheBytes: -1}
	}
	f := Footprint{CacheBytes: -1}
	if src, err := trivy.CacheSource(); err == nil {
		f.CacheLocation = src
		if filepath.IsAbs(src) {
			f.CacheBytes = dirSize(src)
			f.Parts = append(f.Parts, cacheParts(src)...)
		}
	}
	f.Parts = append(f.Parts, FootprintPart{"EPSS and KEV data", filesSize(enrichCacheDir())})
	if fi, err := os.Stat(vexFile()); err == nil {
		f.Parts = append(f.Parts, FootprintPart{"VEX assessments", fi.Size()})
	}
	return f
}

// filesSize sums the regular files directly in dir, not its subdirectories (the Trivy cache can
// live in one of them).
func filesSize(dir string) int64 {
	entries, _ := os.ReadDir(dir)
	var n int64
	for _, e := range entries {
		if e.Type().IsRegular() {
			if info, err := e.Info(); err == nil {
				n += info.Size()
			}
		}
	}
	return n
}

// cachePartName gives the Trivy cache subdirectories names people can read.
func cachePartName(dir string) string {
	switch dir {
	case "db":
		return "Vulnerability database"
	case "java-db":
		return "Java vulnerability database"
	case "fanal":
		return "Scanned image layers"
	}
	return "Trivy " + dir
}

// cacheParts sizes each top-level entry of the Trivy cache (db, java-db, fanal, ...), largest first.
func cacheParts(dir string) []FootprintPart {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var parts []FootprintPart
	for _, e := range entries {
		n := int64(0)
		if e.IsDir() {
			n = dirSize(filepath.Join(dir, e.Name()))
		} else if info, ierr := e.Info(); ierr == nil {
			n = info.Size()
		}
		parts = append(parts, FootprintPart{cachePartName(e.Name()), n})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Bytes > parts[j].Bytes })
	return parts
}

// dirSize sums the regular files under dir; a missing directory is 0.
func dirSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, ierr := d.Info(); ierr == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

// PodmanVersion returns the podman version string or an error.
func (s *ScanService) PodmanVersion() (string, error) { return s.scanner.Version() }

// Scan scans the image with trivy running in podman. It first discards the saved VEX file and
// the findings cached from the previous scan, so a new scan starts from a clean slate.
func (s *ScanService) Scan(req trivy.ScanRequest) (*trivy.ScanResult, error) {
	if err := s.vex.Clear(); err != nil {
		return nil, errors.New("could not clear the old VEX file: " + err.Error())
	}
	s.mu.Lock()
	s.found = map[string][]trivy.Vulnerability{}
	s.latest = nil
	s.last = nil
	s.mu.Unlock()
	res, err := s.scanner.Scan(s.appCtx(), req)
	if err == nil {
		s.mu.Lock()
		s.product[trivy.ImageRepo(res.Image)] = res.ProductPURL
		s.found[trivy.ImageRepo(res.Image)] = res.Vulnerabilities
		s.latest = res.Vulnerabilities
		s.last, s.lastReq = res, req
		s.mu.Unlock()
	}
	return res, err
}

// RestoreScan puts a scan result the frontend remembered across a reload back into the service's
// memory. The findings live only in this process, so after a restart the VEX import and export,
// "mark unassessed" and re-ranking would otherwise claim there is no scan while the UI still
// shows one. Nothing is rescanned and the saved VEX file is kept.
func (s *ScanService) RestoreScan(res *trivy.ScanResult) {
	if res == nil || res.Image == "" {
		return
	}
	repo := trivy.ImageRepo(res.Image)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.product[repo] = res.ProductPURL
	s.found = map[string][]trivy.Vulnerability{repo: res.Vulnerabilities}
	s.latest = res.Vulnerabilities
}

// UpdateDB checks for a newer vulnerability database with the given Trivy version (empty means the
// default) and reports whether Trivy downloaded one. Trivy only downloads when the cached one is out of
// date, and a failure keeps the cache.
func (s *ScanService) UpdateDB(trivyImage string) (bool, error) {
	return s.scanner.UpdateDB(s.appCtx(), trivyImage)
}

// RulePresets returns the built-in scoring presets.
func (s *ScanService) RulePresets() []trivy.Preset { return trivy.Presets() }

// Rescore re-ranks the findings of the latest scan under the given rules, best first. Each
// entry's Index points into the scan result's vulnerabilities. It returns nothing before a scan.
func (s *ScanService) Rescore(rules trivy.Rules) []trivy.Rescored {
	s.mu.Lock()
	vulns := s.latest
	s.mu.Unlock()
	return trivy.Rescore(vulns, rules)
}

// CheckIgnoreFile reports why the text is not a usable .trivyignore.yaml, or "" when it is (or is
// blank). The UI shows it under the field while the user types.
func (s *ScanService) CheckIgnoreFile(text string) string {
	return errText(trivy.CheckIgnoreFile(text))
}

// CheckIgnorePolicy is CheckIgnoreFile for the Rego ignore policy.
func (s *ScanService) CheckIgnorePolicy(text string) string {
	return errText(trivy.CheckIgnorePolicy(text))
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Cancel aborts the running scan.
func (s *ScanService) Cancel() { s.scanner.Cancel() }

// VEXList returns the saved assessments for an image repository.
func (s *ScanService) VEXList(image string) ([]trivy.VEXEntry, error) { return s.vex.List(image) }

// VEXSet validates and saves an assessment.
func (s *ScanService) VEXSet(image string, e trivy.VEXEntry) (trivy.VEXEntry, error) {
	return s.vex.Set(image, e)
}

// VEXDelete removes an assessment.
func (s *ScanService) VEXDelete(image, key string) error { return s.vex.Delete(image, key) }

// VEXExport renders the image's assessments as an OpenVEX document. With
// onlyCurrent, statements that match no finding of the latest scan are left out
// of the document; they stay in the store.
func (s *ScanService) VEXExport(image, author, role string, onlyCurrent bool) (string, error) {
	entries, err := s.vex.List(image)
	if err != nil {
		return "", err
	}
	if onlyCurrent {
		s.mu.Lock()
		findings := s.found[trivy.ImageRepo(image)]
		s.mu.Unlock()
		if len(findings) == 0 {
			return "", errors.New("scan the image first: statements are matched against its findings")
		}
		entries = trivy.MatchingEntries(entries, findings)
	}
	s.mu.Lock()
	product := s.product[trivy.ImageRepo(image)]
	s.mu.Unlock()
	if product == "" {
		product = trivy.ProductPURL(image)
	}
	meta, err := s.vex.Meta(image)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(author) != "" {
		meta.Author = author
	}
	if strings.TrimSpace(role) != "" {
		meta.Role = role
	}
	doc, err := trivy.ExportOpenVEX(entries, product, meta)
	return string(doc), err
}

// VEXImport applies a pasted OpenVEX document to the findings of the latest
// scan of the image and saves the matching assessments. A statement replaces
// the stored assessment of the finding it matches; other stored assessments are
// kept. With markRest, findings still without an assessment afterwards are
// marked under_investigation; a non-empty minSeverity limits that to findings
// of that severity or worse.
func (s *ScanService) VEXImport(image, doc string, markRest bool, minSeverity string) (trivy.ImportReport, error) {
	s.mu.Lock()
	findings := s.found[trivy.ImageRepo(image)]
	s.mu.Unlock()
	if len(findings) == 0 {
		return trivy.ImportReport{}, errors.New("scan the image first: imported statements are matched against its findings")
	}
	entries, rep, err := trivy.ParseOpenVEX([]byte(doc), findings)
	if err != nil {
		return rep, err
	}
	if len(entries) == 0 {
		return rep, errors.New("no valid statement in the document: " + strings.Join(rep.Warnings, "; "))
	}
	if err := s.vex.SetMany(image, entries); err != nil {
		return rep, err
	}
	if err := s.vex.SetMeta(image, rep.Doc); err != nil {
		return rep, err
	}
	if markRest {
		rep.Marked, err = s.vex.MarkUnassessed(image, findings, "", minSeverity)
	}
	return rep, err
}

// VEXMarkUnassessed marks every finding of the latest scan that has no
// assessment as under_investigation and returns how many it marked. A
// non-empty minSeverity limits that to findings of that severity or worse.
func (s *ScanService) VEXMarkUnassessed(image, author, minSeverity string) (int, error) {
	s.mu.Lock()
	findings := s.found[trivy.ImageRepo(image)]
	s.mu.Unlock()
	if len(findings) == 0 {
		return 0, errors.New("scan the image first")
	}
	return s.vex.MarkUnassessed(image, findings, author, minSeverity)
}

// VEXSave exports the document through a native save dialog. It returns the
// chosen path, or "" if the user cancelled. Errors (including headless server
// mode, which has no dialogs) let the UI fall back to a browser download.
func (s *ScanService) VEXSave(image, author, role string, onlyCurrent bool) (string, error) {
	doc, err := s.VEXExport(image, author, role, onlyCurrent)
	if err != nil {
		return "", err
	}
	name := strings.NewReplacer("/", "_", ":", "_").Replace(trivy.ImageRepo(image)) + ".openvex.json"
	path, err := s.app.Dialog.SaveFile().SetFilename(name).AddFilter("OpenVEX (JSON)", "*.json").PromptForSingleSelection()
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		return "", errors.New("saving file: " + err.Error())
	}
	return path, nil
}

// CopyText puts text on the system clipboard. Server mode has no system
// clipboard of its own (it would be the server's, not the browser's), so it
// returns an error and the UI falls back to the browser clipboard.
func (s *ScanService) CopyText(text string) error {
	if headless || s.app == nil {
		return errors.New("no system clipboard in server mode")
	}
	if !s.app.Clipboard.SetText(text) {
		return errors.New("copying to the clipboard failed")
	}
	return nil
}

// Compare scans two tags of an image and returns what changed between them.
// The base is not scanned again when it is the image of the last scan, made with the same options.
func (s *ScanService) Compare(req trivy.CompareRequest) (*trivy.CompareResult, error) {
	s.mu.Lock()
	if s.last != nil && s.lastReq.SameFindings(trivy.ScanRequest{
		IgnoreUnfixed: req.IgnoreUnfixed, ShowSuppressed: req.ShowSuppressed, IgnoreStatus: req.IgnoreStatus,
		TrivyImage: req.TrivyImage, IgnorePolicy: req.IgnorePolicy, IgnoreFile: req.IgnoreFile,
	}) {
		req.Base = s.last
	}
	s.mu.Unlock()
	return s.scanner.Compare(s.appCtx(), req)
}

// ImageParts is an image reference split into its repository and tag.
type ImageParts struct {
	Repo string `json:"repo"`
	Tag  string `json:"tag"`
}

// SplitImage splits an image reference into repository and tag, dropping any digest.
func (s *ScanService) SplitImage(ref string) ImageParts {
	return ImageParts{Repo: trivy.ImageRepo(ref), Tag: trivy.ImageTag(ref)}
}

// ValidateImage says why an image reference cannot be scanned, or returns "" when it can be (or is
// empty, which the field's own "required" covers). It runs the check every scan runs, so the
// field can warn while the reference is typed.
func (s *ScanService) ValidateImage(ref string) string {
	if strings.TrimSpace(ref) == "" {
		return ""
	}
	err := trivy.CheckImage(ref)
	if err == nil {
		return ""
	}
	// The parser's own detail ("repository name … must be lowercase") is the best hint when it has one;
	// its general failure is only "invalid reference format", which says nothing about what to fix.
	detail := strings.TrimPrefix(strings.TrimPrefix(err.Error(), "invalid image reference: "), "invalid reference format")
	detail = strings.TrimPrefix(detail, ": ")
	if detail == "" {
		return "Not a valid image reference. Expected repository[:tag][@sha256:digest], with a lowercase repository and no spaces."
	}
	return strings.ToUpper(detail[:1]) + detail[1:] + "."
}

// LatestTag returns the highest semantic-version tag a registry offers for an image repository,
// preferring one with the same suffix as baseTag (see trivy.Scanner.LatestTag).
func (s *ScanService) LatestTag(repo, baseTag string) (string, error) {
	ctx, cancel := context.WithTimeout(s.appCtx(), time.Minute)
	defer cancel()
	return s.scanner.LatestTag(ctx, repo, baseTag)
}

// ListTags returns the tags a registry offers for an image repository.
func (s *ScanService) ListTags(repo string) ([]string, error) {
	ctx, cancel := context.WithTimeout(s.appCtx(), time.Minute)
	defer cancel()
	return s.scanner.ListTags(ctx, repo)
}
