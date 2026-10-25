package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
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
	// TrivyImage is the default Trivy image, shown as the placeholder of the Options field.
	TrivyImage string `json:"trivyImage"`
}

func NewScanService() *ScanService {
	engine, mode := newEngine()
	mode.TrivyImage = trivy.DefaultTrivyImage()
	if mode.Fixtures {
		log.Print("trivy-scanner: " + mode.Detail)
	}
	cache, _ := os.UserCacheDir()
	cfg, _ := os.UserConfigDir()
	vexPath := os.Getenv("TRIVY_SCANNER_VEX_FILE")
	if vexPath == "" {
		vexPath = filepath.Join(cfg, "trivy-scanner", "vex.json")
	}
	svc := &ScanService{
		mode: mode,
		scanner: &trivy.Scanner{Engine: engine, Enricher: &trivy.Enricher{
			CacheDir: filepath.Join(cache, "trivy-scanner"),
			// Overridable for air-gapped mirrors and tests.
			EPSSURL: os.Getenv("TRIVY_SCANNER_EPSS_URL"),
			KEVURL:  os.Getenv("TRIVY_SCANNER_KEV_URL"),
		}},
		vex:     &trivy.VEXStore{Path: vexPath},
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

// Footprint is what the app keeps on disk and in memory, for the footer note.
type Footprint struct {
	// CacheBytes is the Trivy cache (vulnerability DB); -1 when it is a podman volume the app
	// cannot measure. CacheLocation names the directory or volume.
	CacheBytes    int64  `json:"cacheBytes"`
	CacheLocation string `json:"cacheLocation"`
	// AppCacheBytes is the app's own cache (the KEV catalog).
	AppCacheBytes int64 `json:"appCacheBytes"`
	// MemoryBytes estimates the app's memory: the Go runtime's resident share, excluding the
	// webview and the podman containers.
	MemoryBytes int64 `json:"memoryBytes"`
}

// Footprint measures the cache directories and the Go runtime's memory.
func (s *ScanService) Footprint() Footprint {
	f := Footprint{CacheBytes: -1}
	if src, err := trivy.CacheSource(); err == nil {
		f.CacheLocation = src
		if filepath.IsAbs(src) {
			f.CacheBytes = dirSize(src)
		}
	}
	if s.scanner.Enricher != nil {
		f.AppCacheBytes = dirSize(s.scanner.Enricher.CacheDir)
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	f.MemoryBytes = int64(m.Sys - m.HeapReleased)
	return f
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

// Scan scans the image with trivy running in podman.
func (s *ScanService) Scan(req trivy.ScanRequest) (*trivy.ScanResult, error) {
	res, err := s.scanner.Scan(s.appCtx(), req)
	if err == nil {
		s.mu.Lock()
		s.product[trivy.ImageRepo(res.Image)] = res.ProductPURL
		s.found[trivy.ImageRepo(res.Image)] = res.Vulnerabilities
		s.mu.Unlock()
	}
	return res, err
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

// VEXExport renders the image's assessments as an OpenVEX document.
func (s *ScanService) VEXExport(image, author, role string) (string, error) {
	entries, err := s.vex.List(image)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	product := s.product[trivy.ImageRepo(image)]
	s.mu.Unlock()
	if product == "" {
		product = trivy.ProductPURL(image, nil)
	}
	doc, err := trivy.ExportOpenVEX(entries, product, author, role)
	return string(doc), err
}

// VEXImport applies a pasted OpenVEX document to the findings of the latest
// scan of the image and saves the matching assessments.
func (s *ScanService) VEXImport(image, doc string) (trivy.ImportReport, error) {
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
		return rep, errors.New("no statement in the document matched a finding of this scan")
	}
	return rep, s.vex.SetMany(image, entries)
}

// VEXSave exports the document through a native save dialog. It returns the
// chosen path, or "" if the user cancelled. Errors (including headless server
// mode, which has no dialogs) let the UI fall back to a browser download.
func (s *ScanService) VEXSave(image, author, role string) (string, error) {
	doc, err := s.VEXExport(image, author, role)
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

// Compare scans two tags of an image and returns what changed between them.
func (s *ScanService) Compare(req trivy.CompareRequest) (*trivy.CompareResult, error) {
	return s.scanner.Compare(s.appCtx(), req)
}

// ListTags returns the tags a registry offers for an image repository.
func (s *ScanService) ListTags(repo string) ([]string, error) {
	ctx, cancel := context.WithTimeout(s.appCtx(), time.Minute)
	defer cancel()
	return s.scanner.ListTags(ctx, repo)
}
