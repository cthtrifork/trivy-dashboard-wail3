package main

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
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
	app     *application.App
	scanner *trivy.Scanner
	vex     *trivy.VEXStore

	mu      sync.Mutex
	product map[string]string // image repo -> product purl from the latest scan
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
}

func NewScanService() *ScanService {
	engine, mode := newEngine()
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
	}
	if mode.Fixtures {
		svc.scanner.Enricher = nil // recorded scans stay offline and deterministic
	}
	return svc
}

// ServiceStartup gives the service access to the app so it can emit events.
func (s *ScanService) ServiceStartup(_ context.Context, _ application.ServiceOptions) error {
	s.app = application.Get()
	s.scanner.Log = func(line string) { s.app.Event.Emit("scan:log", line) }
	return nil
}

// Mode reports whether scans are real or replayed demo data.
func (s *ScanService) Mode() Mode { return s.mode }

// PodmanVersion returns the podman version string or an error.
func (s *ScanService) PodmanVersion() (string, error) { return s.scanner.Version() }

// Scan scans the image with trivy running in podman.
func (s *ScanService) Scan(req trivy.ScanRequest) (*trivy.ScanResult, error) {
	res, err := s.scanner.Scan(context.Background(), req)
	if err == nil {
		s.mu.Lock()
		s.product[trivy.ImageRepo(res.Image)] = res.ProductPURL
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
	return s.scanner.Compare(context.Background(), req)
}

// ListTags returns the tags a registry offers for an image repository.
func (s *ScanService) ListTags(repo string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return s.scanner.ListTags(ctx, repo)
}
