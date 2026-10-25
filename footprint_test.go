package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

// The Trivy cache lives inside the app's cache directory, so the KEV figure must count only the
// catalog file or the footer would show the Trivy cache twice.
func TestFootprintCountsTheKEVFileNotTheTrivyCache(t *testing.T) {
	app := t.TempDir()
	trivyCache := filepath.Join(app, "trivy")
	if err := os.MkdirAll(trivyCache, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "kev.json"), make([]byte, 5), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trivyCache, "db"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(trivy.CacheEnv, trivyCache)

	s := &ScanService{scanner: &trivy.Scanner{Enricher: &trivy.Enricher{CacheDir: app}}}
	f := s.Footprint()
	if f.CacheBytes != 100 {
		t.Errorf("Trivy cache = %d bytes, want 100", f.CacheBytes)
	}
	if f.AppCacheBytes != 5 {
		t.Errorf("KEV cache = %d bytes, want 5 (the Trivy cache must not be counted again)", f.AppCacheBytes)
	}
}

func TestFootprintWithoutAKEVFile(t *testing.T) {
	s := &ScanService{scanner: &trivy.Scanner{Enricher: &trivy.Enricher{CacheDir: t.TempDir()}}}
	if got := s.Footprint().AppCacheBytes; got != 0 {
		t.Errorf("KEV cache = %d bytes, want 0", got)
	}
}
