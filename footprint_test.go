package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

func TestFootprintMeasuresTheTrivyCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "db"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(trivy.CacheEnv, dir)

	f := (&ScanService{scanner: &trivy.Scanner{}}).Footprint()
	if f.CacheBytes != 100 || f.CacheLocation != dir {
		t.Errorf("cache = %d bytes at %q, want 100 at %q", f.CacheBytes, f.CacheLocation, dir)
	}
}

func TestFootprintIsZeroInDemoMode(t *testing.T) {
	f := (&ScanService{scanner: &trivy.Scanner{}, mode: Mode{Fixtures: true}}).Footprint()
	if f.CacheBytes != 0 || f.MemoryBytes != 0 || f.WebviewBytes != -1 {
		t.Errorf("demo footprint = %+v, want zero cache and memory, no webview", f)
	}
}

func TestFootprintCannotMeasureAPodmanVolume(t *testing.T) {
	t.Setenv(trivy.CacheEnv, "trivy-cache")
	if got := (&ScanService{scanner: &trivy.Scanner{}}).Footprint().CacheBytes; got != -1 {
		t.Errorf("volume cache = %d, want -1 (unmeasurable)", got)
	}
}

func TestFootprintBreaksTheCacheDownBySubdirectory(t *testing.T) {
	dir := t.TempDir()
	for name, n := range map[string]int{"db": 60, "fanal": 40} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "f"), make([]byte, n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	parts := cacheParts(dir)
	if len(parts) != 2 || parts[0] != (FootprintPart{"Trivy db", 60}) || parts[1] != (FootprintPart{"Trivy fanal", 40}) {
		t.Errorf("parts = %+v, want db 60 then fanal 40", parts)
	}
}
