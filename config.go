package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

// ConfigPath is one resolved location the app reads or writes.
type ConfigPath struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Note  string `json:"note"`
}

// ConfigEnv is one environment variable the app honours, with its value in this process.
type ConfigEnv struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Set     bool   `json:"set"`
	Desc    string `json:"desc"`
	Default string `json:"default"`
}

// AppConfig is the resolved configuration for the help dialog: the paths and environment as this
// process sees them, so nothing shown there is a guess.
type AppConfig struct {
	Version  string       `json:"version"`
	Platform string       `json:"platform"`
	Headless bool         `json:"headless"`
	Podman   string       `json:"podman"`
	Remote   bool         `json:"remote"`
	Paths    []ConfigPath `json:"paths"`
	Env      []ConfigEnv  `json:"env"`
}

// Config resolves the app's paths and environment for the help dialog.
func (s *ScanService) Config() AppConfig {
	c := AppConfig{
		Version:  version,
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Headless: headless,
		Podman:   trivy.PodmanBin(),
		Remote:   trivy.Remote(),
	}
	exe, _ := os.Executable()
	home, _ := os.UserHomeDir()
	cache, _ := os.UserCacheDir()
	cfg, _ := os.UserConfigDir()
	wd, _ := os.Getwd()
	trivyCache, trivyNote := "", "Vulnerability DB, mounted at /root/.cache/trivy in the scanner"
	if src, err := trivy.CacheSource(); err != nil {
		trivyCache, trivyNote = err.Error(), "invalid TRIVY_SCANNER_CACHE"
	} else if filepath.IsAbs(src) {
		trivyCache, trivyNote = src, "Vulnerability DB on the podman host, mounted at /root/.cache/trivy in the scanner"
	} else {
		trivyCache = "podman volume " + src
	}
	for _, p := range []ConfigPath{
		{"Executable", exe, ""},
		{"Working directory", wd, ""},
		{"Home", home, ""},
		{"User cache dir", cache, ""},
		{"User config dir", cfg, ""},
		{"Trivy cache", trivyCache, trivyNote},
		{"EPSS / KEV cache", enrichCacheDir(), "Downloaded EPSS data and kev.json, reused between scans"},
		{"VEX assessments", vexFile(), "Saved per image repository"},
	} {
		if p.Value != "" {
			c.Paths = append(c.Paths, p)
		}
	}
	// The desc and def tags on settings document each variable.
	for _, f := range reflect.VisibleFields(reflect.TypeFor[settings]()) {
		if desc := f.Tag.Get("desc"); desc != "" {
			e := ConfigEnv{Name: f.Tag.Get("env"), Desc: desc, Default: f.Tag.Get("def")}
			e.Value, e.Set = os.LookupEnv(e.Name)
			c.Env = append(c.Env, e)
		}
	}
	return c
}
