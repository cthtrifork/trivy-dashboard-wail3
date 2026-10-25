package main

import (
	"os"
	"path/filepath"
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

// envDocs lists the variables worth showing. Dev-only ones are included only in dev builds.
var envDocs = []ConfigEnv{
	{Name: "TRIVY_SCANNER_CACHE", Desc: "Trivy cache source: a podman volume name or an absolute directory on the podman host.", Default: "user cache dir, or volume trivy-cache with a remote podman or on Windows"},
	{Name: "TRIVY_SCANNER_VEX_FILE", Desc: "Where VEX assessments are stored.", Default: "<user config dir>/trivy-scanner/vex.json"},
	{Name: "TRIVY_SCANNER_EPSS_URL", Desc: "EPSS API endpoint, for an air-gapped mirror.", Default: trivy.DefaultEPSSURL},
	{Name: "TRIVY_SCANNER_KEV_URL", Desc: "CISA KEV feed URL, for an air-gapped mirror.", Default: trivy.DefaultKEVURL},
	{Name: "TRIVY_DB_REPOSITORY", Desc: "Trivy vulnerability DB mirror, forwarded into the scanner container when set.", Default: "Trivy default"},
	{Name: "TRIVY_JAVA_DB_REPOSITORY", Desc: "Trivy Java DB mirror, forwarded into the scanner container when set.", Default: "Trivy default"},
	{Name: "PODMAN", Desc: "Path of the podman binary.", Default: "podman"},
	{Name: "CONTAINER_HOST", Desc: "Remote podman socket. Switches the cache default to a named volume.", Default: "local podman"},
	{Name: "DOCKER_HOST", Desc: "Same effect as CONTAINER_HOST.", Default: "local podman"},
	{Name: "WAILS_SERVER_HOST", Desc: "Listen address in server mode. Keep it on loopback.", Default: "127.0.0.1"},
	{Name: "WAILS_SERVER_PORT", Desc: "Listen port in server mode.", Default: "8080"},
	{Name: "XDG_CACHE_HOME", Desc: "Moves the user cache dir (Linux).", Default: "~/.cache"},
	{Name: "XDG_CONFIG_HOME", Desc: "Moves the user config dir (Linux).", Default: "~/.config"},
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
	add := func(label, value, note string) {
		if value != "" {
			c.Paths = append(c.Paths, ConfigPath{label, value, note})
		}
	}
	exe, _ := os.Executable()
	home, _ := os.UserHomeDir()
	cache, _ := os.UserCacheDir()
	cfg, _ := os.UserConfigDir()
	wd, _ := os.Getwd()
	add("Executable", exe, "")
	add("Working directory", wd, "")
	add("Home", home, "")
	add("User cache dir", cache, "")
	add("User config dir", cfg, "")
	if src, err := trivy.CacheSource(); err != nil {
		add("Trivy cache", err.Error(), "invalid TRIVY_SCANNER_CACHE")
	} else if filepath.IsAbs(src) {
		add("Trivy cache", src, "Vulnerability DB on the podman host, mounted at /root/.cache/trivy in the scanner")
	} else {
		add("Trivy cache", "podman volume "+src, "Vulnerability DB, mounted at /root/.cache/trivy in the scanner")
	}
	add("EPSS / KEV cache", enrichCacheDir(), "Downloaded EPSS data and kev.json, reused between scans")
	add("VEX assessments", vexFile(), "Saved per image repository")
	for _, e := range envDocs {
		e.Value, e.Set = os.LookupEnv(e.Name)
		c.Env = append(c.Env, e)
	}
	return c
}
