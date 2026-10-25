package main

import (
	"github.com/caarlos0/env/v11"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

// settings are all the environment variables the app documents. The desc and def tags feed the
// help dialog (def is prose, not applied); fields nothing reads are listed for that dialog only.
// It is parsed on every use, not cached, so tests can change the environment with t.Setenv.
type settings struct {
	trivy.Env
	VEXFile    string `env:"TRIVY_SCANNER_VEX_FILE" desc:"Where VEX assessments are stored." def:"<user config dir>/trivy-scanner/vex.json"`
	EPSSURL    string `env:"TRIVY_SCANNER_EPSS_URL" desc:"EPSS API endpoint, for an air-gapped mirror." def:"https://api.first.org/data/v1/epss"`
	KEVURL     string `env:"TRIVY_SCANNER_KEV_URL" desc:"CISA KEV feed URL, for an air-gapped mirror." def:"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"`
	FakePodman bool   `env:"TRIVY_SCANNER_FAKE_PODMAN"`

	WailsHost string `env:"WAILS_SERVER_HOST" desc:"Listen address in server mode. Keep it on loopback." def:"127.0.0.1"`
	WailsPort string `env:"WAILS_SERVER_PORT" desc:"Listen port in server mode." def:"8080"`
	XDGCache  string `env:"XDG_CACHE_HOME" desc:"Moves the user cache dir (Linux)." def:"~/.cache"`
	XDGConfig string `env:"XDG_CONFIG_HOME" desc:"Moves the user config dir (Linux)." def:"~/.config"`
}

// loadSettings reads the environment. A malformed value (say a non-boolean flag) leaves that
// field at its zero value.
func loadSettings() settings {
	s, _ := env.ParseAs[settings]()
	return s
}
