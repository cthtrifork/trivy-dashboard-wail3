package main

import "github.com/caarlos0/env/v11"

// settings are the environment variables the app itself reads. It is parsed on every use, not
// cached, so tests can change the environment with t.Setenv.
type settings struct {
	VEXFile    string `env:"TRIVY_SCANNER_VEX_FILE"`
	EPSSURL    string `env:"TRIVY_SCANNER_EPSS_URL"`
	KEVURL     string `env:"TRIVY_SCANNER_KEV_URL"`
	FakePodman bool   `env:"TRIVY_SCANNER_FAKE_PODMAN"`
}

// loadSettings reads the environment. A malformed value (say a non-boolean flag) leaves that
// field at its zero value.
func loadSettings() settings {
	s, _ := env.ParseAs[settings]()
	return s
}
