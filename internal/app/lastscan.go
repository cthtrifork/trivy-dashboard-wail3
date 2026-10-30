package app

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

// lastScanFile is where the most recent scan is kept so the findings survive a restart: $TRIVY_SCANNER_VEX_FILE's
// directory when set, else the user config dir. It sits beside the VEX assessments, which also outlive the process.
func lastScanFile() string {
	return filepath.Join(filepath.Dir(vexFile()), "last-scan.json")
}

// saveLastScan writes the scan to disk. Failure is logged only: the scan itself succeeded.
func (s *ScanService) saveLastScan(res *trivy.ScanResult) {
	if s.lastScanPath == "" {
		return
	}
	data, err := json.Marshal(res)
	if err == nil {
		if err = os.MkdirAll(filepath.Dir(s.lastScanPath), 0o755); err == nil {
			err = os.WriteFile(s.lastScanPath, data, 0o600)
		}
	}
	if err != nil {
		log.Print("trivy-scanner: could not save the last scan: " + err.Error())
	}
}

// loadLastScan puts the scan saved by the previous run back into memory, so VEX import and export,
// "mark unassessed" and re-ranking work for the scan the UI still shows. A missing or unreadable file is ignored.
func (s *ScanService) loadLastScan() {
	if s.lastScanPath == "" {
		return
	}
	data, err := os.ReadFile(s.lastScanPath)
	if err != nil {
		return
	}
	var res trivy.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		log.Print("trivy-scanner: ignoring unreadable last scan: " + err.Error())
		return
	}
	s.RestoreScan(&res)
}

// forgetLastScan removes the saved scan; a new scan replaces it.
func (s *ScanService) forgetLastScan() {
	if s.lastScanPath != "" {
		_ = os.Remove(s.lastScanPath)
	}
}
