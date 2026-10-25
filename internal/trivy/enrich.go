package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultEPSSURL = "https://api.first.org/data/v1/epss"
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	kevMaxAge = 12 * time.Hour
	epssBatch = 80 // keeps the query string well under common URL limits
)

// EnrichInfo reports what enrichment data was applied.
type EnrichInfo struct {
	EPSS     bool     `json:"epss"`
	KEV      bool     `json:"kev"`
	KEVDate  string   `json:"kevDate"`
	Warnings []string `json:"warnings"`
}

type kevEntry struct {
	DateAdded  string
	DueDate    string
	Ransomware bool
	Action     string
}

// Enricher adds exploitation signals (EPSS, CISA KEV) to findings.
// Failures are non-fatal: the scan result simply lacks those signals.
type Enricher struct {
	HTTP     *http.Client
	EPSSURL  string
	KEVURL   string
	CacheDir string // optional on-disk cache for the KEV catalog

	mu      sync.Mutex
	kev     map[string]kevEntry
	kevAt   time.Time
	kevDate string
}

func (e *Enricher) client() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func orDefault(s, d string) string {
	if s != "" {
		return s
	}
	return d
}

// Enrich looks up every CVE in vulns, sets the exploitation fields and
// re-runs Assess on each finding.
func (e *Enricher) Enrich(ctx context.Context, vulns []Vulnerability) EnrichInfo {
	var info EnrichInfo
	var ids []string
	seen := map[string]bool{}
	for _, v := range vulns {
		if strings.HasPrefix(v.ID, "CVE-") && !seen[v.ID] {
			seen[v.ID] = true
			ids = append(ids, v.ID)
		}
	}

	if kev, date, err := e.loadKEV(ctx); err != nil {
		info.Warnings = append(info.Warnings, "CISA KEV unavailable: "+err.Error())
	} else {
		info.KEV, info.KEVDate = true, date
		for i := range vulns {
			if k, ok := kev[vulns[i].ID]; ok {
				vulns[i].KEV, vulns[i].KEVRansomware = true, k.Ransomware
				vulns[i].KEVAdded, vulns[i].KEVDue, vulns[i].KEVAction = k.DateAdded, k.DueDate, k.Action
			}
		}
	}

	if len(ids) > 0 {
		scores, err := e.fetchEPSS(ctx, ids)
		if err != nil {
			info.Warnings = append(info.Warnings, "EPSS unavailable: "+err.Error())
		} else {
			info.EPSS = true
			for i := range vulns {
				if s, ok := scores[vulns[i].ID]; ok {
					vulns[i].HasEPSS, vulns[i].EPSS, vulns[i].EPSSPercentile = true, s[0], s[1]
				}
			}
		}
	}

	for i := range vulns {
		Assess(&vulns[i])
	}
	return info
}

// fetchEPSS returns id -> [probability, percentile].
func (e *Enricher) fetchEPSS(ctx context.Context, ids []string) (map[string][2]float64, error) {
	out := map[string][2]float64{}
	for start := 0; start < len(ids); start += epssBatch {
		batch := ids[start:min(start+epssBatch, len(ids))]
		u := orDefault(e.EPSSURL, DefaultEPSSURL) + "?limit=" + strconv.Itoa(len(batch)) + "&cve=" + url.QueryEscape(strings.Join(batch, ","))
		var body struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		if err := e.getJSON(ctx, u, &body); err != nil {
			return nil, err
		}
		for _, d := range body.Data {
			p, err1 := strconv.ParseFloat(d.EPSS, 64)
			pc, err2 := strconv.ParseFloat(d.Percentile, 64)
			if err1 == nil && err2 == nil {
				out[strings.ToUpper(d.CVE)] = [2]float64{p, pc}
			}
		}
	}
	return out, nil
}

func (e *Enricher) loadKEV(ctx context.Context) (map[string]kevEntry, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.kev != nil && time.Since(e.kevAt) < kevMaxAge {
		return e.kev, e.kevDate, nil
	}
	cache := ""
	if e.CacheDir != "" {
		cache = filepath.Join(e.CacheDir, "kev.json")
		if st, err := os.Stat(cache); err == nil && time.Since(st.ModTime()) < kevMaxAge {
			if b, err := os.ReadFile(cache); err == nil {
				if m, date, err := parseKEV(b); err == nil {
					e.kev, e.kevAt, e.kevDate = m, st.ModTime(), date
					return m, date, nil
				}
			}
		}
	}
	var raw json.RawMessage
	err := e.getJSON(ctx, orDefault(e.KEVURL, DefaultKEVURL), &raw)
	if err == nil {
		var m map[string]kevEntry
		var date string
		if m, date, err = parseKEV(raw); err == nil {
			e.kev, e.kevAt, e.kevDate = m, time.Now(), date
			if cache != "" {
				_ = os.MkdirAll(e.CacheDir, 0o755)
				_ = os.WriteFile(cache, raw, 0o644)
			}
			return m, date, nil
		}
	}
	// Network failed: a stale cache beats nothing.
	if cache != "" {
		if b, rerr := os.ReadFile(cache); rerr == nil {
			if m, date, perr := parseKEV(b); perr == nil {
				e.kev, e.kevAt, e.kevDate = m, time.Now().Add(-kevMaxAge+10*time.Minute), date
				return m, date + " (cached)", nil
			}
		}
	}
	return nil, "", err
}

func parseKEV(b []byte) (map[string]kevEntry, string, error) {
	var doc struct {
		DateReleased    string `json:"dateReleased"`
		CatalogVersion  string `json:"catalogVersion"`
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			DateAdded                  string `json:"dateAdded"`
			DueDate                    string `json:"dueDate"`
			RequiredAction             string `json:"requiredAction"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, "", err
	}
	if len(doc.Vulnerabilities) == 0 {
		return nil, "", fmt.Errorf("catalog is empty")
	}
	m := make(map[string]kevEntry, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		m[strings.ToUpper(v.CVEID)] = kevEntry{v.DateAdded, v.DueDate, strings.EqualFold(v.KnownRansomwareCampaignUse, "Known"), v.RequiredAction}
	}
	date := doc.CatalogVersion
	if date == "" {
		date = doc.DateReleased
	}
	return m, date, nil
}

func (e *Enricher) getJSON(ctx context.Context, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := e.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", req.URL.Host, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}
