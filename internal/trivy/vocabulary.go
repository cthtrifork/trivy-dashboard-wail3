package trivy

import "slices"

// VendorStatuses are the statuses Trivy reports for a vendor advisory, in the order the Options
// menu lists them. Scans can leave out findings with any of them (see DefaultIgnoreStatus).
var VendorStatuses = []string{
	"will_not_fix", "not_affected", "affected", "fixed",
	"under_investigation", "fix_deferred", "end_of_life", "unknown",
}

// Vocabulary is what the UI needs to know about the engine's fixed lists and thresholds, so it
// keeps no copy that could drift.
type Vocabulary struct {
	// Severities are Trivy's ratings, most severe first.
	Severities []string `json:"severities"`
	// Tiers are the priority tiers, most urgent first.
	Tiers          []string `json:"tiers"`
	VendorStatuses []string `json:"vendorStatuses"`
	// EPSSHigh is the exploitation probability from which the UI flags a finding, as a fraction.
	EPSSHigh float64 `json:"epssHigh"`
}

// Vocab returns the vocabulary for the default (balanced) rules.
func Vocab() Vocabulary {
	sev := make([]string, 0, len(severityRank))
	for s := range severityRank {
		sev = append(sev, s)
	}
	slices.SortFunc(sev, func(a, b string) int { return severityRank[a] - severityRank[b] })
	return Vocabulary{
		Severities:     sev,
		Tiers:          []string{TierNow, TierSoon, TierPlan, TierMonitor},
		VendorStatuses: slices.Clone(VendorStatuses),
		EPSSHigh:       DefaultRules().EPSSHigh,
	}
}
