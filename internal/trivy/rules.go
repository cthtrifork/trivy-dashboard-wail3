package trivy

import "slices"

// Points each rule adds. They are constants on purpose: a rule can be switched off or have its
// thresholds moved, but never re-weighted, so every score is a sum of numbers the UI prints.
const (
	PointsKEV           = 50
	PointsKEVRansomware = 10
	PointsEPSSVeryHigh  = 35
	PointsEPSSHigh      = 22
	PointsEPSSLow       = 10
)

// Rules is the tunable part of the priority score: which rules apply and where their thresholds
// sit. The zero value switches everything off; use DefaultRules for the standard behaviour.
type Rules struct {
	// KEVEnabled adds PointsKEV (+PointsKEVRansomware) to findings in CISA's KEV catalog.
	KEVEnabled bool `json:"kevEnabled"`
	// KEVForceNow puts every KEV finding in the Act now tier whatever its score.
	KEVForceNow bool `json:"kevForceNow"`

	// EPSSEnabled scores the exploitation probability in three bands: at least EPSSCutoff
	// (+PointsEPSSLow), at least EPSSHigh (+PointsEPSSHigh) and at least EPSSVeryHigh
	// (+PointsEPSSVeryHigh, and the Fix soon tier). Below the cutoff it adds nothing.
	EPSSEnabled  bool    `json:"epssEnabled"`
	EPSSCutoff   float64 `json:"epssCutoff"`
	EPSSHigh     float64 `json:"epssHigh"`
	EPSSVeryHigh float64 `json:"epssVeryHigh"`

	SeverityEnabled bool `json:"severityEnabled"` // +3 (low) to +30 (critical)
	VectorEnabled   bool `json:"vectorEnabled"`   // network/low complexity/no auth/no interaction add points
	FixEnabled      bool `json:"fixEnabled"`      // +5 with a fix, -3 without, -5 when the vendor will not fix
	// FixedOnly drops findings without a fix to score 0 and the Monitor tier.
	FixedOnly bool `json:"fixedOnly"`

	// A finding is in the first tier whose minimum score it reaches (KEVForceNow and the EPSS
	// band above aside).
	TierNow  int `json:"tierNow"`
	TierSoon int `json:"tierSoon"`
	TierPlan int `json:"tierPlan"`
}

// DefaultRules is the "balanced" behaviour.
func DefaultRules() Rules {
	return Rules{
		KEVEnabled: true, KEVForceNow: true,
		EPSSEnabled: true, EPSSCutoff: 0.01, EPSSHigh: 0.1, EPSSVeryHigh: 0.5,
		SeverityEnabled: true, VectorEnabled: true, FixEnabled: true,
		TierNow: 70, TierSoon: 45, TierPlan: 25,
	}
}

// Normalize clamps thresholds into range and keeps them ordered (cutoff ≤ high ≤ very high,
// plan ≤ soon ≤ now), so a bad value from the UI cannot produce an inconsistent ranking.
func (r Rules) Normalize() Rules {
	r.EPSSCutoff = min(max(r.EPSSCutoff, 0), 1)
	r.EPSSHigh = min(max(r.EPSSHigh, r.EPSSCutoff), 1)
	r.EPSSVeryHigh = min(max(r.EPSSVeryHigh, r.EPSSHigh), 1)
	r.TierPlan = min(max(r.TierPlan, 0), 100)
	r.TierSoon = min(max(r.TierSoon, r.TierPlan), 100)
	r.TierNow = min(max(r.TierNow, r.TierSoon), 100)
	return r
}

// Preset is a named, built-in set of rules.
type Preset struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Rules       Rules  `json:"rules"`
}

// Presets returns the built-in presets, "balanced" (the default) first.
func Presets() []Preset {
	strict := DefaultRules()
	strict.EPSSCutoff, strict.EPSSHigh = 0.05, 0.2
	strict.FixedOnly = true
	strict.TierNow, strict.TierSoon, strict.TierPlan = 80, 55, 35

	exploited := DefaultRules()
	exploited.SeverityEnabled, exploited.VectorEnabled, exploited.FixEnabled = false, false, false
	exploited.TierNow, exploited.TierSoon, exploited.TierPlan = 50, 20, 10

	return []Preset{
		{"balanced", "Exploitation evidence first, then severity, reachability and fix availability. The default.", DefaultRules()},
		{"strict", "A short list: EPSS counts from 5%, findings without a fix are dropped, and the tiers start higher.", strict},
		{"exploited only", "Ranks by KEV and EPSS alone; severity, vector and fix availability add nothing.", exploited},
	}
}

// Rescored is one finding's outcome under a set of rules. Index points into the slice that was
// rescored; the result is ordered best-ranked first.
type Rescored struct {
	Index    int      `json:"index"`
	Priority int      `json:"priority"`
	Tier     string   `json:"tier"`
	TierWhy  string   `json:"tierWhy"`
	Reasons  []Reason `json:"reasons"`
	Attack   string   `json:"attack"` // the attack text follows the EPSS threshold, so it is rescored too
}

// Rescore re-ranks vulns under r without touching them.
func Rescore(vulns []Vulnerability, r Rules) []Rescored {
	r = r.Normalize()
	scored := make([]Vulnerability, len(vulns))
	idx := make([]int, len(vulns))
	for i := range vulns {
		scored[i] = vulns[i]
		applyRules(newRuleCtx(r, &scored[i]))
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(a, b int) int {
		switch {
		case ranksBefore(&scored[a], &scored[b]):
			return -1
		case ranksBefore(&scored[b], &scored[a]):
			return 1
		}
		return 0
	})
	out := make([]Rescored, len(idx))
	for n, i := range idx {
		v := &scored[i]
		out[n] = Rescored{Index: i, Priority: v.Priority, Tier: v.Tier, TierWhy: v.TierWhy, Reasons: v.Reasons, Attack: v.Attack}
	}
	return out
}
