package trivy

import (
	"fmt"
	"strings"
)

// Points each rule adds. They are constants on purpose: a rule can be switched off or have its
// thresholds moved, but never re-weighted, so every score is a sum of numbers the UI prints.
const (
	PointsKEV           = 50
	PointsKEVRansomware = 10
	PointsEPSSVeryHigh  = 35
	PointsEPSSHigh      = 22
	PointsEPSSLow       = 10

	// Vector and impact: exploitability (at most 14), then what an attacker gets. Availability scores
	// nothing: a DoS ends with the attack, severity already rates it, and EPSS or KEV lifts a DoS that
	// is really exploited.
	PointsNetwork             = 6
	PointsAdjacent            = 2
	PointsPhysical            = -2
	PointsLowComplexity       = 2
	PointsNoPrivileges        = 3 // also "no authentication" in CVSS v2
	PointsNoInteraction       = 3
	PointsImpactHigh          = 4 // confidentiality and integrity, each
	PointsImpactLimited       = 2
	PointsAvailabilityHigh    = 0
	PointsAvailabilityLimited = 0

	PointsFix     = 5
	PointsNoFix   = -3
	PointsWontFix = -5
)

// SeverityPoints is what the Severity rule adds for each rating.
var SeverityPoints = map[string]int{"CRITICAL": 30, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "UNKNOWN": 0}

// RuleSummaries is the one-line description of what each rule adds, written from the same constants
// the rules use, so the scoring panel cannot show points that differ from the ones applied.
type RuleSummaries struct {
	KEV      string `json:"kev"`
	EPSS     string `json:"epss"`
	Severity string `json:"severity"`
	Vector   string `json:"vector"`
	Fix      string `json:"fix"`
	// Tiers says where each tier starts and that the score is capped.
	Tiers string `json:"tiers"`
}

// RuleHelp returns the summaries for the scoring panel, kept short: the points per signal, not the
// full rule text (each finding lists the exact rules that fired).
func RuleHelp() RuleSummaries {
	d := DefaultRules()
	pct := func(f float64) string { return fmt.Sprintf("%g%%", f*100) }
	sev := func(name string) string {
		return fmt.Sprintf("%s %+d", strings.ToLower(name), SeverityPoints[name])
	}
	kev := fmt.Sprintf("%+d, %+d more with ransomware use", PointsKEV, PointsKEVRansomware)
	if d.KEVForceNow {
		kev += ". Always Act now"
	}
	vector := fmt.Sprintf("Network %+d (physical %+d); an easy attack adds up to %+d; high confidentiality or integrity impact %+d",
		PointsNetwork, PointsPhysical, PointsLowComplexity+PointsNoPrivileges+PointsNoInteraction, PointsImpactHigh)
	if PointsAvailabilityHigh == 0 && PointsAvailabilityLimited == 0 {
		vector += "; availability adds nothing"
	}
	return RuleSummaries{
		KEV:      kev,
		EPSS:     fmt.Sprintf("%s %+d, %s %+d, %s %+d and Fix soon", pct(d.EPSSCutoff), PointsEPSSLow, pct(d.EPSSHigh), PointsEPSSHigh, pct(d.EPSSVeryHigh), PointsEPSSVeryHigh),
		Severity: fmt.Sprintf("%s, %s, %s, %s", sev("CRITICAL"), sev("HIGH"), sev("MEDIUM"), sev("LOW")),
		Vector:   vector,
		Fix:      fmt.Sprintf("Fix exists %+d, none yet %+d, vendor will not fix %+d", PointsFix, PointsNoFix, PointsWontFix),
		Tiers:    fmt.Sprintf("Act now %d+, Fix soon %d+, Plan %d+, otherwise Monitor. Score is capped at 100", d.TierNow, d.TierSoon, d.TierPlan),
	}
}

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
