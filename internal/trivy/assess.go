package trivy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// Reason is one explainable contribution to a finding's priority score.
type Reason struct {
	Signal string `json:"signal"` // KEV, EPSS, Severity, Vector, Fix, Status, Context
	Text   string `json:"text"`
	Points int    `json:"points"`
	// Rule is the exact rule that fired, with the thresholds in force, e.g. "EPSS ≥ 10% → +22".
	Rule string `json:"rule"`
}

// Priority tiers, most urgent first.
const (
	TierNow     = "Act now"
	TierSoon    = "Fix soon"
	TierPlan    = "Plan"
	TierMonitor = "Monitor"
)

// CVSSVector holds the base metrics of a CVSS v2, v3 or v4 vector that the rules read.
type CVSSVector struct {
	Raw     string
	Version int // 2, 3 or 4; 0 when the vector is empty or does not parse
	M       map[string]string
}

// ParseVector parses "CVSS:3.1/AV:N/AC:L/…", "CVSS:4.0/…" or a v2 "AV:N/AC:L/Au:N/…" vector.
// A vector the library rejects yields no metrics, so no rule reads it.
func ParseVector(raw string) CVSSVector {
	v := CVSSVector{Raw: raw, M: map[string]string{}}
	var get func(string) (string, error)
	switch {
	case raw == "":
		return v
	case strings.HasPrefix(raw, "CVSS:4.0/"):
		c, err := gocvss40.ParseVector(raw)
		if err != nil {
			return v
		}
		v.Version, get = 4, c.Get
	case strings.HasPrefix(raw, "CVSS:3.1/"):
		c, err := gocvss31.ParseVector(raw)
		if err != nil {
			return v
		}
		v.Version, get = 3, c.Get
	case strings.HasPrefix(raw, "CVSS:3.0/"):
		c, err := gocvss30.ParseVector(raw)
		if err != nil {
			return v
		}
		v.Version, get = 3, c.Get
	default:
		c, err := gocvss20.ParseVector(raw)
		if err != nil {
			return v
		}
		v.Version, get = 2, c.Get
	}
	for _, k := range []string{"AV", "AC", "PR", "Au", "UI", "S", "C", "I", "A", "AT", "VC", "VI", "VA", "SC", "SI", "SA"} {
		if val, err := get(k); err == nil {
			v.M[k] = val
		}
	}
	return v
}

// ruleCtx is everything the rules may look at.
type ruleCtx struct {
	r   Rules
	v   *Vulnerability
	vec CVSSVector
	// text is the lowercase title + description for keyword rules.
	text string
}

// rule inspects the context and may return a reason (nil = not applicable).
type rule struct {
	name  string
	apply func(c *ruleCtx) *Reason
}

var rules = []rule{
	{"kev", func(c *ruleCtx) *Reason {
		if !c.r.KEVEnabled || !c.v.KEV {
			return nil
		}
		pts, txt := PointsKEV, "Listed in CISA's Known Exploited Vulnerabilities catalog: exploitation in the wild is documented"
		rule := fmt.Sprintf("listed in KEV → +%d", PointsKEV)
		if c.v.KEVRansomware {
			pts += PointsKEVRansomware
			txt += ", including use in ransomware campaigns"
			rule += fmt.Sprintf(", used in ransomware → +%d", PointsKEVRansomware)
		}
		return &Reason{"KEV", txt, pts, rule}
	}},
	{"epss", func(c *ruleCtx) *Reason {
		if !c.r.EPSSEnabled || !c.v.HasEPSS {
			return nil
		}
		pct := c.v.EPSS * 100
		txt := fmt.Sprintf("EPSS predicts a %.1f%% chance of exploitation in the next 30 days (more likely than %.1f%% of all CVEs)", pct, c.v.EPSSPercentile*100)
		switch {
		case c.v.EPSS >= c.r.EPSSVeryHigh:
			return &Reason{"EPSS", txt, PointsEPSSVeryHigh, fmt.Sprintf("EPSS ≥ %s → +%d", pctText(c.r.EPSSVeryHigh), PointsEPSSVeryHigh)}
		case c.v.EPSS >= c.r.EPSSHigh:
			return &Reason{"EPSS", txt, PointsEPSSHigh, fmt.Sprintf("EPSS ≥ %s → +%d", pctText(c.r.EPSSHigh), PointsEPSSHigh)}
		case c.v.EPSS >= c.r.EPSSCutoff:
			return &Reason{"EPSS", txt, PointsEPSSLow, fmt.Sprintf("EPSS ≥ %s → +%d", pctText(c.r.EPSSCutoff), PointsEPSSLow)}
		}
		return &Reason{"EPSS", txt + ": unlikely to be exploited", 0, fmt.Sprintf("EPSS < %s → +0", pctText(c.r.EPSSCutoff))}
	}},
	{"severity", func(c *ruleCtx) *Reason {
		if !c.r.SeverityEnabled {
			return nil
		}
		pts := map[string]int{"CRITICAL": 30, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "UNKNOWN": 5}[c.v.Severity]
		txt := fmt.Sprintf("%s severity", strings.ToLower(c.v.Severity))
		if c.v.Score > 0 {
			txt += fmt.Sprintf(" (CVSS %.1f)", c.v.Score)
		}
		return &Reason{"Severity", txt + ": how bad it is if exploited", pts, fmt.Sprintf("severity %s → +%d", c.v.Severity, pts)}
	}},
	{"vector", func(c *ruleCtx) *Reason {
		if !c.r.VectorEnabled {
			return nil
		}
		av := c.vec.M["AV"]
		if av == "" {
			return nil
		}
		pts := 0
		var parts []string
		add := func(label string, n int) {
			pts += n
			parts = append(parts, fmt.Sprintf("%s %+d", label, n))
		}
		switch av {
		case "N":
			add("AV:N", 10)
		case "A":
			add("AV:A", 4)
		case "P":
			add("AV:P", -2)
		}
		if c.vec.M["AC"] == "L" {
			add("AC:L", 3)
		}
		if c.vec.M["PR"] == "N" {
			add("PR:N", 5)
		} else if c.vec.M["Au"] == "N" {
			add("Au:N", 5)
		}
		if c.vec.M["UI"] == "N" {
			add("UI:N", 4)
		}
		rule := fmt.Sprintf("CVSS vector → %+d", pts)
		if len(parts) > 0 {
			rule += " (" + strings.Join(parts, ", ") + ")"
		}
		return &Reason{"Vector", "attack vector makes exploitation " + ease(pts), pts, rule}
	}},
	{"fix", func(c *ruleCtx) *Reason {
		if !c.r.FixEnabled {
			return nil
		}
		switch {
		case c.v.Fixed != "":
			return &Reason{"Fix", "a fixed version exists (" + c.v.Fixed + "): remediation is an upgrade away", 5, "fix available → +5"}
		case strings.Contains(strings.ToLower(c.v.Status), "end_of_life"), strings.Contains(strings.ToLower(c.v.Status), "will_not_fix"):
			return &Reason{"Fix", "the vendor will not fix this: plan mitigation or replacement", -5, "vendor will not fix → -5"}
		default:
			return &Reason{"Fix", "no fix is available yet: mitigate or accept the risk", -3, "no fix available → -3"}
		}
	}},
}

// pctText formats a probability as a short percentage: 0.01 → "1%", 0.125 → "12.5%".
func pctText(p float64) string {
	return strconv.FormatFloat(p*100, 'f', -1, 64) + "%"
}

func ease(pts int) string {
	switch {
	case pts >= 18:
		return "very easy"
	case pts >= 10:
		return "relatively easy"
	case pts >= 4:
		return "harder"
	}
	return "difficult"
}

// Assess scores v with the default (balanced) rules; see AssessWith.
func Assess(v *Vulnerability) { AssessWith(v, DefaultRules()) }

// AssessWith fills in the vector, priority score, tier, reasons and the
// human-readable attack assessment of v from its current signals, under rules r.
func AssessWith(v *Vulnerability, r Rules) {
	c := &ruleCtx{r: r.Normalize(), v: v, vec: ParseVector(v.Vector), text: strings.ToLower(v.Title + " " + v.Description)}
	applyRules(c)
	v.Attack = describeAttack(c)
}

// applyRules sets everything about v that depends on the rules: reasons, score, tier and the
// sentence saying which threshold decided the tier.
func applyRules(c *ruleCtx) {
	v, r := c.v, c.r
	v.Reasons = nil
	score := 0
	for _, ru := range rules {
		if re := ru.apply(c); re != nil {
			v.Reasons = append(v.Reasons, *re)
			score += re.Points
		}
	}
	v.Priority = min(max(score, 0), 100)
	// Highest-impact reasons first so the UI can show the top few.
	sort.SliceStable(v.Reasons, func(i, j int) bool { return abs(v.Reasons[i].Points) > abs(v.Reasons[j].Points) })

	epssTop := r.EPSSEnabled && v.HasEPSS && v.EPSS >= r.EPSSVeryHigh
	switch {
	case r.FixedOnly && v.Fixed == "":
		v.Priority, v.Tier = 0, TierMonitor
		v.TierWhy = "Monitor: the fixed-only rule drops findings without a fix"
		v.Reasons = append([]Reason{{"Fix", "no fix is available and the fixed-only rule is on: the score is set to 0", 0, "fixed-only → score 0"}}, v.Reasons...)
	case r.KEVEnabled && r.KEVForceNow && v.KEV:
		v.Tier, v.TierWhy = TierNow, "Act now: listed in KEV and the KEV rule forces Act now"
	case v.Priority >= r.TierNow:
		v.Tier, v.TierWhy = TierNow, fmt.Sprintf("Act now: score %d ≥ %d", v.Priority, r.TierNow)
	case v.Priority >= r.TierSoon:
		v.Tier, v.TierWhy = TierSoon, fmt.Sprintf("Fix soon: score %d ≥ %d", v.Priority, r.TierSoon)
	case epssTop:
		v.Tier, v.TierWhy = TierSoon, fmt.Sprintf("Fix soon: EPSS %s ≥ %s", pctText(v.EPSS), pctText(r.EPSSVeryHigh))
	case v.Priority >= r.TierPlan:
		v.Tier, v.TierWhy = TierPlan, fmt.Sprintf("Plan: score %d ≥ %d", v.Priority, r.TierPlan)
	default:
		v.Tier, v.TierWhy = TierMonitor, fmt.Sprintf("Monitor: score %d < %d", v.Priority, r.TierPlan)
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// describeAttack turns the CVSS vector plus keywords into plain English.
func describeAttack(c *ruleCtx) string {
	m := c.vec.M
	var parts []string

	switch m["AV"] {
	case "N":
		parts = append(parts, "Can be attacked remotely over the network")
	case "A":
		parts = append(parts, "Can be attacked from the adjacent network only (same subnet or VLAN)")
	case "L":
		parts = append(parts, "Needs local access: an attacker must already be able to run code or log in inside the container or host")
	case "P":
		parts = append(parts, "Needs physical access to the machine")
	default:
		parts = append(parts, "No CVSS vector is published, so the attack path is unknown")
	}

	if m["AV"] != "" {
		var cond []string
		switch {
		case m["AC"] == "L":
			cond = append(cond, "low complexity (no special conditions)")
		case m["AC"] == "H" || m["AC"] == "M":
			cond = append(cond, "specific conditions outside the attacker's control")
		}
		switch {
		case m["PR"] == "N" || m["Au"] == "N":
			cond = append(cond, "no authentication")
		case m["PR"] == "L" || m["Au"] == "S":
			cond = append(cond, "a low-privileged account")
		case m["PR"] == "H" || m["Au"] == "M":
			cond = append(cond, "administrator privileges")
		}
		if m["UI"] == "N" {
			cond = append(cond, "no user interaction")
		} else if m["UI"] == "R" {
			cond = append(cond, "a user to take an action (e.g. open a file or link)")
		}
		if len(cond) > 0 {
			parts[0] += " with " + joinWords(cond)
		}
	}
	out := parts[0] + "."

	if m["S"] == "C" {
		out += " A successful attack can cross the security boundary of the vulnerable component."
	}
	if imp := impactSentence(m); imp != "" {
		out += " " + imp
	}
	if k := keywordOutcome(c.text); k != "" {
		out += " Likely outcome: " + k + "."
	}

	switch {
	case c.v.KEV:
		out += " This is being exploited in the real world."
	case c.v.HasEPSS && c.v.EPSS >= 0.1:
		out += " Exploitation is considered likely."
	}
	if m["AV"] == "L" {
		out += " In a container image this only matters if something else already gives an attacker code execution."
	} else if m["AV"] == "N" {
		out += " It only matters if the affected component is running and reachable; if not, record that in a VEX statement."
	}
	return out
}

func impactSentence(m map[string]string) string {
	var hi, lo []string
	for _, k := range []struct{ key, name string }{{"C", "confidentiality"}, {"I", "integrity"}, {"A", "availability"}} {
		switch m[k.key] {
		case "H", "C":
			hi = append(hi, k.name)
		case "L", "P":
			lo = append(lo, k.name)
		}
	}
	switch {
	case len(hi) > 0 && len(lo) > 0:
		return fmt.Sprintf("Impact: high on %s, limited on %s.", joinWords(hi), joinWords(lo))
	case len(hi) > 0:
		return fmt.Sprintf("Impact: high on %s.", joinWords(hi))
	case len(lo) > 0:
		return fmt.Sprintf("Impact: limited on %s.", joinWords(lo))
	}
	return ""
}

// keywordOutcome maps advisory wording to the most severe likely outcome.
func keywordOutcome(text string) string {
	for _, k := range []struct {
		kw  []string
		out string
	}{
		{[]string{"remote code execution", "arbitrary code", "code execution", "command injection"}, "arbitrary code execution"},
		{[]string{"sql injection"}, "database compromise through SQL injection"},
		{[]string{"authentication bypass", "bypass authentication", "improper authentication"}, "authentication bypass"},
		{[]string{"privilege escalation", "elevation of privilege", "escalate privileges"}, "privilege escalation"},
		{[]string{"path traversal", "directory traversal", "arbitrary file"}, "reading or writing files outside the intended directory"},
		{[]string{"ssrf", "server-side request forgery"}, "requests made from your server to internal systems"},
		{[]string{"cross-site scripting", "xss"}, "script injection in users' browsers"},
		{[]string{"information disclosure", "information leak", "sensitive information", "memory disclosure"}, "leakage of sensitive data"},
		{[]string{"denial of service", "crash", "infinite loop", "resource exhaustion"}, "denial of service"},
	} {
		for _, w := range k.kw {
			if strings.Contains(text+" ", w) {
				return k.out
			}
		}
	}
	return ""
}

func joinWords(w []string) string {
	switch len(w) {
	case 0:
		return ""
	case 1:
		return w[0]
	}
	return strings.Join(w[:len(w)-1], ", ") + " and " + w[len(w)-1]
}
