package trivy

import (
	"fmt"
	"sort"
	"strings"
)

// Reason is one explainable contribution to a finding's priority score.
type Reason struct {
	Signal string `json:"signal"` // KEV, EPSS, Severity, Vector, Fix, Status, Context
	Text   string `json:"text"`
	Points int    `json:"points"`
}

// Priority tiers, most urgent first.
const (
	TierNow     = "Act now"
	TierSoon    = "Fix soon"
	TierPlan    = "Plan"
	TierMonitor = "Monitor"
)

// CVSSVector holds the parsed base metrics of a CVSS v2/v3 vector.
type CVSSVector struct {
	Raw     string
	Version int // 2 or 3
	M       map[string]string
}

// ParseVector parses "CVSS:3.1/AV:N/AC:L/…" or a v2 "AV:N/AC:L/Au:N/…" vector.
func ParseVector(raw string) CVSSVector {
	v := CVSSVector{Raw: raw, M: map[string]string{}}
	if raw == "" {
		return v
	}
	for _, part := range strings.Split(raw, "/") {
		k, val, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		if k == "CVSS" {
			v.Version = 3
			continue
		}
		v.M[k] = val
	}
	if v.Version == 0 && len(v.M) > 0 {
		v.Version = 2
	}
	return v
}

// ruleCtx is everything the rules may look at.
type ruleCtx struct {
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
		if !c.v.KEV {
			return nil
		}
		pts, txt := 50, "Listed in CISA's Known Exploited Vulnerabilities catalog: exploitation in the wild is documented"
		if c.v.KEVRansomware {
			pts += 10
			txt += ", including use in ransomware campaigns"
		}
		return &Reason{"KEV", txt, pts}
	}},
	{"epss", func(c *ruleCtx) *Reason {
		if !c.v.HasEPSS {
			return nil
		}
		pct := c.v.EPSS * 100
		txt := fmt.Sprintf("EPSS predicts a %.1f%% chance of exploitation in the next 30 days (more likely than %.1f%% of all CVEs)", pct, c.v.EPSSPercentile*100)
		switch {
		case c.v.EPSS >= 0.5:
			return &Reason{"EPSS", txt, 35}
		case c.v.EPSS >= 0.1:
			return &Reason{"EPSS", txt, 22}
		case c.v.EPSS >= 0.01:
			return &Reason{"EPSS", txt, 10}
		}
		return &Reason{"EPSS", txt + ": unlikely to be exploited", 0}
	}},
	{"severity", func(c *ruleCtx) *Reason {
		pts := map[string]int{"CRITICAL": 20, "HIGH": 14, "MEDIUM": 8, "LOW": 3, "UNKNOWN": 5}[c.v.Severity]
		txt := fmt.Sprintf("%s severity", strings.ToLower(c.v.Severity))
		if c.v.Score > 0 {
			txt += fmt.Sprintf(" (CVSS %.1f)", c.v.Score)
		}
		return &Reason{"Severity", txt + ": how bad it is if exploited", pts}
	}},
	{"vector", func(c *ruleCtx) *Reason {
		av := c.vec.M["AV"]
		if av == "" {
			return nil
		}
		pts := 0
		switch av {
		case "N":
			pts += 10
		case "A":
			pts += 4
		case "P":
			pts -= 2
		}
		if c.vec.M["AC"] == "L" {
			pts += 3
		}
		if pr := c.vec.M["PR"]; pr == "N" || c.vec.M["Au"] == "N" {
			pts += 5
		}
		if c.vec.M["UI"] == "N" {
			pts += 4
		}
		return &Reason{"Vector", "attack vector makes exploitation " + ease(pts), pts}
	}},
	{"fix", func(c *ruleCtx) *Reason {
		switch {
		case c.v.Fixed != "":
			return &Reason{"Fix", "a fixed version exists (" + c.v.Fixed + "): remediation is an upgrade away", 5}
		case strings.Contains(strings.ToLower(c.v.Status), "end_of_life"), strings.Contains(strings.ToLower(c.v.Status), "will_not_fix"):
			return &Reason{"Fix", "the vendor will not fix this: plan mitigation or replacement", -5}
		default:
			return &Reason{"Fix", "no fix is available yet: mitigate or accept the risk", -3}
		}
	}},
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

// Assess fills in the vector, priority score, tier, reasons and the
// human-readable attack assessment of v from its current signals.
func Assess(v *Vulnerability) {
	c := &ruleCtx{v: v, vec: ParseVector(v.Vector), text: strings.ToLower(v.Title + " " + v.Description)}
	v.Reasons = nil
	score := 0
	for _, r := range rules {
		if re := r.apply(c); re != nil {
			v.Reasons = append(v.Reasons, *re)
			score += re.Points
		}
	}
	v.Priority = min(max(score, 0), 100)
	switch {
	case v.KEV || v.Priority >= 70:
		v.Tier = TierNow
	case v.Priority >= 45 || (v.HasEPSS && v.EPSS >= 0.5):
		v.Tier = TierSoon
	case v.Priority >= 25:
		v.Tier = TierPlan
	default:
		v.Tier = TierMonitor
	}
	// Highest-impact reasons first so the UI can show the top few.
	sort.SliceStable(v.Reasons, func(i, j int) bool { return abs(v.Reasons[i].Points) > abs(v.Reasons[j].Points) })
	v.Attack = describeAttack(c)
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
