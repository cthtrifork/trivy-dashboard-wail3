package trivy

import (
	"strings"
	"testing"
)

func TestCheckIgnoreFile(t *testing.T) {
	for _, c := range []struct {
		name, src string
		bad       string // substring of the expected error; empty means valid
	}{
		{"blank", "  \n", ""},
		{"only comments", "# nothing yet\n", ""},
		{"example", "# c\nvulnerabilities:\n  - id: CVE-1\n    statement: \"not used\"\nmisconfigurations:\n  - id: AVD-KSV-0104\n    paths:\n      - \"kube-system/x\"\n    statement: y\n", ""},
		{"plain trivyignore", "CVE-2024-1\nCVE-2024-2\n", "not a list or plain text"},
		{"bad indentation", "vulnerabilities:\n  - id: CVE-1\n   statement: x\n", "invalid YAML"},
		{"unknown section", "vulnerabilites:\n  - id: CVE-1\n", `line 1: unknown section "vulnerabilites"`},
		{"entry without id", "vulnerabilities:\n  - statement: x\n", "line 2: vulnerabilities entry 1 has no id"},
		{"section not a list", "vulnerabilities: CVE-1\n", "vulnerabilities must be a list"},
	} {
		err := CheckIgnoreFile(c.src)
		if (err == nil) != (c.bad == "") || (err != nil && !strings.Contains(err.Error(), c.bad)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.bad)
		}
	}
}

func TestCheckIgnorePolicy(t *testing.T) {
	for _, c := range []struct {
		name, src string
		bad       string
	}{
		{"blank", "", ""},
		{"example", "# https://example\npackage trivy\n\nimport rego.v1\n", ""},
		{"trailing comment", "package trivy # ignore rules\n", ""},
		{"other package", "package main\n", `package is "main"`},
		{"no package", "ignore if true\n", "must start with `package trivy`"},
		{"package with a longer name", "package trivy.extra\n", `package is "trivy.extra"`},
	} {
		err := CheckIgnorePolicy(c.src)
		if (err == nil) != (c.bad == "") || (err != nil && !strings.Contains(err.Error(), c.bad)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.bad)
		}
	}
}
