package trivy

import (
	"fmt"
	"sort"
	"strings"
)

// SBOMSummary is a plain-language overview of what an image contains.
type SBOMSummary struct {
	Text     string         `json:"text"`
	OS       string         `json:"os"`
	Binaries []BinaryInfo   `json:"binaries"`
	Packages map[string]int `json:"packages"` // purl type (golang, apk, …) -> count
}

// BinaryInfo is one application artifact found in the image.
type BinaryInfo struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`      // e.g. "Go binary"
	Toolchain string `json:"toolchain"` // e.g. "Go 1.26.10", empty if unknown
}

var appKinds = map[string]string{
	"gobinary":   "Go binary",
	"rustbinary": "Rust binary",
	"jar":        "Java archive",
	"node-pkg":   "Node.js package set",
	"python-pkg": "Python package set",
}

var osNames = map[string]string{
	"alpine": "Alpine Linux", "debian": "Debian", "ubuntu": "Ubuntu", "wolfi": "Wolfi",
	"redhat": "Red Hat Enterprise Linux", "centos": "CentOS", "rocky": "Rocky Linux",
	"alma": "AlmaLinux", "fedora": "Fedora", "amazon": "Amazon Linux", "oracle": "Oracle Linux",
}

// summarize builds the summary from the flattened SBOM. apps maps an application
// component's path to its Trivy type (gobinary, jar, …).
func summarize(res *ScanResult, apps map[string]string, osFamily, osVersion string) *SBOMSummary {
	s := &SBOMSummary{Binaries: []BinaryInfo{}, Packages: map[string]int{}}
	if osFamily != "" {
		name := osNames[osFamily]
		if name == "" {
			name = osFamily
		}
		s.OS = strings.TrimSpace(name + " " + osVersion)
	}
	var goVersions []string
	for _, c := range res.Components {
		t, _, ok := strings.Cut(strings.TrimPrefix(c.PURL, "pkg:"), "/")
		if !ok || c.PURL == "" {
			continue
		}
		s.Packages[t]++
		if t == "golang" && c.Name == "stdlib" && c.Group == "" {
			goVersions = append(goVersions, "Go "+strings.TrimPrefix(c.Version, "v"))
		}
	}
	paths := make([]string, 0, len(apps))
	for p := range apps {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		b := BinaryInfo{Path: p, Kind: appKinds[apps[p]]}
		if b.Kind == "" {
			b.Kind = apps[p]
		}
		if apps[p] == "gobinary" && len(goVersions) > 0 {
			b.Toolchain = strings.Join(goVersions, ", ")
		}
		s.Binaries = append(s.Binaries, b)
	}

	var parts []string
	for _, b := range s.Binaries {
		d := fmt.Sprintf("%s is a %s", b.Path, b.Kind)
		if b.Toolchain != "" {
			d += " built with " + b.Toolchain
		}
		parts = append(parts, d)
	}
	text := strings.Join(parts, "; ")
	if s.OS != "" {
		if text == "" {
			text = "This image is based on " + s.OS
		} else {
			text += ", on " + s.OS
		}
	}
	if text != "" {
		text += ". "
	}
	var counts []string
	keys := make([]string, 0, len(s.Packages))
	for k := range s.Packages {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return s.Packages[keys[i]] > s.Packages[keys[j]] || s.Packages[keys[i]] == s.Packages[keys[j]] && keys[i] < keys[j]
	})
	for _, k := range keys {
		counts = append(counts, fmt.Sprintf("%d %s", s.Packages[k], k))
	}
	text += fmt.Sprintf("%d components", len(res.Components))
	if len(counts) > 0 {
		text += " (" + strings.Join(counts, ", ") + ")"
	}
	s.Text = text + "."
	return s
}
