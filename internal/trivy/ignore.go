package trivy

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ignoreFileSections are the top-level keys Trivy reads from a .trivyignore.yaml.
var ignoreFileSections = map[string]bool{"vulnerabilities": true, "misconfigurations": true, "secrets": true, "licenses": true}

// CheckIgnoreFile is a quick sanity check of a .trivyignore.yaml: it must be YAML, its top-level
// keys must be Trivy's sections, and every entry needs an id. It catches the usual mistakes (a
// plain .trivyignore line list, bad indentation) before a scan starts; Trivy remains the authority.
// Blank text is valid and means no ignore file.
func CheckIgnoreFile(src string) error {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	var doc yaml.Node
	if err := yaml.NewDecoder(strings.NewReader(src)).Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) { // only comments
			return nil
		}
		return fmt.Errorf("invalid YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode { // a plain .trivyignore (one ID per line) is just text
		return errors.New("expected sections such as `vulnerabilities:` with a list of `- id:` entries, not a list or plain text")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, entries := root.Content[i], root.Content[i+1]
		if !ignoreFileSections[key.Value] {
			return fmt.Errorf("line %d: unknown section %q (expected vulnerabilities, misconfigurations, secrets or licenses)", key.Line, key.Value)
		}
		if entries.Kind != yaml.SequenceNode {
			return fmt.Errorf("line %d: %s must be a list of entries", key.Line, key.Value)
		}
		for n, e := range entries.Content {
			if !hasID(e) {
				return fmt.Errorf("line %d: %s entry %d has no id", e.Line, key.Value, n+1)
			}
		}
	}
	return nil
}

// hasID reports whether a YAML mapping node has a non-blank `id` scalar.
func hasID(n *yaml.Node) bool {
	for i := 0; n.Kind == yaml.MappingNode && i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "id" {
			return n.Content[i+1].Kind == yaml.ScalarNode && strings.TrimSpace(n.Content[i+1].Value) != ""
		}
	}
	return false
}

var packageLine = regexp.MustCompile(`^package\s+([A-Za-z_][\w.]*)\s*(#.*)?$`)

// CheckIgnorePolicy is a quick sanity check of a Rego ignore policy: its package must be
// `trivy`, because Trivy evaluates `data.trivy.ignore` and a policy in another package would
// silently ignore nothing. It does not parse Rego: Trivy reports syntax errors itself. Blank
// text is valid and means no policy.
func CheckIgnorePolicy(src string) error {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	for _, line := range strings.Split(src, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		m := packageLine.FindStringSubmatch(l)
		switch {
		case m == nil:
			return errors.New("the policy must start with `package trivy`")
		case m[1] != "trivy":
			return fmt.Errorf("the policy's package is %q, but Trivy only reads `package trivy`", m[1])
		}
		return nil
	}
	return nil
}
