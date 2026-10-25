package trivy

import (
	"strings"

	apk "github.com/knqyf263/go-apk-version"
	deb "github.com/knqyf263/go-deb-version"
	rpm "github.com/knqyf263/go-rpm-version"

	"github.com/aquasecurity/go-version/pkg/version"
)

// compareVersions orders a and b by the version scheme of the package URL's type
// (deb, rpm and apk each have their own); an empty or other purl, such as an image
// tag, is read as a semantic-ish version. Versions that do not parse sort below
// those that do and are compared as plain strings.
func compareVersions(purl, a, b string) int {
	typ, _, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	if purl == "" {
		typ = ""
	}
	switch typ {
	case "deb":
		va, ea := deb.NewVersion(a)
		vb, eb := deb.NewVersion(b)
		if ea == nil && eb == nil {
			return va.Compare(vb)
		}
	case "rpm":
		return rpm.NewVersion(a).Compare(rpm.NewVersion(b))
	case "apk":
		va, ea := apk.NewVersion(a)
		vb, eb := apk.NewVersion(b)
		if ea == nil && eb == nil {
			return va.Compare(vb)
		}
	default:
		va, ea := version.Parse(a)
		vb, eb := version.Parse(b)
		switch {
		case ea == nil && eb == nil:
			return va.Compare(vb)
		case ea == nil:
			return 1
		case eb == nil:
			return -1
		}
	}
	return strings.Compare(a, b)
}
