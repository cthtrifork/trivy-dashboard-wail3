package trivy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
)

// VEX statuses and justifications as defined by OpenVEX, taken from the
// go-vex library that vexctl is built on.
var (
	VEXStatuses       = vex.Statuses()
	VEXJustifications = vex.Justifications()
)

// VEXEntry is a user's assessment of one finding.
type VEXEntry struct {
	Key           string `json:"key"`
	Vulnerability string `json:"vulnerability"`
	Package       string `json:"package"`
	Version       string `json:"version"`
	PURL          string `json:"purl"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
	Impact        string `json:"impact"`
	Action        string `json:"action"`
	// Author and Expires are kept locally and are not part of the OpenVEX
	// export: the format has no per-statement expiry, and its author is
	// document-level. Expires is a UTC date (YYYY-MM-DD); after it the
	// assessment stays on record but no longer hides the finding.
	Author  string `json:"author"`
	Expires string `json:"expires"`
	Updated string `json:"updated"`
}

const expiryLayout = "2006-01-02"

// Expired reports whether the assessment's review date has passed. The
// expiry day itself still counts as valid.
func (e VEXEntry) Expired(now time.Time) bool {
	return e.Expires != "" && now.UTC().Format(expiryLayout) > e.Expires
}

// VEXKey identifies a finding independent of scan order.
func VEXKey(id, purl, pkg, version string) string {
	if purl != "" {
		return id + "|" + purl
	}
	return id + "|" + pkg + "@" + version
}

// ImageRepo strips tag and digest so assessments carry over to new tags.
func ImageRepo(ref string) string {
	ref = NormalizeImage(ref)
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

// Validate enforces the OpenVEX rules for each status.
func (e *VEXEntry) Validate() error {
	if e.Vulnerability == "" {
		return errors.New("vulnerability id is required")
	}
	if !contains(VEXStatuses, e.Status) {
		return fmt.Errorf("status must be one of %s", strings.Join(VEXStatuses, ", "))
	}
	if e.Status != "not_affected" {
		e.Justification = "" // only meaningful for not_affected; the UI may leave a stale one
	}
	if e.Justification != "" && !contains(VEXJustifications, e.Justification) {
		return fmt.Errorf("unknown justification %q", e.Justification)
	}
	e.Author = strings.TrimSpace(e.Author)
	e.Expires = strings.TrimSpace(e.Expires)
	if e.Expires != "" {
		if _, err := time.Parse(expiryLayout, e.Expires); err != nil {
			return errors.New("expiry must be a date like 2026-12-31")
		}
	}
	st := e.statement()
	return st.Validate()
}

// statement maps the entry to an OpenVEX statement, carrying only the fields
// its status allows (the entry may hold a stale impact or action from an
// earlier status).
func (e VEXEntry) statement() vex.Statement {
	st := vex.Statement{
		Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(e.Vulnerability)},
		Status:        vex.Status(e.Status),
	}
	switch st.Status {
	case vex.StatusNotAffected:
		st.Justification = vex.Justification(e.Justification)
		st.ImpactStatement = strings.TrimSpace(e.Impact)
	case vex.StatusAffected:
		st.ActionStatement = strings.TrimSpace(e.Action)
	}
	return st
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// VEXStore persists assessments per image repository in a JSON file.
type VEXStore struct {
	Path string
	mu   sync.Mutex
}

type vexFile map[string]map[string]VEXEntry // repo -> key -> entry

func (s *VEXStore) load() (vexFile, error) {
	f := vexFile{}
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	return f, json.Unmarshal(b, &f)
}

func (s *VEXStore) save(f vexFile) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// List returns the entries for an image, sorted by vulnerability id.
func (s *VEXStore) List(image string) ([]VEXEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	out := []VEXEntry{}
	for _, e := range f[ImageRepo(image)] {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Set validates and stores an entry.
func (s *VEXStore) Set(image string, e VEXEntry) (VEXEntry, error) {
	if err := e.Validate(); err != nil {
		return e, err
	}
	e.Key = VEXKey(e.Vulnerability, e.PURL, e.Package, e.Version)
	e.Updated = time.Now().UTC().Format(time.RFC3339)
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return e, err
	}
	repo := ImageRepo(image)
	if f[repo] == nil {
		f[repo] = map[string]VEXEntry{}
	}
	f[repo][e.Key] = e
	return e, s.save(f)
}

// Delete removes an entry.
func (s *VEXStore) Delete(image, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	delete(f[ImageRepo(image)], key)
	return s.save(f)
}

// ProductPURL builds the OCI package URL that identifies the scanned image,
// using the registry digest when trivy reported one.
func ProductPURL(image string, repoDigests []string) string {
	repo := ImageRepo(image)
	name := repo[strings.LastIndex(repo, "/")+1:]
	for _, d := range repoDigests {
		r, dig, ok := strings.Cut(d, "@")
		if ok && strings.HasPrefix(dig, "sha256:") {
			rn := r[strings.LastIndex(r, "/")+1:]
			return "pkg:oci/" + rn + "@" + strings.ReplaceAll(dig, ":", "%3A") + "?repository_url=" + url.QueryEscape(r)
		}
	}
	p := "pkg:oci/" + name
	q := url.Values{"repository_url": {repo}}
	if rest := strings.TrimPrefix(NormalizeImage(image), repo); strings.HasPrefix(rest, ":") {
		q.Set("tag", rest[1:])
	}
	return p + "?" + q.Encode()
}

// ExportOpenVEX renders entries as an OpenVEX document using go-vex, which
// stamps the current spec version and derives the canonical document id.
func ExportOpenVEX(entries []VEXEntry, product, author, role string) ([]byte, error) {
	if len(entries) == 0 {
		return nil, errors.New("no VEX assessments to export")
	}
	if strings.TrimSpace(author) == "" {
		return nil, errors.New("author is required in an OpenVEX document")
	}
	sorted := append([]VEXEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })

	doc := vex.New()
	doc.Author = author
	doc.AuthorRole = strings.TrimSpace(role)
	doc.Tooling = "Trivy Scanner (Wails)"
	for _, e := range sorted {
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Vulnerability, err)
		}
		sub := e.PURL
		if sub == "" {
			sub = "pkg:generic/" + url.PathEscape(e.Package) + "@" + url.PathEscape(e.Version)
		}
		st := e.statement()
		if ts, err := time.Parse(time.RFC3339, e.Updated); err == nil {
			st.Timestamp = &ts
		}
		st.Products = []vex.Product{{
			Component:     vex.Component{ID: product},
			Subcomponents: []vex.Subcomponent{{Component: vex.Component{ID: sub}}},
		}}
		doc.Statements = append(doc.Statements, st)
	}
	if _, err := doc.GenerateCanonicalID(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(&doc, "", "  ")
}

// ImportReport summarises what ImportOpenVEX did with a pasted document.
type ImportReport struct {
	Imported int      `json:"imported"` // findings that received an assessment
	Skipped  int      `json:"skipped"`  // statements that matched nothing or were invalid
	Marked   int      `json:"marked"`   // findings left without a statement that were marked under_investigation
	Warnings []string `json:"warnings"`
}

// ParseOpenVEX turns an OpenVEX document (v0.2.0, as read by go-vex) into assessments for the given findings. A statement with
// subcomponents applies to findings whose PURL (or name@version) matches one;
// a statement without applies to every finding with that vulnerability id.
// When several statements hit one finding the newest timestamp wins.
func ParseOpenVEX(data []byte, findings []Vulnerability) ([]VEXEntry, ImportReport, error) {
	rep := ImportReport{Warnings: []string{}}
	doc, err := openVEXDoc(data)
	if err != nil {
		return nil, rep, err
	}
	if len(doc.Statements) == 0 {
		return nil, rep, errors.New("document has no statements")
	}

	byKey := map[string]VEXEntry{}
	for i, st := range doc.Statements {
		ids := []string{string(st.Vulnerability.Name)}
		for _, a := range st.Vulnerability.Aliases {
			ids = append(ids, string(a))
		}
		var subs []string
		for _, p := range st.Products {
			for _, sc := range p.Subcomponents {
				subs = append(subs, sc.ID)
			}
		}
		stamp := time.Now().UTC()
		switch {
		case st.Timestamp != nil:
			stamp = st.Timestamp.UTC()
		case doc.Timestamp != nil:
			stamp = doc.Timestamp.UTC()
		}
		matched := false
		for _, v := range findings {
			if !containsFold(ids, v.ID) {
				continue
			}
			if len(subs) > 0 && !anyPURLMatches(subs, v) {
				continue
			}
			e := VEXEntry{
				Vulnerability: v.ID, Package: v.Package, Version: v.Installed, PURL: v.PURL,
				Status: string(st.Status), Justification: string(st.Justification),
				Impact: st.ImpactStatement, Action: st.ActionStatement,
				Updated: stamp.Format(time.RFC3339),
			}
			if err := e.Validate(); err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("statement %d (%s): %v", i+1, v.ID, err))
				matched = true // reported, not "unmatched"
				break
			}
			e.Key = v.Key
			if old, ok := byKey[e.Key]; !ok || e.Updated >= old.Updated {
				byKey[e.Key] = e
			}
			matched = true
		}
		if !matched {
			rep.Skipped++
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("statement %d (%s): no matching finding in this scan", i+1, ids[0]))
		}
	}
	out := make([]VEXEntry, 0, len(byKey))
	for _, e := range byKey {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	rep.Imported = len(out)
	return out, rep, nil
}

// openVEXDoc decodes an OpenVEX v0.2.0 document with go-vex.
func openVEXDoc(data []byte) (*vex.VEX, error) {
	doc, err := vex.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if !strings.Contains(doc.Context, "openvex") {
		return nil, errors.New("not an OpenVEX document (missing openvex @context)")
	}
	return doc, nil
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if x != "" && strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// SetMany stores already-validated entries, keeping their Updated stamps.
func (s *VEXStore) SetMany(image string, entries []VEXEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	repo := ImageRepo(image)
	if f[repo] == nil {
		f[repo] = map[string]VEXEntry{}
	}
	for _, e := range entries {
		f[repo][e.Key] = e
	}
	return s.save(f)
}

// MarkUnassessed gives every finding that has no assessment yet an
// under_investigation one, so each CVE is covered and the open work is the
// list of under_investigation entries. Existing assessments, expired ones
// included, are left alone. It returns how many entries it added.
func (s *VEXStore) MarkUnassessed(image string, findings []Vulnerability, author string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return 0, err
	}
	repo := ImageRepo(image)
	if f[repo] == nil {
		f[repo] = map[string]VEXEntry{}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	n := 0
	for _, v := range findings {
		if _, ok := f[repo][v.Key]; ok {
			continue // a finding repeated across layers shares one key
		}
		f[repo][v.Key] = VEXEntry{
			Key: v.Key, Vulnerability: v.ID, Package: v.Package, Version: v.Installed, PURL: v.PURL,
			Status: "under_investigation", Author: strings.TrimSpace(author), Updated: now,
		}
		n++
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.save(f)
}

// anyPURLMatches reports whether a statement's subcomponent ids cover a finding.
// Hand-written and hub-published documents often give versionless PURLs
// ("pkg:apk/alpine/zlib"), which apply to every version; qualifiers
// (arch, distro) are ignored on both sides.
func anyPURLMatches(subs []string, v Vulnerability) bool {
	generic := "pkg:generic/" + url.PathEscape(v.Package) + "@" + url.PathEscape(v.Installed)
	fname, fver := splitPURL(v.PURL)
	for _, sub := range subs {
		if sub == generic {
			return true
		}
		name, ver := splitPURL(sub)
		if v.PURL != "" && strings.EqualFold(name, fname) && (ver == "" || ver == fver) {
			return true
		}
	}
	return false
}

// splitPURL returns the unescaped "pkg:type/namespace/name" and the version.
func splitPURL(p string) (name, version string) {
	p, _, _ = strings.Cut(p, "#")
	p, _, _ = strings.Cut(p, "?")
	if i := strings.LastIndex(p, "@"); i > strings.LastIndex(p, "/") {
		p, version = p[:i], p[i+1:]
	}
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	if u, err := url.PathUnescape(version); err == nil {
		version = u
	}
	return p, version
}
