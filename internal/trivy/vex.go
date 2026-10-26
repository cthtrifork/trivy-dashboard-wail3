package trivy

import (
	"bytes"
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

	"github.com/distribution/reference"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
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
	// Description is the vulnerability description of an imported statement,
	// kept so the next export writes it back.
	Description   string `json:"description"`
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
	named, err := reference.Parse(ref)
	if err != nil {
		return ref
	}
	if n, ok := named.(reference.Named); ok {
		return n.Name()
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
		Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(e.Vulnerability), Description: e.Description},
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
	if old, ok := f[repo][e.Key]; ok && e.Description == "" {
		e.Description = old.Description // the editor does not show it, so do not drop it
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

// Clear deletes the whole store file, and with it every image's assessments.
func (s *VEXStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ProductPURL builds the OCI package URL that identifies the scanned image.
// It carries only the image name, with no digest, tag or repository, so the
// same document covers every tag of the image.
func ProductPURL(image string) string {
	repo := ImageRepo(image)
	return "pkg:oci/" + repo[strings.LastIndex(repo, "/")+1:]
}

// DocMeta is the document-level data of an imported OpenVEX file that is kept
// so the next export reuses it.
type DocMeta struct {
	ID     string `json:"id"`
	Author string `json:"author"`
	Role   string `json:"role"`
	// Version, Timestamp (RFC 3339, when the document was first issued) and
	// Tooling are carried over so a re-export is the next version of the same
	// document rather than a new one.
	Version   int    `json:"version"`
	Timestamp string `json:"timestamp"`
	Tooling   string `json:"tooling"`
}

// AuthorPlaceholder stands in for the author until one is imported or typed, so
// the document is always shown.
const AuthorPlaceholder = "<author>"

// ExportOpenVEX renders entries as an OpenVEX document using go-vex, which
// stamps the current spec version and derives the canonical document id.
// A non-empty meta.ID (an imported document's @id) is kept, and so are its
// timestamp and tooling; its version is incremented, since the export changes
// the document. An empty author becomes AuthorPlaceholder.
func ExportOpenVEX(entries []VEXEntry, product string, meta DocMeta) ([]byte, error) {
	if len(entries) == 0 {
		return nil, errors.New("no VEX assessments to export")
	}
	id, role := meta.ID, meta.Role
	author := strings.TrimSpace(meta.Author)
	if author == "" {
		author = AuthorPlaceholder
	}
	sorted := append([]VEXEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })

	doc := vex.New()
	doc.Author = author
	doc.AuthorRole = strings.TrimSpace(role)
	doc.Tooling = strings.TrimSpace(meta.Tooling)
	if meta.Version > 0 {
		doc.Version = meta.Version + 1
		now := time.Now().UTC()
		doc.LastUpdated = &now
	}
	if ts, err := time.Parse(time.RFC3339, meta.Timestamp); err == nil {
		doc.Timestamp = &ts
	}
	for _, e := range sorted {
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Vulnerability, err)
		}
		sub := e.PURL
		if sub == "" && e.Package != "" {
			sub = "pkg:generic/" + url.PathEscape(e.Package) + "@" + url.PathEscape(e.Version)
		}
		st := e.statement()
		if ts, err := time.Parse(time.RFC3339, e.Updated); err == nil {
			st.Timestamp = &ts
		}
		prod := vex.Product{Component: vex.Component{ID: product}}
		if sub != "" {
			prod.Subcomponents = []vex.Subcomponent{{Component: vex.Component{ID: sub}}}
		}
		st.Products = []vex.Product{prod}
		doc.Statements = append(doc.Statements, st)
	}
	if id = strings.TrimSpace(id); id != "" {
		doc.ID = id
	} else if _, err := doc.GenerateCanonicalID(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(&doc, "", "  ")
	if err != nil {
		return nil, err
	}
	// The placeholder author has angle brackets, which encoding/json escapes.
	return bytes.ReplaceAll(bytes.ReplaceAll(b, []byte(`\u003c`), []byte("<")), []byte(`\u003e`), []byte(">")), nil
}

// ImportReport summarises what ImportOpenVEX did with a pasted document.
type ImportReport struct {
	Imported int      `json:"imported"` // findings that received an assessment
	Skipped  int      `json:"skipped"`  // statements kept as they are because no finding of this scan matched them
	Marked   int      `json:"marked"`   // findings left without a statement that were marked under_investigation
	Warnings []string `json:"warnings"`
	Doc      DocMeta  `json:"doc"` // @id, author and role of the document
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

	rep.Doc = DocMeta{
		ID: doc.ID, Author: strings.TrimSpace(doc.Author), Role: strings.TrimSpace(doc.AuthorRole),
		Version: doc.Version, Tooling: strings.TrimSpace(doc.Tooling),
	}
	if doc.Timestamp != nil {
		rep.Doc.Timestamp = doc.Timestamp.UTC().Format(time.RFC3339Nano)
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
				Impact: st.ImpactStatement, Action: st.ActionStatement, Description: st.Vulnerability.Description,
				Updated: stamp.Format(time.RFC3339Nano),
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
			// Keep it so merging a file and exporting again does not drop
			// statements about other tags or packages of the image.
			rep.Skipped++
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("statement %d (%s): no finding in this scan, kept as it is", i+1, ids[0]))
			for _, e := range unmatchedEntries(st, ids[0], subs, stamp) {
				if err := e.Validate(); err != nil {
					rep.Warnings = append(rep.Warnings, fmt.Sprintf("statement %d (%s): %v", i+1, ids[0], err))
					continue
				}
				e.Key = VEXKey(e.Vulnerability, e.PURL, e.Package, e.Version)
				if old, ok := byKey[e.Key]; !ok || e.Updated >= old.Updated {
					byKey[e.Key] = e
				}
			}
		}
	}
	out := make([]VEXEntry, 0, len(byKey))
	for _, e := range byKey {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	rep.Imported = len(out) - kept(out, findings)
	return out, rep, nil
}

// unmatchedEntries turns a statement that hit no finding into one entry per
// subcomponent (or one without a package when it names none).
func unmatchedEntries(st vex.Statement, id string, subs []string, stamp time.Time) []VEXEntry {
	base := VEXEntry{
		Vulnerability: id, Status: string(st.Status), Justification: string(st.Justification),
		Impact: st.ImpactStatement, Action: st.ActionStatement, Description: st.Vulnerability.Description,
		Updated: stamp.Format(time.RFC3339Nano),
	}
	if len(subs) == 0 {
		return []VEXEntry{base}
	}
	out := make([]VEXEntry, 0, len(subs))
	for _, sub := range subs {
		e := base
		e.PURL = sub
		if u, err := packageurl.FromString(sub); err == nil {
			e.Package, e.Version = u.Name, u.Version
		}
		out = append(out, e)
	}
	return out
}

// kept counts the entries that belong to no finding.
func kept(entries []VEXEntry, findings []Vulnerability) int {
	known := make(map[string]bool, len(findings))
	for _, v := range findings {
		known[v.Key] = true
	}
	n := 0
	for _, e := range entries {
		if !known[e.Key] {
			n++
		}
	}
	return n
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

func (s *VEXStore) metaPath() string { return s.Path + ".meta" }

// Meta returns the document data kept from the last import of the image.
func (s *VEXStore) Meta(image string) (DocMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadMeta()
	return m[ImageRepo(image)], err
}

// SetMeta keeps the document data of an imported file for later exports.
func (s *VEXStore) SetMeta(image string, d DocMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadMeta()
	if err != nil {
		return err
	}
	m[ImageRepo(image)] = d
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(), b, 0o600)
}

func (s *VEXStore) loadMeta() (map[string]DocMeta, error) {
	m := map[string]DocMeta{}
	b, err := os.ReadFile(s.metaPath())
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	return m, json.Unmarshal(b, &m)
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
// included, are left alone. A non-empty minSeverity (CRITICAL, HIGH, MEDIUM,
// LOW) restricts it to findings of that severity or worse. It returns how many
// entries it added.
func (s *VEXStore) MarkUnassessed(image string, findings []Vulnerability, author, minSeverity string) (int, error) {
	limit, filtered := severityRank[strings.ToUpper(strings.TrimSpace(minSeverity))]
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
		if filtered && severityRank[v.Severity] > limit {
			continue
		}
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

// splitPURL returns the canonical "pkg:type/namespace/name" and the version.
// A string that is not a package URL is returned as it is, without a version.
func splitPURL(p string) (name, version string) {
	u, err := packageurl.FromString(p)
	if err != nil {
		return p, ""
	}
	base := packageurl.PackageURL{Type: u.Type, Namespace: u.Namespace, Name: u.Name}
	return base.ToString(), u.Version
}
