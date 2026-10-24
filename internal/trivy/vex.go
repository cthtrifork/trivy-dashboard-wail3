package trivy

import (
	"crypto/sha256"
	"encoding/hex"
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
)

// VEX statuses and justifications as defined by OpenVEX v0.2.0.
var (
	VEXStatuses       = []string{"affected", "not_affected", "fixed", "under_investigation"}
	VEXJustifications = []string{
		"component_not_present",
		"vulnerable_code_not_present",
		"vulnerable_code_not_in_execute_path",
		"vulnerable_code_cannot_be_controlled_by_adversary",
		"inline_mitigations_already_exist",
	}
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
	Updated       string `json:"updated"`
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
	switch e.Status {
	case "not_affected":
		if e.Justification == "" && strings.TrimSpace(e.Impact) == "" {
			return errors.New("not_affected needs a justification or an impact statement")
		}
	case "affected":
		if strings.TrimSpace(e.Action) == "" {
			return errors.New("affected needs an action statement (what should be done about it)")
		}
	}
	return nil
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

// ExportOpenVEX renders entries as an OpenVEX v0.2.0 document.
func ExportOpenVEX(entries []VEXEntry, product, author, role string) ([]byte, error) {
	if len(entries) == 0 {
		return nil, errors.New("no VEX assessments to export")
	}
	if strings.TrimSpace(author) == "" {
		return nil, errors.New("author is required in an OpenVEX document")
	}
	type obj = map[string]any
	sorted := append([]VEXEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })

	stmts := []obj{}
	for _, e := range sorted {
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Vulnerability, err)
		}
		sub := e.PURL
		if sub == "" {
			sub = "pkg:generic/" + url.PathEscape(e.Package) + "@" + url.PathEscape(e.Version)
		}
		st := obj{
			"vulnerability": obj{"name": e.Vulnerability},
			"products":      []obj{{"@id": product, "subcomponents": []obj{{"@id": sub}}}},
			"status":        e.Status,
			"timestamp":     e.Updated,
		}
		if e.Justification != "" {
			st["justification"] = e.Justification
		}
		if strings.TrimSpace(e.Impact) != "" {
			st["impact_statement"] = e.Impact
		}
		if strings.TrimSpace(e.Action) != "" {
			st["action_statement"] = e.Action
		}
		stmts = append(stmts, st)
	}
	body, _ := json.Marshal(stmts)
	sum := sha256.Sum256(body)
	doc := obj{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        "https://openvex.dev/docs/public/vex-" + hex.EncodeToString(sum[:]),
		"author":     author,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"version":    1,
		"tooling":    "Trivy Scanner (Wails)",
		"statements": stmts,
	}
	if strings.TrimSpace(role) != "" {
		doc["role"] = role
	}
	return json.MarshalIndent(doc, "", "  ")
}
