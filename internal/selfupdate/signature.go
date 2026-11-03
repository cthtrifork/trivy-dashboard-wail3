package selfupdate

import (
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/wailsapp/wails/v3/pkg/updater"
)

// SignatureSuffix is appended to a release asset's name to get its signature asset.
const SignatureSuffix = ".sig"

// ErrUnsigned is returned for a release whose binary has no valid-looking signature asset while a
// public key is pinned in the app.
var ErrUnsigned = errors.New("release is not signed")

//go:embed update-key.pub
var embeddedKey string

// PublicKey is the Ed25519 key the app was built to trust, or nil when none is pinned (then only
// the SHA-256 from SHA256SUMS is checked). An unparsable key file is a build error, not a silent
// downgrade, so it panics at start-up.
func PublicKey() ed25519.PublicKey {
	key, err := parsePublicKey(embeddedKey)
	if err != nil {
		panic("selfupdate: update-key.pub: " + err.Error())
	}
	return key
}

// parsePublicKey reads the key file: comment lines (#) and blanks are ignored, and the first other
// line is the base64 of the 32-byte key. No such line means "no key", not an error.
func parsePublicKey(text string) (ed25519.PublicKey, error) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("not a base64 Ed25519 public key (32 bytes)")
		}
		return ed25519.PublicKey(raw), nil
	}
	return nil, nil
}

// signed wraps a provider and attaches the Ed25519 signature published next to the binary. The
// GitHub provider only reads SHA256SUMS, so the signature is fetched here from the release's
// "<asset>.sig" asset: base64 of an Ed25519 signature over the binary's raw SHA-256 digest, which
// is exactly what the updater verifies under Config.PublicKey ("ed25519" algorithm).
//
// The key itself is never read from the release: the updater verifies against the key it was
// configured with, so a hijacked release cannot bring its own.
type signed struct {
	updater.Provider
	repo, base string
	client     *http.Client
}

func (p signed) Check(ctx context.Context, req updater.CheckRequest) (*updater.Release, error) {
	rel, err := p.Provider.Check(ctx, req)
	if err != nil || rel == nil {
		return rel, err
	}
	if rel.Verification == nil {
		return rel, nil // failClosed reports the missing digest
	}
	tag, _ := rel.Metadata["github.release.tag"].(string)
	if tag == "" {
		return nil, fmt.Errorf("%w: release %s has no tag to look the signature up by", ErrUnsigned, rel.Version)
	}
	sig, err := p.fetchSignature(ctx, tag, rel.Artifact.Filename+SignatureSuffix)
	if err != nil {
		return nil, fmt.Errorf("%w (release %s, asset %s): %w", ErrUnsigned, rel.Version, rel.Artifact.Filename, err)
	}
	rel.Verification.SignatureAlgo = "ed25519"
	rel.Verification.Signature = sig
	return rel, nil
}

func (p signed) fetchSignature(ctx context.Context, tag, name string) ([]byte, error) {
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"assets"`
	}
	if err := p.getJSON(ctx, p.base+"/repos/"+p.repo+"/releases/tags/"+tag, &rel); err != nil {
		return nil, err
	}
	for _, a := range rel.Assets {
		if a.Name != name {
			continue
		}
		body, err := p.get(ctx, a.URL, "application/octet-stream")
		if err != nil {
			return nil, err
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%s is not a base64 Ed25519 signature", name)
		}
		return sig, nil
	}
	return nil, fmt.Errorf("no %s asset in the release", name)
}

func (p signed) getJSON(ctx context.Context, url string, out any) error {
	body, err := p.get(ctx, url, "application/vnd.github+json")
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (p signed) get(ctx context.Context, url, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func newSigned(inner updater.Provider, baseURL string) signed {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return signed{Provider: inner, repo: Repository, base: strings.TrimRight(baseURL, "/"), client: &http.Client{Timeout: 30 * time.Second}}
}
