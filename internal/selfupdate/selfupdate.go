// Package selfupdate configures Wails' built-in updater for this app: a GitHub
// Releases provider that only offers installable, checksum-verified releases.
//
// The updater swaps the running binary for a downloaded file, so every choice
// here is about not installing something wrong: development builds never update
// themselves, only the raw binary asset is considered (the release tarball holds
// several files, which the updater rejects), and a release without a SHA-256
// digest, or without a signature from the key compiled into the app, is refused
// rather than installed unchecked.
package selfupdate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/wailsapp/wails/v3/pkg/updater"
	"github.com/wailsapp/wails/v3/pkg/updater/providers/github"
)

const (
	// Repository is where releases are published.
	Repository = "cthtrifork/trivy-dashboard-wail3"
	// ChecksumAsset is the release asset listing the SHA-256 of every other asset.
	// The provider looks it up by exact name, so it must not contain the version.
	ChecksumAsset = "SHA256SUMS"
)

// releaseVersion matches the semantic versions a release is tagged with, with or
// without the leading "v". "dev", "ci-<sha>" and the like are not release versions.
var releaseVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// Enabled reports whether a build that identifies itself as version should be
// able to update. This matters: the updater compares versions with x/mod/semver,
// where an invalid string such as "dev" sorts below every real version, so a
// development build would otherwise offer to replace itself with the newest
// release.
func Enabled(version string) bool { return releaseVersion.MatchString(version) }

// isArchive reports whether an asset name is an archive or a Linux package (.deb, .rpm), none of
// which the updater can install in place.
func isArchive(name string) bool {
	n := strings.ToLower(name)
	for _, ext := range []string{".tar.gz", ".tgz", ".zip", ".deb", ".rpm"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return false
}

// MatchAsset picks the raw binary for the running platform. Archives and packages are
// skipped on purpose: the release also ships a tarball (binary + README + LICENSE) and
// .deb/.rpm packages for people, but the updater can only install a single file or an archive with
// exactly one top-level entry, and the default matcher would take whichever
// matching asset GitHub lists first.
func MatchAsset(req updater.CheckRequest, assets []github.ReleaseAsset) int {
	var plain []github.ReleaseAsset
	var origin []int
	for i, a := range assets {
		if !isArchive(a.Name) {
			plain = append(plain, a)
			origin = append(origin, i)
		}
	}
	if i := github.DefaultAssetMatcher(req, plain); i >= 0 {
		return origin[i]
	}
	return -1
}

// ErrUnverified is returned for a release that carries no SHA-256 digest.
var ErrUnverified = errors.New("release has no SHA-256 digest to verify the download against")

// ErrUnsigned is returned for a release that has no signature, or one that does not verify.
var ErrUnsigned = errors.New("release is not signed by the update signing key")

// maxSignature bounds the signature download: an Ed25519 signature is 64 bytes.
const maxSignature = 1024

// SignatureAsset names the detached signature published next to the binary asset.
func SignatureAsset(binary string) string { return binary + ".sig" }

// verified wraps a provider and refuses releases that are not both checksummed and signed. The GitHub
// provider silently omits verification when the checksum file is missing or has no line for the chosen
// asset, and the updater would then install unchecked bytes; and a checksum from the same release
// proves nothing about who published it. For a program that replaces its own executable both must be
// errors. The signature covers the digest, the version and the asset name (see Statement), and the
// updater compares the downloaded bytes against that digest, so the bytes installed are the signed ones.
type verified struct {
	updater.Provider
	key    ed25519.PublicKey
	client *http.Client
}

func (p verified) Check(ctx context.Context, req updater.CheckRequest) (*updater.Release, error) {
	rel, err := p.Provider.Check(ctx, req)
	if err != nil || rel == nil {
		return rel, err
	}
	if rel.Verification == nil || len(rel.Verification.Digest) == 0 {
		return nil, fmt.Errorf("%w (release %s, asset %s): is %s part of the release?",
			ErrUnverified, rel.Version, rel.Artifact.Filename, ChecksumAsset)
	}
	assetURL, _ := rel.Metadata["github.asset.url"].(string)
	if assetURL == "" {
		return nil, fmt.Errorf("%w (release %s): the provider did not say where the asset is", ErrUnsigned, rel.Version)
	}
	sig, err := p.fetchSignature(ctx, assetURL+".sig")
	if err != nil {
		return nil, fmt.Errorf("%w (release %s, asset %s): is %s part of the release? %v",
			ErrUnsigned, rel.Version, rel.Artifact.Filename, SignatureAsset(rel.Artifact.Filename), err)
	}
	if err := VerifyRelease(p.key, rel.Version, rel.Artifact.Filename, rel.Verification.Digest, sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsigned, err)
	}
	return rel, nil
}

func (p verified) fetchSignature(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxSignature))
}

// NewProvider returns the GitHub Releases provider, which only offers releases signed by key.
// baseURL overrides the API endpoint (GitHub Enterprise, or a test server); empty means api.github.com.
func NewProvider(baseURL string, key ed25519.PublicKey) (updater.Provider, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrNoSigningKey
	}
	gh, err := github.New(github.Config{
		Repository:    Repository,
		BaseURL:       baseURL,
		AssetMatcher:  MatchAsset,
		ChecksumAsset: ChecksumAsset,
	})
	if err != nil {
		return nil, err
	}
	return verified{Provider: gh, key: key, client: &http.Client{Timeout: 30 * time.Second}}, nil
}

// Installable reports whether the updater could replace the executable at exe. It stages
// the new binary in a directory beside it, so that directory must be writable. A copy
// installed by a package manager (/usr/bin) is not, and should be updated by that package
// manager instead. Inside an AppImage the updater replaces the .AppImage file itself.
func Installable(exe string) error {
	if appImage := os.Getenv("APPIMAGE"); appImage != "" {
		exe = appImage
	}
	dir := filepath.Dir(exe)
	probe, err := os.CreateTemp(dir, ".update-probe-*")
	if err != nil {
		return fmt.Errorf("%s is not writable, so the app cannot replace itself there "+
			"(was it installed by a package manager? update it with that instead): %w", dir, err)
	}
	probe.Close()
	return os.Remove(probe.Name())
}
