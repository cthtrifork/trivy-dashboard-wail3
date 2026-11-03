package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/updater"
	"github.com/wailsapp/wails/v3/pkg/updater/providers/github"
)

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	enc := base64.StdEncoding.EncodeToString(pub)
	if k, err := parsePublicKey("# comment\n\n  " + enc + "  \n"); err != nil || !k.Equal(pub) {
		t.Errorf("valid key: %v %v", k, err)
	}
	if k, err := parsePublicKey("# only comments\n\n"); k != nil || err != nil {
		t.Errorf("no key line must mean no key, got %v %v", k, err)
	}
	for _, bad := range []string{"not base64!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := parsePublicKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The key committed to the repository must parse (it may be absent).
func TestEmbeddedKeyParses(t *testing.T) {
	if _, err := parsePublicKey(embeddedKey); err != nil {
		t.Fatal(err)
	}
}

func TestMatchAssetSkipsSignatureFiles(t *testing.T) {
	assets := []github.ReleaseAsset{{Name: "trivy-scanner_linux_amd64.sig"}, {Name: "trivy-scanner_linux_amd64"}}
	if got := MatchAsset(updater.CheckRequest{Platform: "linux", Arch: "amd64"}, assets); got != 1 {
		t.Errorf("picked %d, want the binary at 1", got)
	}
}

func signedCheck(t *testing.T, files map[string][]byte, order []string, binary []byte, sign func(digest []byte) []byte) (*updater.Release, error) {
	t.Helper()
	if sign != nil {
		sum := sha256.Sum256(binary)
		files["trivy-scanner_linux_amd64"+SignatureSuffix] = []byte(base64.StdEncoding.EncodeToString(sign(sum[:])) + "\n")
		order = append(order, "trivy-scanner_linux_amd64"+SignatureSuffix)
	}
	srv := newFakeGitHub(t, "v0.2.0", files, order)
	inner, err := NewProvider(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := newSigned(inner, srv.URL)
	return p.Check(context.Background(), updater.CheckRequest{CurrentVersion: "v0.1.0", Platform: "linux", Arch: "amd64"})
}

func TestSignedProviderAttachesSignature(t *testing.T) {
	files, order, binary := packageRelease(t, "v0.2.0")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rel, err := signedCheck(t, files, order, binary, func(d []byte) []byte { return ed25519.Sign(priv, d) })
	if err != nil {
		t.Fatal(err)
	}
	v := rel.Verification
	if v == nil || v.SignatureAlgo != "ed25519" || len(v.Digest) == 0 {
		t.Fatalf("verification: %+v", v)
	}
	// What the updater checks: the signature over the digest of the downloaded bytes, under the pinned key.
	if !ed25519.Verify(pub, v.Digest, v.Signature) {
		t.Error("signature does not verify against the digest")
	}
	if ed25519.Verify(pub, []byte("other digest, same length......"), v.Signature) {
		t.Error("signature verifies for a different digest")
	}
}

func TestSignedProviderFailsClosed(t *testing.T) {
	files, order, binary := packageRelease(t, "v0.2.0")
	if _, err := signedCheck(t, files, order, binary, nil); !errors.Is(err, ErrUnsigned) {
		t.Errorf("missing .sig: err = %v, want ErrUnsigned", err)
	}
	files, order, binary = packageRelease(t, "v0.2.0")
	_, err := signedCheck(t, files, order, binary, func([]byte) []byte { return []byte("short") })
	if !errors.Is(err, ErrUnsigned) || !strings.Contains(err.Error(), "not a base64 Ed25519 signature") {
		t.Errorf("garbled .sig: err = %v", err)
	}
}
