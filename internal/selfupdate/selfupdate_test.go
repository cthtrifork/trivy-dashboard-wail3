package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/updater"
	"github.com/wailsapp/wails/v3/pkg/updater/providers/github"
)

func TestEnabled(t *testing.T) {
	for v, want := range map[string]bool{
		"v0.1.0":               true,
		"0.1.0":                true,
		"v1.2.3-rc.1":          true,
		"v0.0.0-dryrun.abc123": true, // the release workflow's dry-run version is a valid semver
		"v1.2.3+build5":        true,
		"dev":                  false, // the default for `go run` / `go build`
		"":                     false,
		"ci-0123456":           false, // CI binaries
		"v1.2":                 false,
		"latest":               false,
		"v1.2.3;rm -rf":        false,
	} {
		if got := Enabled(v); got != want {
			t.Errorf("Enabled(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestMatchAsset(t *testing.T) {
	linux := updater.CheckRequest{Platform: "linux", Arch: "amd64"}
	// GitHub lists assets in upload order; the tarball can come first.
	assets := []github.ReleaseAsset{
		{Name: "trivy-scanner_v0.2.0_linux_amd64.tar.gz"},
		{Name: "trivy-scanner_v0.2.0_amd64.deb"},
		{Name: "trivy-scanner_v0.2.0_x86_64.rpm"},
		{Name: "SHA256SUMS"},
		{Name: "trivy-scanner_linux_amd64"},
	}
	if got := MatchAsset(linux, assets); got != 4 {
		t.Errorf("picked index %d (%s), want the raw binary at 4", got, assets[max(got, 0)].Name)
	}
	if got := MatchAsset(updater.CheckRequest{Platform: "linux", Arch: "arm64"}, assets); got != -1 {
		t.Errorf("arm64 matched %d, but none is published", got)
	}
	if got := MatchAsset(updater.CheckRequest{Platform: "windows", Arch: "amd64"}, assets); got != -1 {
		t.Errorf("windows matched %d", got)
	}
	// With only the multi-file tarball and the packages the update must fail with "no asset", not install it.
	if got := MatchAsset(linux, assets[:4]); got != -1 {
		t.Errorf("a tarball-only release matched %d", got)
	}
}

// fakeGitHub serves one release in the shape of the GitHub REST API.
type fakeGitHub struct {
	*httptest.Server
}

func newFakeGitHub(t *testing.T, tag string, files map[string][]byte, order []string) *fakeGitHub {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/repos/"+Repository+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		type asset struct {
			ID                 int    `json:"id"`
			Name               string `json:"name"`
			ContentType        string `json:"content_type"`
			Size               int    `json:"size"`
			BrowserDownloadURL string `json:"browser_download_url"`
		}
		var assets []asset
		for i, name := range order {
			assets = append(assets, asset{i + 1, name, "application/octet-stream", len(files[name]), srv.URL + "/dl/" + name})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": tag, "name": tag, "body": "notes", "html_url": srv.URL, "assets": assets,
		})
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[strings.TrimPrefix(r.URL.Path, "/dl/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	return &fakeGitHub{srv}
}

// packageRelease runs the real scripts/package-release.sh on a stand-in binary and
// returns its output files, in the order a release would list them.
func packageRelease(t *testing.T, version string) (files map[string][]byte, order []string, binary []byte) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the release is packaged on Linux")
	}
	for _, tool := range []string{"bash", "sha256sum", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	binary = make([]byte, 4096)
	_, _ = rand.Read(binary)
	dir := t.TempDir()
	bin := filepath.Join(dir, "built")
	if err := os.WriteFile(bin, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "dist")
	cmd := exec.Command("bash", "../../scripts/package-release.sh", bin, version, out)
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("package-release.sh: %v\n%s", err, msg)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	files = map[string][]byte{}
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(out, e.Name()))
		files[e.Name()] = b
	}
	// Put the tarball first: the default matcher would take it, ours must not.
	for name := range files {
		if strings.HasSuffix(name, ".tar.gz") {
			order = append([]string{name}, order...)
		} else {
			order = append(order, name)
		}
	}
	return files, order, binary
}

// signRelease signs the raw binary of a packaged release with the real scripts/sign-update.sh, adds
// the .sig next to it, and returns the matching public key. It is the contract between the release
// workflow and the app: the script's output must verify under Statement and VerifyRelease.
func signRelease(t *testing.T, version string, files map[string][]byte, order []string) (map[string][]byte, []string, ed25519.PublicKey) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "private.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	const raw = "trivy-scanner_linux_amd64"
	bin := filepath.Join(dir, raw)
	if err := os.WriteFile(bin, files[raw], 0o755); err != nil {
		t.Fatal(err)
	}
	if msg, err := exec.Command("bash", "../../scripts/sign-update.sh", "sign", bin, version, keyFile).CombinedOutput(); err != nil {
		t.Fatalf("sign-update.sh: %v\n%s", err, msg)
	}
	sig, err := os.ReadFile(bin + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	signed := map[string][]byte{SignatureAsset(raw): sig}
	for k, v := range files {
		signed[k] = v
	}
	return signed, append(append([]string{}, order...), SignatureAsset(raw)), pub
}

func check(t *testing.T, srv *fakeGitHub, current string, key ed25519.PublicKey) (*updater.Release, error) {
	t.Helper()
	p, err := NewProvider(srv.URL, key)
	if err != nil {
		t.Fatal(err)
	}
	return p.Check(context.Background(), updater.CheckRequest{CurrentVersion: current, Platform: "linux", Arch: "amd64"})
}

// The release workflow's output must be exactly what the updater can consume.
func TestReleaseLayoutIsInstallable(t *testing.T) {
	files, order, binary := packageRelease(t, "v0.2.0")
	files, order, key := signRelease(t, "v0.2.0", files, order)
	srv := newFakeGitHub(t, "v0.2.0", files, order)

	rel, err := check(t, srv, "v0.1.0", key)
	if err != nil || rel == nil {
		t.Fatalf("Check: %v %v", rel, err)
	}
	if rel.Version != "0.2.0" || rel.Artifact.Filename != "trivy-scanner_linux_amd64" {
		t.Fatalf("release %s picked asset %q", rel.Version, rel.Artifact.Filename)
	}
	want := sha256.Sum256(binary)
	if rel.Verification == nil || string(rel.Verification.Digest) != string(want[:]) {
		t.Fatalf("digest does not match the binary: %+v", rel.Verification)
	}

	// Download delivers the raw binary byte for byte, which is what gets swapped in.
	p, _ := NewProvider(srv.URL, key)
	var got strings.Builder
	if err := p.Download(context.Background(), rel, &got, func(int64, int64) {}); err != nil {
		t.Fatal(err)
	}
	if got.String() != string(binary) {
		t.Error("downloaded bytes differ from the packaged binary")
	}

	// The tarball is for people: several entries, so the updater could not install it.
	var tarball string
	for name := range files {
		if strings.HasSuffix(name, ".tar.gz") {
			tarball = name
		}
	}
	if !strings.Contains(string(files["SHA256SUMS"]), tarball) {
		t.Errorf("SHA256SUMS should also list %s", tarball)
	}
}

func TestVersionComparison(t *testing.T) {
	files, order, _ := packageRelease(t, "v0.2.0")
	files, order, key := signRelease(t, "v0.2.0", files, order)
	srv := newFakeGitHub(t, "v0.2.0", files, order)
	for current, wantUpdate := range map[string]bool{
		"v0.1.0":      true,
		"0.1.9":       true, // no leading v
		"v0.2.0-rc.1": true, // a release candidate is older than the release
		"v0.2.0":      false,
		"v1.0.0":      false, // never downgrade
	} {
		rel, err := check(t, srv, current, key)
		if err != nil {
			t.Errorf("current %s: %v", current, err)
			continue
		}
		if (rel != nil) != wantUpdate {
			t.Errorf("current %s: update offered = %v, want %v", current, rel != nil, wantUpdate)
		}
	}
}

// A release the updater could not verify must be refused, not installed unchecked.
func TestUnverifiedReleaseIsRefused(t *testing.T) {
	files, order, _ := packageRelease(t, "v0.2.0")
	files, order, key := signRelease(t, "v0.2.0", files, order)

	t.Run("no SHA256SUMS in the release", func(t *testing.T) {
		f := map[string][]byte{}
		var o []string
		for _, n := range order {
			if n != "SHA256SUMS" {
				f[n], o = files[n], append(o, n)
			}
		}
		_, err := check(t, newFakeGitHub(t, "v0.2.0", f, o), "v0.1.0", key)
		if !errors.Is(err, ErrUnverified) {
			t.Fatalf("err = %v, want ErrUnverified", err)
		}
	})

	t.Run("SHA256SUMS does not list the binary", func(t *testing.T) {
		f := map[string][]byte{}
		for k, v := range files {
			f[k] = v
		}
		f["SHA256SUMS"] = []byte("0000000000000000000000000000000000000000000000000000000000000000  something_else\n")
		_, err := check(t, newFakeGitHub(t, "v0.2.0", f, order), "v0.1.0", key)
		if !errors.Is(err, ErrUnverified) {
			t.Fatalf("err = %v, want ErrUnverified", err)
		}
	})

	t.Run("up to date is not an error even without checksums", func(t *testing.T) {
		rel, err := check(t, newFakeGitHub(t, "v0.1.0", map[string][]byte{"trivy-scanner_linux_amd64": {1}}, []string{"trivy-scanner_linux_amd64"}), "v0.1.0", key)
		if err != nil || rel != nil {
			t.Fatalf("got %v, %v", rel, err)
		}
	})
}

// The checksum comes from the release itself, so only the signature says who published it.
func TestUnsignedOrForgedReleaseIsRefused(t *testing.T) {
	files, order, binary := packageRelease(t, "v0.2.0")
	signed, signedOrder, key := signRelease(t, "v0.2.0", files, order)
	const raw = "trivy-scanner_linux_amd64"

	copyWith := func(mutate func(map[string][]byte)) map[string][]byte {
		f := map[string][]byte{}
		for k, v := range signed {
			f[k] = v
		}
		mutate(f)
		return f
	}
	// A release that someone with write access to the repository republished: the binary and
	// SHA256SUMS agree with each other, but the signature is still the old one.
	forged := func() map[string][]byte {
		evil := append([]byte("evil"), binary...)
		sum := sha256.Sum256(evil)
		return copyWith(func(f map[string][]byte) {
			f[raw] = evil
			f["SHA256SUMS"] = []byte(hexOf(sum[:]) + "  " + raw + "\n")
		})
	}()
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)

	for name, c := range map[string]struct {
		files map[string][]byte
		key   ed25519.PublicKey
	}{
		"no signature in the release": {copyWith(func(f map[string][]byte) { delete(f, raw+".sig") }), key},
		"signature of another binary": {forged, key},
		"signed by another key":       {signed, otherKey.Public().(ed25519.PublicKey)},
		"truncated signature":         {copyWith(func(f map[string][]byte) { f[raw+".sig"] = f[raw+".sig"][:10] }), key},
		"empty signature":             {copyWith(func(f map[string][]byte) { f[raw+".sig"] = nil }), key},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := check(t, newFakeGitHub(t, "v0.2.0", c.files, signedOrder), "v0.1.0", c.key)
			if !errors.Is(err, ErrUnsigned) {
				t.Fatalf("err = %v, want ErrUnsigned", err)
			}
		})
	}

	t.Run("a signed release is accepted", func(t *testing.T) {
		if rel, err := check(t, newFakeGitHub(t, "v0.2.0", signed, signedOrder), "v0.1.0", key); err != nil || rel == nil {
			t.Fatalf("got %v, %v", rel, err)
		}
	})

	// The signature names the version: an old signed binary cannot be offered as a newer release.
	t.Run("signed for another version", func(t *testing.T) {
		_, err := check(t, newFakeGitHub(t, "v0.3.0", signed, signedOrder), "v0.1.0", key)
		if !errors.Is(err, ErrUnsigned) {
			t.Fatalf("err = %v, want ErrUnsigned", err)
		}
	})
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func TestNewProviderNeedsAKey(t *testing.T) {
	if _, err := NewProvider("", nil); !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("err = %v, want ErrNoSigningKey", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if got, err := ParsePublicKey(append([]byte("# a comment above the key\n"), block...)); err != nil || !got.Equal(pub) {
		t.Errorf("ParsePublicKey = %v, %v", got, err)
	}
	for name, bad := range map[string][]byte{"empty": nil, "comment only": []byte("# placeholder\n"), "garbage block": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")})} {
		if _, err := ParsePublicKey(bad); !errors.Is(err, ErrNoSigningKey) {
			t.Errorf("%s: err = %v, want ErrNoSigningKey", name, err)
		}
	}
}

// The committed key file is either a real key or the placeholder; it must never be something
// that parses as a different kind of key.
func TestCommittedSigningKey(t *testing.T) {
	if key, err := SigningKey(); err == nil && len(key) != ed25519.PublicKeySize {
		t.Errorf("committed key has %d bytes", len(key))
	} else if err != nil && !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("unexpected error: %v", err)
	}
}

// The release workflow verifies with the same script before publishing.
func TestSignScriptVerifies(t *testing.T) {
	files, order, _ := packageRelease(t, "v0.2.0")
	signed, _, pub := signRelease(t, "v0.2.0", files, order)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "trivy-scanner_linux_amd64")
	_ = os.WriteFile(bin, signed["trivy-scanner_linux_amd64"], 0o755)
	_ = os.WriteFile(bin+".sig", signed["trivy-scanner_linux_amd64.sig"], 0o644)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	keyFile := filepath.Join(dir, "public.pem")
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
	run := func(version string) error {
		return exec.Command("bash", "../../scripts/sign-update.sh", "verify", bin, version, keyFile).Run()
	}
	if err := run("v0.2.0"); err != nil {
		t.Errorf("verify of the right version: %v", err)
	}
	if err := run("v0.3.0"); err == nil {
		t.Error("verify accepted another version")
	}
}

func TestInstallable(t *testing.T) {
	t.Setenv("APPIMAGE", "")
	dir := t.TempDir()
	if err := Installable(filepath.Join(dir, "trivy-scanner")); err != nil {
		t.Errorf("writable directory rejected: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".update-probe-*")); len(left) != 0 {
		t.Errorf("probe file left behind: %v", left)
	}
	err := Installable(filepath.Join(dir, "missing", "trivy-scanner"))
	if err == nil || !strings.Contains(err.Error(), "package manager") {
		t.Errorf("unwritable location should explain itself: %v", err)
	}

	// Inside an AppImage the updater replaces the .AppImage file, so its directory is what counts.
	other := t.TempDir()
	t.Setenv("APPIMAGE", filepath.Join(other, "Trivy.AppImage"))
	if err := Installable("/usr/bin/trivy-scanner"); err != nil {
		t.Errorf("AppImage in a writable directory rejected: %v", err)
	}

	if os.Geteuid() != 0 { // root ignores directory permissions
		t.Setenv("APPIMAGE", "")
		ro := t.TempDir()
		if err := os.Chmod(ro, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
		if err := Installable(filepath.Join(ro, "trivy-scanner")); err == nil {
			t.Error("read-only directory accepted")
		}
	}
}
