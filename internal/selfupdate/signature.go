package selfupdate

import (
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// signingKeyPEM is the Ed25519 public key release binaries are signed with. It is compiled into the
// app so that the release feed has no say in who is trusted: someone who can publish to the
// repository can publish a binary and a matching SHA256SUMS, but not a signature this key accepts.
// Releasing sets it up once, see docs/releasing.md.
//
//go:embed update-signing-key.pub
var signingKeyPEM []byte

// ErrNoSigningKey means the build has no (valid) update signing key, so it cannot trust any release.
var ErrNoSigningKey = errors.New("this build has no update signing key, so it cannot verify releases (see docs/releasing.md)")

// SigningKey returns the key compiled into the app.
func SigningKey() (ed25519.PublicKey, error) { return ParsePublicKey(signingKeyPEM) }

// ParsePublicKey reads a PEM encoded Ed25519 public key (`openssl pkey -pubout`). Lines that are not part
// of the PEM block, such as the placeholder comment in a repository that has no key yet, are ignored.
func ParsePublicKey(pemData []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrNoSigningKey
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoSigningKey, err)
	}
	key, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: the key is %T, not Ed25519", ErrNoSigningKey, pub)
	}
	return key, nil
}

// Statement is the text the release signs for one binary. It names the version and the asset as well as the
// digest, so a validly signed old binary cannot be passed off as a newer release or under another name.
// scripts/sign-update.sh builds the same text; the test runs the script against this function.
func Statement(version, asset string, sha256 []byte) []byte {
	return []byte(fmt.Sprintf("trivy-scanner release\nversion: %s\nasset: %s\nsha256: %s\n",
		strings.TrimPrefix(version, "v"), asset, hex.EncodeToString(sha256)))
}

// VerifyRelease checks sig, the detached signature published next to a binary, over its Statement.
func VerifyRelease(key ed25519.PublicKey, version, asset string, sha256, sig []byte) error {
	if len(key) != ed25519.PublicKeySize {
		return ErrNoSigningKey
	}
	if len(sha256) == 0 {
		return ErrUnverified
	}
	if !ed25519.Verify(key, Statement(version, asset, sha256), sig) {
		return fmt.Errorf("the signature of %s %s does not match the update signing key", asset, version)
	}
	return nil
}
