// Command updatesign is the release-side half of the updater's signature check: it makes the
// Ed25519 key pair, signs a release binary and verifies a signature. The signature is over the
// raw SHA-256 digest of the file, base64-encoded, and is what the updater checks (see
// internal/selfupdate/signature.go).
//
//	updatesign keygen                     prints the private key (a secret) and the public key
//	updatesign sign <binary> <out.sig>    reads the private key from $UPDATE_SIGNING_KEY
//	updatesign verify <binary> <sig> <pub>  <pub> is a base64 key or a file in update-key.pub format
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Getenv("UPDATE_SIGNING_KEY")); err != nil {
		fmt.Fprintln(os.Stderr, "updatesign:", err)
		os.Exit(1)
	}
}

func run(args []string, signingKey string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: updatesign keygen | sign <binary> <out.sig> | verify <binary> <sig> <public-key>")
	}
	switch args[0] {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		fmt.Println("private key (keep secret; the RELEASE_UPDATE_SIGNING_KEY repository secret):")
		fmt.Println(base64.StdEncoding.EncodeToString(priv.Seed()))
		fmt.Println("public key (the line in internal/selfupdate/update-key.pub):")
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return nil
	case "sign":
		if len(args) != 3 {
			return fmt.Errorf("usage: updatesign sign <binary> <out.sig>")
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signingKey))
		if err != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("$UPDATE_SIGNING_KEY is not a base64 Ed25519 seed (32 bytes)")
		}
		digest, err := digestOf(args[1])
		if err != nil {
			return err
		}
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), digest)
		return os.WriteFile(args[2], []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
	case "verify":
		if len(args) != 4 {
			return fmt.Errorf("usage: updatesign verify <binary> <sig> <public-key>")
		}
		return verify(args[1], args[2], args[3])
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func digestOf(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

func verify(binary, sigPath, pubArg string) error {
	pubText := pubArg
	if b, err := os.ReadFile(pubArg); err == nil {
		pubText = string(b)
	}
	var pub []byte
	for _, line := range strings.Split(pubText, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			pub, _ = base64.StdEncoding.DecodeString(line)
			break
		}
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("no base64 Ed25519 public key found in %q", pubArg)
	}
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("%s is not base64: %w", sigPath, err)
	}
	digest, err := digestOf(binary)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest, sig) {
		return fmt.Errorf("signature of %s does not verify", binary)
	}
	fmt.Println("signature ok:", binary)
	return nil
}
