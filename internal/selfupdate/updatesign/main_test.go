package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	bin, sig := filepath.Join(dir, "bin"), filepath.Join(dir, "bin.sig")
	if err := os.WriteFile(bin, []byte("binary bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Make a key pair the way keygen does and use its halves.
	out := captureStdout(t, func() {
		if err := run([]string{"keygen"}, ""); err != nil {
			t.Fatal(err)
		}
	})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	priv, pub := lines[1], lines[3]

	if err := run([]string{"sign", bin, sig}, priv); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", bin, sig, pub}, ""); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := os.WriteFile(bin, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", bin, sig, pub}, ""); err == nil {
		t.Error("a modified binary verified")
	}
	if err := run([]string{"sign", bin, sig}, "bad"); err == nil {
		t.Error("signed with a bad key")
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	return string(buf[:n])
}
