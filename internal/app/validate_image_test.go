package app

import "testing"

func TestValidateImage(t *testing.T) {
	var s ScanService
	digest := "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, ref := range []string{
		"", "  ", "nginx", "nginx:1.27", "docker.io/library/nginx:1.27", "localhost:5000/app:dev",
		"nginx" + digest, "nginx:1.27" + digest, "docker://nginx:1.27", "  ghcr.io/acme/api:2.4.1 ",
	} {
		if got := s.ValidateImage(ref); got != "" {
			t.Errorf("ValidateImage(%q) = %q, want valid", ref, got)
		}
	}
	for _, ref := range []string{
		"Nginx", "docker.io/Library/nginx", "nginx:", "nginx@", "nginx@sha256:abc", "nginx:-bad",
		"nginx latest", ":1.27", "-flag", "--rm", "a___b",
	} {
		if got := s.ValidateImage(ref); got == "" {
			t.Errorf("ValidateImage(%q) = valid, want a reason", ref)
		}
	}
}
