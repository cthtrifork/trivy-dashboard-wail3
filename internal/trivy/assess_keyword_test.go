package trivy

import "testing"

func TestKeywordOutcome(t *testing.T) {
	tests := []struct {
		name, text, want string
	}{
		{"no match", "a harmless cosmetic bug", ""},
		{"match at end of text", "leads to denial of service", "denial of service"},
		{"most severe wins", "may crash and allows code execution", "arbitrary code execution"},
		{"later rule", "reflected xss in the admin page", "script injection in users' browsers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keywordOutcome(tt.text); got != tt.want {
				t.Errorf("keywordOutcome(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}
