package trivy

import (
	"os"
	"strings"

	"github.com/distribution/reference"
)

// githubRegistry is the only registry a GITHUB_TOKEN is ever sent to: a GitHub token must not
// leak to an arbitrary registry the user happens to scan.
const githubRegistry = "ghcr.io"

// GithubLogin returns the registry login taken from the environment: GITHUB_TOKEN plus a
// username (GITHUB_ACTOR, GITHUB_USER, else "github"; ghcr.io accepts any name with a token).
// ok is false when no token is set. The token never reaches the UI, only the Go side holds it.
func GithubLogin() (user, token string, ok bool) {
	token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return "", "", false
	}
	for _, k := range []string{"GITHUB_ACTOR", "GITHUB_USER"} {
		if user = strings.TrimSpace(os.Getenv(k)); user != "" {
			return user, token, true
		}
	}
	return "github", token, true
}

// withDefaultCredentials fills an empty password from GITHUB_TOKEN when image lives on ghcr.io.
// Credentials the user typed are never replaced.
func withDefaultCredentials(image, username, password string) (string, string) {
	if password != "" {
		return username, password
	}
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil || reference.Domain(named) != githubRegistry {
		return username, password
	}
	user, token, ok := GithubLogin()
	if !ok {
		return username, password
	}
	if username == "" {
		username = user
	}
	return username, token
}
