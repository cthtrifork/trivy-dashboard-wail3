package trivy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// TrivyImage is the container image used to run the scanner.
const TrivyImage = "docker.io/aquasec/trivy:latest"

// TrivyJob is one `trivy image` invocation.
type TrivyJob struct {
	Image    string   // image reference to scan
	Flags    []string // e.g. --format json --scanners vuln
	Username string   // optional registry credentials
	Password string
}

// Engine is whatever actually runs Trivy and talks to registries.
// PodmanEngine is the real implementation; dev builds can also use a
// FixtureEngine that replays recorded scans (see fixture_engine.go).
type Engine interface {
	// Version reports the engine's version string.
	Version(ctx context.Context) (string, error)
	// RunTrivy runs the job and returns its stdout. Progress lines go to log.
	RunTrivy(ctx context.Context, job TrivyJob, log func(string)) ([]byte, error)
	// ListTags returns the tags available for an image repository.
	ListTags(ctx context.Context, repo string) ([]string, error)
}

// PodmanEngine runs Trivy in a throwaway podman container.
type PodmanEngine struct {
	// Bin is the podman binary; defaults to $PODMAN or "podman".
	Bin string
}

func (p *PodmanEngine) bin() string {
	if p.Bin != "" {
		return p.Bin
	}
	if b := os.Getenv("PODMAN"); b != "" {
		return b
	}
	return "podman"
}

// Version runs `podman --version`.
func (p *PodmanEngine) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, p.bin(), "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("podman not available: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// RunTrivy runs `trivy image <flags> <image>` in a throwaway container and
// returns stdout. A named volume caches the vulnerability DB between runs.
// Credentials travel as environment variables, never on the command line.
func (p *PodmanEngine) RunTrivy(ctx context.Context, job TrivyJob, log func(string)) ([]byte, error) {
	// A name we chose lets us stop the container ourselves if the scan is cancelled.
	name := containerName()
	args := []string{"run", "--rm", "--name", name, "-v", "trivy-cache:/root/.cache/trivy"}
	env := os.Environ()
	if job.Username != "" {
		args = append(args, "-e", "TRIVY_USERNAME", "-e", "TRIVY_PASSWORD")
		env = append(env, "TRIVY_USERNAME="+job.Username, "TRIVY_PASSWORD="+job.Password)
	}
	args = append(args, TrivyImage, "image")
	args = append(args, job.Flags...)
	args = append(args, job.Image)

	cmd := exec.CommandContext(ctx, p.bin(), args...)
	cmd.Env = env
	// CommandContext would SIGKILL the podman client. That gives podman no chance to stop the
	// container, which would then keep running after the app has moved on (or quit). Stop the
	// container first, then ask the client to exit, and only kill it if it will not.
	cmd.Cancel = func() error { return p.stop(cmd, name) }
	cmd.WaitDelay = 3 * time.Second
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting podman: %w", err)
	}

	var tail []string
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		log(line)
		if tail = append(tail, line); len(tail) > 5 {
			tail = tail[1:]
		}
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("cancelled")
		}
		return nil, fmt.Errorf("%w: %s", err, strings.Join(tail, "\n"))
	}
	return stdout.Bytes(), nil
}

// containerName returns a unique, recognisable name for a scan container.
func containerName() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "trivy-scanner-" + hex.EncodeToString(b)
}

// stop removes the named container, then asks the podman client to exit. It is the
// cancellation path for RunTrivy, so it must never block for long: the removal is bounded.
func (p *PodmanEngine) stop(cmd *exec.Cmd, name string) error {
	rmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// --force kills a running container, --time 0 skips the stop grace period, --ignore
	// makes an already-gone container (the usual race with --rm) a no-op.
	_ = exec.CommandContext(rmCtx, p.bin(), "rm", "--force", "--ignore", "--time", "0", name).Run()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}

// ListTags runs `podman search --list-tags`.
func (p *PodmanEngine) ListTags(ctx context.Context, repo string) ([]string, error) {
	out, err := exec.CommandContext(ctx, p.bin(), "search", "--list-tags", "--limit", "1000", "--format", "{{.Tag}}", repo).Output()
	if err != nil {
		msg := err.Error()
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			msg = strings.TrimSpace(string(ee.Stderr))
		}
		return nil, fmt.Errorf("listing tags: %s", msg)
	}
	return strings.Fields(string(out)), nil
}
