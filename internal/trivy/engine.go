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
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// TrivyImage is the container image used to run the scanner.
const TrivyImage = "docker.io/aquasec/trivy:latest"

const (
	// cacheMount is where the Trivy cache sits inside the scanner container. It is passed to
	// Trivy as --cache-dir so the location never depends on the image's HOME.
	cacheMount = "/root/.cache/trivy"
	// DefaultCacheSource is the podman named volume used unless TRIVY_SCANNER_CACHE says otherwise.
	// A named volume lives wherever podman itself runs, so it works with a local podman, a podman
	// machine VM, and a remote podman socket alike.
	DefaultCacheSource = "trivy-cache"
	// CacheEnv overrides the cache source: a volume name, or an absolute directory on the host
	// that runs podman.
	CacheEnv = "TRIVY_SCANNER_CACHE"
)

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
	// Cache is the Trivy cache source mounted into the scanner: a podman volume name or an
	// absolute directory on the machine running podman. Defaults to $TRIVY_SCANNER_CACHE, then
	// DefaultCacheSource.
	Cache string
}

// cacheSource validates and returns the cache mount source.
func (p *PodmanEngine) cacheSource() (string, error) {
	src := p.Cache
	if src == "" {
		src = os.Getenv(CacheEnv)
	}
	if src == "" {
		return DefaultCacheSource, nil
	}
	// podman reads "-v a:b" as a volume when a has no slash, and as a host path when it starts
	// with one. Anything in between ("./cache") would silently become a volume, so refuse it.
	if strings.ContainsAny(src, "/\\") && !filepath.IsAbs(src) {
		return "", fmt.Errorf("%s=%q: use a volume name or an absolute path", CacheEnv, src)
	}
	if strings.ContainsRune(src, ':') && !filepath.IsAbs(src) {
		return "", fmt.Errorf("%s=%q: ':' is not allowed in a volume name", CacheEnv, src)
	}
	return src, nil
}

// remote reports whether the podman client talks to another machine's podman, in which case a
// host path is not ours to create.
func remote() bool {
	return os.Getenv("CONTAINER_HOST") != "" || os.Getenv("DOCKER_HOST") != ""
}

// runArgs builds the `podman run` arguments for a job (credentials excluded: see RunTrivy).
func (p *PodmanEngine) runArgs(job TrivyJob, name string) ([]string, error) {
	src, err := p.cacheSource()
	if err != nil {
		return nil, err
	}
	args := []string{"run", "--rm", "--name", name}
	if filepath.IsAbs(src) {
		// A host directory: make it when podman is local, and keep SELinux from blocking access
		// to a directory we do not own the labels of.
		if !remote() {
			if err := os.MkdirAll(src, 0o755); err != nil {
				return nil, fmt.Errorf("creating cache directory: %w", err)
			}
		}
		args = append(args, "--security-opt", "label=disable")
	}
	args = append(args, "-v", src+":"+cacheMount)
	if job.Username != "" {
		args = append(args, "-e", "TRIVY_USERNAME", "-e", "TRIVY_PASSWORD")
	}
	args = append(args, TrivyImage, "image", "--cache-dir", cacheMount)
	args = append(args, job.Flags...)
	return append(args, job.Image), nil
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
// returns stdout. The Trivy cache (vulnerability DB) is mounted from a volume or host directory
// and selected with --cache-dir, so it survives between runs.
// Credentials travel as environment variables, never on the command line.
func (p *PodmanEngine) RunTrivy(ctx context.Context, job TrivyJob, log func(string)) ([]byte, error) {
	// A name we chose lets us stop the container ourselves if the scan is cancelled.
	name := containerName()
	args, err := p.runArgs(job, name)
	if err != nil {
		return nil, err
	}
	env := os.Environ()
	if job.Username != "" {
		env = append(env, "TRIVY_USERNAME="+job.Username, "TRIVY_PASSWORD="+job.Password)
	}

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
