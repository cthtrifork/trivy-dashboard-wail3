package trivy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/caarlos0/env/v11"
)

// DefaultTrivyImage is the Trivy image scans run with unless the user picks another version. The
// renovate comment on the line above keeps the tag current (the custom manager in
// .github/renovate.json5).
// renovate: datasource=docker depName=docker.io/aquasec/trivy
const DefaultTrivyImage = "docker.io/aquasec/trivy:0.76.1"

// DefaultDBRepository is the vulnerability DB Trivy downloads, unless TRIVY_DB_REPOSITORY names a
// mirror. The tag is the DB schema version, so it is a floating tag that rarely changes; Renovate
// still tracks it so a schema bump shows up as a PR.
// renovate: datasource=docker depName=ghcr.io/aquasecurity/trivy-db
const DefaultDBRepository = "ghcr.io/aquasecurity/trivy-db:2"

// ResolveTrivyImage turns the "Trivy version" setting into an image reference: empty means
// DefaultTrivyImage, a version ("0.77.0", "v0.77.0") means that tag of the same repository. Anything
// with a registry, path, tag or digest separator is an image reference and is refused.
func ResolveTrivyImage(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return DefaultTrivyImage, nil
	}
	if _, err := version.Parse(strings.TrimPrefix(v, "v")); err != nil || strings.ContainsAny(v, "/:@") {
		return "", fmt.Errorf("%q is not a valid Trivy version", v)
	}
	repo, _, _ := strings.Cut(DefaultTrivyImage, ":")
	return repo + ":" + strings.TrimPrefix(v, "v"), nil
}

const (
	// cacheMount is where the Trivy cache sits inside the scanner container. It is passed to
	// Trivy as --cache-dir so the location never depends on the image's HOME.
	cacheMount = "/root/.cache/trivy"
	// The ignore policy and ignore file travel into the scanner container as environment
	// variables; the container writes them to these paths for Trivy's --ignore-policy and
	// --ignorefile.
	ignorePolicyEnv  = "SCANNER_IGNORE_POLICY"
	ignorePolicyPath = "/tmp/ignore.rego"
	ignoreFileEnv    = "SCANNER_IGNORE_FILE"
	ignoreFilePath   = "/tmp/ignorefile.yaml"
	// DefaultCacheSource is the podman named volume used when there is no better default: a
	// remote podman socket, or no user cache directory. A named volume lives wherever podman
	// itself runs, so it is right for any podman, local or remote.
	DefaultCacheSource = "trivy-cache"
	// CacheEnv overrides the cache source: a volume name, or an absolute directory on the host
	// that runs podman.
	CacheEnv = "TRIVY_SCANNER_CACHE"
)

// Env is the environment the engine reads. The desc and def tags document each variable for the
// help dialog (def is prose, not applied). The two DB mirrors are forwarded into the scanner
// container when set.
type Env struct {
	Cache            string `env:"TRIVY_SCANNER_CACHE" desc:"Trivy cache source: a podman volume name or an absolute directory on the podman host." def:"user cache dir, or volume trivy-cache with a remote podman or on Windows"`
	DBRepository     string `env:"TRIVY_DB_REPOSITORY" desc:"Trivy vulnerability DB mirror, forwarded into the scanner container when set." def:"Trivy default"`
	JavaDBRepository string `env:"TRIVY_JAVA_DB_REPOSITORY" desc:"Trivy Java DB mirror, forwarded into the scanner container when set." def:"Trivy default"`
	HTTPSProxy       string `env:"HTTPS_PROXY" desc:"HTTPS proxy, forwarded into the scanner container when set. A loopback proxy also puts the container on the host network." def:"none"`
	HTTPProxy        string `env:"HTTP_PROXY" desc:"HTTP proxy, forwarded into the scanner container when set." def:"none"`
	NoProxy          string `env:"NO_PROXY" desc:"Hosts that bypass the proxy, forwarded into the scanner container when set." def:"none"`
	CABundle         string `env:"TRIVY_SCANNER_CA_BUNDLE" desc:"PEM file with extra CA certificates (a TLS-inspecting proxy), mounted into the scanner container. An absolute path on the podman host." def:"none"`
	Podman           string `env:"PODMAN" desc:"Path of the podman binary." def:"podman"`
	ContainerHost    string `env:"CONTAINER_HOST" desc:"Remote podman socket. Switches the cache default to a named volume." def:"local podman"`
	DockerHost       string `env:"DOCKER_HOST" desc:"Same effect as CONTAINER_HOST." def:"local podman"`
}

// loadEnv reads the environment on each call so tests can change it with t.Setenv.
func loadEnv() Env {
	e, _ := env.ParseAs[Env]()
	return e
}

// TrivyJob is one `trivy image` invocation.
type TrivyJob struct {
	Image string // image reference to scan; empty for --download-db-only
	// TrivyImage is the Trivy version to run (see ResolveTrivyImage); empty means DefaultTrivyImage.
	TrivyImage string
	Flags      []string // e.g. --format json --scanners vuln
	Username   string   // optional registry credentials
	Password   string
	// IgnorePolicy is the source of a Rego ignore policy for `--ignore-policy`; empty means none.
	IgnorePolicy string
	// IgnoreFile is the source of a .trivyignore.yaml for `--ignorefile`; empty means none.
	IgnoreFile string
	// CleanDB runs `trivy clean --vuln-db` (deletes the cached vulnerability DB) instead of a scan.
	CleanDB bool
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
	// defaultCache().
	Cache string
}

// CacheSource is the Trivy cache source the engine mounts by default: a podman volume name or an
// absolute host directory. An invalid $TRIVY_SCANNER_CACHE is reported as an error.
func CacheSource() (string, error) { return (&PodmanEngine{}).cacheSource() }

// cacheSource validates and returns the cache mount source.
func (p *PodmanEngine) cacheSource() (string, error) {
	src := p.Cache
	if src == "" {
		src = loadEnv().Cache
	}
	if src == "" {
		return defaultCache(), nil
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

// defaultCache is the cache source when nothing is configured. With a local podman it is a
// directory in the user's cache dir, so the Trivy DB is a plain, inspectable host directory that
// survives `podman system reset`. With a remote podman (including the containerised headless
// deployment) our own paths mean nothing to the podman host, so it is the named volume there.
func defaultCache() string {
	if remote() || runtime.GOOS == "windows" { // Windows paths need translating for the podman VM
		return DefaultCacheSource
	}
	dir, err := os.UserCacheDir()
	if err != nil || !filepath.IsAbs(dir) {
		return DefaultCacheSource
	}
	return filepath.Join(dir, "trivy-scanner", "trivy")
}

// proxyArgs forwards the proxy settings and an extra CA bundle into the scanner container, so the
// DB download and registry pulls work behind a (TLS-inspecting) proxy. The container's own
// loopback is not the host's, so a proxy on localhost needs the host network.
func proxyArgs(e Env) []string {
	var args []string
	for name, val := range map[string]string{"HTTPS_PROXY": e.HTTPSProxy, "HTTP_PROXY": e.HTTPProxy, "NO_PROXY": e.NoProxy} {
		if val != "" {
			args = append(args, "-e", name)
		}
	}
	slices.Sort(args) // map order is random; keep the command line stable
	if loopbackProxy(e.HTTPSProxy) || loopbackProxy(e.HTTPProxy) {
		args = append(args, "--network", "host")
	}
	if e.CABundle != "" {
		args = append(args, "-v", e.CABundle+":/etc/ssl/certs/ca-certificates.crt:ro")
	}
	return args
}

func loopbackProxy(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "::1" || strings.HasPrefix(h, "127.")
}

// PodmanBin is the podman binary a default engine runs: $PODMAN or "podman".
func PodmanBin() string { return (&PodmanEngine{}).bin() }

// Remote reports whether the podman client talks to another machine's podman.
func Remote() bool { return remote() }

// remote reports whether the podman client talks to another machine's podman, in which case a
// host path is not ours to create.
func remote() bool {
	e := loadEnv()
	return e.ContainerHost != "" || e.DockerHost != ""
}

// runArgs builds the `podman run` arguments for a job (credentials excluded: see RunTrivy).
func (p *PodmanEngine) runArgs(job TrivyJob, name string) ([]string, error) {
	src, err := p.cacheSource()
	if err != nil {
		return nil, err
	}
	image, err := ResolveTrivyImage(job.TrivyImage)
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
	// Let air-gapped and rate-limited setups point Trivy at a DB mirror.
	e := loadEnv()
	if e.DBRepository != "" {
		args = append(args, "-e", "TRIVY_DB_REPOSITORY")
	} else {
		args = append(args, "-e", "TRIVY_DB_REPOSITORY="+DefaultDBRepository)
	}
	if e.JavaDBRepository != "" {
		args = append(args, "-e", "TRIVY_JAVA_DB_REPOSITORY")
	}
	args = append(args, proxyArgs(e)...)
	// --skip-version-check: no "newer Trivy available" lookup; the version is pinned by us.
	// --vuln-severity-source redhat,auto prefers Red Hat severities, then the vendor default.
	// --disable-telemetry and --offline-scan keep Trivy from phoning home beyond the DB download.
	trivyArgs := []string{"image", "--cache-dir", cacheMount, "--skip-version-check", "--disable-telemetry", "--offline-scan", "--vuln-severity-source", "redhat,auto"}
	if job.CleanDB {
		trivyArgs = []string{"clean", "--vuln-db", "--cache-dir", cacheMount}
	}
	// The policy and ignore file travel as environment variables and are written to files inside
	// the container, so they work with a remote podman too (a bind mount would need the files on
	// the podman host). The wrapper replaces the image's entrypoint, hence "trivy" below.
	var script string
	for _, f := range []struct{ text, env, path, flag string }{
		{job.IgnorePolicy, ignorePolicyEnv, ignorePolicyPath, "--ignore-policy"},
		{job.IgnoreFile, ignoreFileEnv, ignoreFilePath, "--ignorefile"},
	} {
		if f.text == "" {
			continue
		}
		args = append(args, "-e", f.env)
		script += `printf '%s' "$` + f.env + `" > ` + f.path + ` && `
		trivyArgs = append(trivyArgs, f.flag, f.path)
	}
	if script != "" {
		args = append(args, "--entrypoint", "sh", image, "-c", script+`exec trivy "$@"`, "sh")
	} else {
		args = append(args, image)
	}
	args = append(args, trivyArgs...)
	args = append(args, job.Flags...)
	if job.Image != "" { // a DB-only job has no image
		args = append(args, job.Image)
	}
	return args, nil
}

func (p *PodmanEngine) bin() string {
	if p.Bin != "" {
		return p.Bin
	}
	if b := loadEnv().Podman; b != "" {
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
	if job.IgnorePolicy != "" {
		env = append(env, ignorePolicyEnv+"="+job.IgnorePolicy)
	}
	if job.IgnoreFile != "" {
		env = append(env, ignoreFileEnv+"="+job.IgnoreFile)
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
