//go:build !production

package trivy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// recEngine replays recordings and remembers every job it was given.
type recEngine struct {
	*FixtureEngine
	mu     sync.Mutex
	jobs   []TrivyJob
	dbFail bool
}

func (r *recEngine) RunTrivy(ctx context.Context, job TrivyJob, log func(string)) ([]byte, error) {
	r.mu.Lock()
	r.jobs = append(r.jobs, job)
	r.mu.Unlock()
	if r.dbFail && slices.Contains(job.Flags, "--download-db-only") {
		return nil, errors.New("offline")
	}
	return r.FixtureEngine.RunTrivy(ctx, job, log)
}

func (r *recEngine) dbJobs() (n int) {
	for _, j := range r.jobs {
		if slices.Contains(j.Flags, "--download-db-only") {
			n++
		}
	}
	return n
}

func newRec(t *testing.T) (*recEngine, *Scanner) {
	e := NewFixtureEngine()
	e.Delay = 0
	r := &recEngine{FixtureEngine: e}
	return r, &Scanner{Engine: r}
}

func TestDBCheckedOncePerSessionAndScansSkipUpdate(t *testing.T) {
	r, s := newRec(t)
	for i := 0; i < 2; i++ {
		if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13"}); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.dbJobs(); n != 1 {
		t.Errorf("db checks = %d, want 1 for two scans", n)
	}
	for _, j := range r.jobs {
		if slices.Contains(j.Flags, "--download-db-only") {
			if j.Image != "" || j.Username != "" {
				t.Errorf("db job must have no image or credentials: %+v", j)
			}
			continue
		}
		if !slices.Contains(j.Flags, "--skip-db-update") {
			t.Errorf("scan did not skip the DB update: %v", j.Flags)
		}
	}
}

func TestCompareChecksDBOnce(t *testing.T) {
	r, s := newRec(t)
	if _, err := s.Compare(context.Background(), CompareRequest{Repo: "traefik", TagA: "3.7.13", TagB: "3.7.16"}); err != nil {
		t.Fatal(err)
	}
	if n := r.dbJobs(); n != 1 {
		t.Errorf("db checks = %d, want 1 for a comparison", n)
	}
}

func TestOfflineDBRefreshFallsBackToCache(t *testing.T) {
	r, s := newRec(t)
	r.dbFail = true
	var logs []string
	s.Log = func(l string) { logs = append(logs, l) }
	if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13"}); err != nil {
		t.Fatalf("scan must go on with the cached DB: %v", err)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "cached copy") {
		t.Errorf("no warning logged: %v", logs)
	}
	// A failed check is retried on the next scan.
	if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13"}); err != nil {
		t.Fatal(err)
	}
	if n := r.dbJobs(); n != 2 {
		t.Errorf("db checks = %d, want a retry after failure", n)
	}
}

func TestCancelledDBCheckStopsTheScan(t *testing.T) {
	_, s := newRec(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.ensureDB(ctx, "", func(string) {}); err == nil {
		// the fixture engine ignores cancellation for DB jobs, so only a failing engine proves it
		r := &recEngine{FixtureEngine: NewFixtureEngine(), dbFail: true}
		if err := (&Scanner{Engine: r}).ensureDB(ctx, "", func(string) {}); err == nil {
			t.Error("a cancelled context must stop the scan")
		}
	}
}

func TestRunArgsDBOnlyJobAndMirrorEnv(t *testing.T) {
	t.Setenv("TRIVY_DB_REPOSITORY", "mirror.example/trivy-db")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "")
	args, err := (&PodmanEngine{Cache: "my-cache"}).runArgs(TrivyJob{Flags: []string{"--download-db-only"}}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if args[len(args)-1] != "--download-db-only" {
		t.Errorf("an empty image must not become an argument: %v", args)
	}
	if !slices.Contains(args, "--skip-version-check") {
		t.Errorf("Trivy's version check must be off: %v", args)
	}
	if !slices.Contains(args, "TRIVY_DB_REPOSITORY") || slices.Contains(args, "TRIVY_JAVA_DB_REPOSITORY") {
		t.Errorf("only set mirror variables are forwarded: %v", args)
	}
	if strings.Contains(strings.Join(args, " "), "mirror.example") {
		t.Error("values travel in the environment, not argv")
	}
}

func TestChangingTrivyVersionDoesNotRecheckDBAndIsUsedByEveryJob(t *testing.T) {
	r, s := newRec(t)
	for _, v := range []string{"", "", "0.99.0"} {
		if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13", TrivyImage: v}); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.dbJobs(); n != 1 {
		t.Errorf("db checks = %d, want 1 (a new version does not check again)", n)
	}
	last := r.jobs[len(r.jobs)-1]
	if last.TrivyImage != "0.99.0" {
		t.Errorf("last job used %q", last.TrivyImage)
	}
	if first := r.jobs[0]; first.TrivyImage != "" {
		t.Errorf("default jobs must leave the version empty, got %q", first.TrivyImage)
	}
}

func TestCompareForwardsTrivyImage(t *testing.T) {
	r, s := newRec(t)
	if _, err := s.Compare(context.Background(), CompareRequest{Repo: "traefik", TagA: "3.7.13", TagB: "3.7.16", TrivyImage: "v0.99.0"}); err != nil {
		t.Fatal(err)
	}
	for _, j := range r.jobs {
		if j.TrivyImage != "v0.99.0" {
			t.Errorf("job %v used %q", j.Flags, j.TrivyImage)
		}
	}
}

func TestInvalidTrivyImageIsRejectedBeforeAnyJob(t *testing.T) {
	r, s := newRec(t)
	if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13", TrivyImage: "--privileged"}); err == nil {
		t.Fatal("want an error")
	}
	if len(r.jobs) != 0 {
		t.Errorf("jobs ran: %v", r.jobs)
	}
}

// failEngine fails every scan job the way Trivy does with an empty cache; a DB job fails with
// the real cause.
type failEngine struct{ *FixtureEngine }

func (failEngine) RunTrivy(_ context.Context, job TrivyJob, _ func(string)) ([]byte, error) {
	if slices.Contains(job.Flags, "--download-db-only") {
		return nil, errors.New("pulling trivy-db: connection refused")
	}
	return nil, errors.New("--skip-db-update cannot be specified on the first run")
}

func TestScanFailureNamesTheDBDownloadError(t *testing.T) {
	s := &Scanner{Engine: failEngine{NewFixtureEngine()}}
	_, err := s.Scan(context.Background(), ScanRequest{Image: "alpine:3"})
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("the download error must reach the user, got: %v", err)
	}
}

func TestRunArgsProxyAndCABundle(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("NO_PROXY", "corp.example")
	t.Setenv("TRIVY_SCANNER_CA_BUNDLE", "/etc/ca.pem")
	args, err := (&PodmanEngine{Cache: "my-cache"}).runArgs(TrivyJob{Image: "x"}, "n")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"HTTPS_PROXY", "NO_PROXY", "host", "/etc/ca.pem:/etc/ssl/certs/ca-certificates.crt:ro"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
	if slices.Contains(args, "HTTP_PROXY") || strings.Contains(strings.Join(args, " "), "3128") {
		t.Errorf("unset variables are not forwarded and values stay out of argv: %v", args)
	}

	t.Setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
	args, _ = (&PodmanEngine{Cache: "my-cache"}).runArgs(TrivyJob{Image: "x"}, "n")
	if slices.Contains(args, "host") {
		t.Errorf("a remote proxy does not need the host network: %v", args)
	}
}

func TestIgnorePolicyAndFileOnlyFilterTheVulnerabilityScan(t *testing.T) {
	r, s := newRec(t)
	const policy = "package trivy\n\nignore if input.PkgName == \"x\"\n"
	const file = "vulnerabilities:\n  - id: CVE-1\n"
	if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13", IgnorePolicy: policy, IgnoreFile: file}); err != nil {
		t.Fatal(err)
	}
	for _, j := range r.jobs {
		vuln := slices.Contains(j.Flags, "json")
		if vuln != (j.IgnorePolicy == policy) || vuln != (j.IgnoreFile == file) || (!vuln && (j.IgnorePolicy != "" || j.IgnoreFile != "")) {
			t.Errorf("job %v has policy %q and file %q", j.Flags, j.IgnorePolicy, j.IgnoreFile)
		}
	}
	for _, bad := range []string{strings.Repeat("a", maxIgnoreText+1), "a\x00b"} {
		if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13", IgnorePolicy: bad}); err == nil {
			t.Errorf("policy of %d bytes accepted", len(bad))
		}
		if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13", IgnoreFile: bad}); err == nil {
			t.Errorf("ignore file of %d bytes accepted", len(bad))
		}
	}
}

func TestScanRejectsInvalidIgnoreTextBeforeRunningTrivy(t *testing.T) {
	r, s := newRec(t)
	for _, req := range []ScanRequest{
		{Image: "traefik:3.7.13", IgnorePolicy: "package main\n"},
		{Image: "traefik:3.7.13", IgnoreFile: "CVE-1\n"},
	} {
		if _, err := s.Scan(context.Background(), req); err == nil {
			t.Errorf("%+v accepted", req)
		}
	}
	if len(r.jobs) != 0 {
		t.Errorf("trivy ran %d jobs for invalid input", len(r.jobs))
	}
}

func TestUpdateDBCleansThenDownloadsAndTheNextScanDoesNotCheckAgain(t *testing.T) {
	r, s := newRec(t)
	if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13"}); err != nil {
		t.Fatal(err)
	}
	r.jobs = nil
	if err := s.UpdateDB(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if len(r.jobs) != 2 || !r.jobs[0].CleanDB || !slices.Contains(r.jobs[1].Flags, "--download-db-only") {
		t.Fatalf("want a clean job then a download, got %+v", r.jobs)
	}
	r.jobs = nil
	if _, err := s.Scan(context.Background(), ScanRequest{Image: "traefik:3.7.13"}); err != nil {
		t.Fatal(err)
	}
	if n := r.dbJobs(); n != 0 {
		t.Errorf("db checks = %d after an update, want 0", n)
	}
	if err := s.UpdateDB(context.Background(), "--privileged"); err == nil {
		t.Error("an invalid version must be refused")
	}
}

func TestRunArgsPassTheDBRepository(t *testing.T) {
	line := func() string {
		args, err := (&PodmanEngine{Cache: "c"}).runArgs(TrivyJob{Image: "x"}, "n")
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(args, " ")
	}
	if got := line(); !strings.Contains(got, "-e TRIVY_DB_REPOSITORY="+DefaultDBRepository) {
		t.Errorf("default DB repository missing: %s", got)
	}
	t.Setenv("TRIVY_DB_REPOSITORY", "mirror.example/db:2")
	if got := line(); strings.Contains(got, DefaultDBRepository) || !strings.Contains(got, "-e TRIVY_DB_REPOSITORY ") {
		t.Errorf("the user's mirror must be forwarded from the environment: %s", got)
	}
	args, _ := (&PodmanEngine{Cache: "c"}).runArgs(TrivyJob{CleanDB: true}, "n")
	if got := strings.Join(args, " "); !strings.Contains(got, "clean --vuln-db --cache-dir") || strings.Contains(got, " image ") {
		t.Errorf("clean job args: %s", got)
	}
}
