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
	if err := s.ensureDB(ctx, func(string) {}); err == nil {
		// the fixture engine ignores cancellation for DB jobs, so only a failing engine proves it
		r := &recEngine{FixtureEngine: NewFixtureEngine(), dbFail: true}
		if err := (&Scanner{Engine: r}).ensureDB(ctx, func(string) {}); err == nil {
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
	if !slices.Contains(args, "TRIVY_DB_REPOSITORY") || slices.Contains(args, "TRIVY_JAVA_DB_REPOSITORY") {
		t.Errorf("only set mirror variables are forwarded: %v", args)
	}
	if strings.Contains(strings.Join(args, " "), "mirror.example") {
		t.Error("values travel in the environment, not argv")
	}
}
