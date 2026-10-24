package trivy

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubPodman writes a podman stand-in that logs every call. `run` behaves like a long scan:
// it sleeps until it is signalled, and logs TERM like podman's signal proxy would see it.
func stubPodman(t *testing.T, runBody string) (bin, logPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stub")
	}
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\ncase \"$1\" in\n run) " + runBody + " ;;\nesac\n"
	bin = filepath.Join(dir, "podman")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, logPath
}

const blockingRun = `trap 'echo TERM >> "$0.term"; kill $S 2>/dev/null; exit 143' TERM; sleep 30 & S=$!; wait $S`

func readLog(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Cancelling a scan must stop its container, not just kill the client that started it.
func TestCancelStopsTheContainerThenTheClient(t *testing.T) {
	bin, logPath := stubPodman(t, blockingRun)
	s := &Scanner{Podman: bin}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := s.Scan(ctx, ScanRequest{Image: "nginx:1.27"}); errc <- err }()

	waitFor(t, "the scan container to start", func() bool { return strings.Contains(readLog(logPath), "run --rm --name ") })
	start := time.Now()
	cancel()

	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "cancelled") {
			t.Fatalf("err = %v, want a cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the scan did not stop after being cancelled")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("cancelling took %v; shutdown has to be fast", took)
	}

	log := readLog(logPath)
	var name string
	for _, f := range strings.Fields(log) {
		if strings.HasPrefix(f, "trivy-scanner-") {
			name = f
			break
		}
	}
	if name == "" {
		t.Fatalf("the container was not given a name we could stop it by:\n%s", log)
	}
	if want := "rm --force --ignore --time 0 " + name; !strings.Contains(log, want) {
		t.Errorf("expected %q in the podman calls:\n%s", want, log)
	}
	// The client is asked to exit (SIGTERM, which podman proxies to the container), not SIGKILLed.
	waitFor(t, "the podman client to receive SIGTERM", func() bool {
		b, _ := os.ReadFile(bin + ".term")
		return strings.Contains(string(b), "TERM")
	})
}

func TestEveryContainerGetsItsOwnName(t *testing.T) {
	bin, logPath := stubPodman(t, `echo '{}'`)
	s := &Scanner{Podman: bin}
	for i := 0; i < 2; i++ {
		if _, err := s.Scan(context.Background(), ScanRequest{Image: "nginx"}); err != nil {
			t.Fatal(err)
		}
	}
	names := map[string]bool{}
	for _, line := range strings.Split(readLog(logPath), "\n") {
		if !strings.HasPrefix(line, "run ") {
			continue
		}
		f := strings.Fields(line)
		for i, w := range f {
			if w == "--name" {
				names[f[i+1]] = true
			}
		}
	}
	if len(names) != 4 { // two scans x (vulnerability report + SBOM)
		t.Errorf("want 4 distinct container names, got %v", names)
	}
}

// slowEngine ignores its context for a while, like a stuck podman.
type slowEngine struct {
	Engine
	hold    time.Duration
	started chan struct{}
	once    sync.Once
}

func (e *slowEngine) RunTrivy(_ context.Context, _ TrivyJob, _ func(string)) ([]byte, error) {
	e.once.Do(func() { close(e.started) }) // Scan calls the engine twice: report, then SBOM
	time.Sleep(e.hold)
	return []byte(`{}`), nil
}

func TestCancelAndWait(t *testing.T) {
	t.Run("idle returns at once", func(t *testing.T) {
		s := &Scanner{}
		if !s.CancelAndWait(time.Hour) || s.Running() {
			t.Fatal("an idle scanner should report done immediately")
		}
	})

	t.Run("waits for a job that cleans up promptly", func(t *testing.T) {
		bin, logPath := stubPodman(t, blockingRun)
		s := &Scanner{Podman: bin}
		go func() { _, _ = s.Scan(context.Background(), ScanRequest{Image: "nginx"}) }()
		waitFor(t, "the scan to start", func() bool { return strings.Contains(readLog(logPath), "run --rm") })
		if !s.Running() {
			t.Fatal("Running() should be true during a scan")
		}
		start := time.Now()
		if !s.CancelAndWait(5 * time.Second) {
			t.Fatal("the job did not finish within the grace period")
		}
		if s.Running() {
			t.Error("still running after CancelAndWait returned true")
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("took %v", took)
		}
	})

	t.Run("gives up after the grace period instead of hanging shutdown", func(t *testing.T) {
		e := &slowEngine{hold: 400 * time.Millisecond, started: make(chan struct{})}
		s := &Scanner{Engine: e}
		finished := make(chan struct{})
		go func() { _, _ = s.Scan(context.Background(), ScanRequest{Image: "nginx"}); close(finished) }()
		<-e.started
		start := time.Now()
		if s.CancelAndWait(30 * time.Millisecond) {
			t.Fatal("reported done while the engine was still stuck")
		}
		if took := time.Since(start); took > 300*time.Millisecond {
			t.Errorf("waited %v for a 30ms grace period", took)
		}
		<-finished // let the goroutine end before the test returns
	})
}
