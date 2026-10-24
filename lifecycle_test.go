package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cthtrifork/trivy-dashboard-wail3/internal/trivy"
)

// blockingEngine stands in for podman: RunTrivy blocks until its context is cancelled.
type blockingEngine struct {
	started chan struct{}
	ignore  time.Duration // when set, keep going this long after cancellation (a stuck podman)
}

func (e *blockingEngine) Version(context.Context) (string, error) { return "stub", nil }
func (e *blockingEngine) ListTags(context.Context, string) ([]string, error) {
	return nil, nil
}
func (e *blockingEngine) RunTrivy(ctx context.Context, _ trivy.TrivyJob, _ func(string)) ([]byte, error) {
	select {
	case e.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	time.Sleep(e.ignore)
	return nil, errors.New("cancelled")
}

func newTestService(e trivy.Engine) *ScanService {
	return &ScanService{scanner: &trivy.Scanner{Engine: e}, product: map[string]string{}}
}

// Wails cancels the application context when shutdown begins, so a scan started from a
// binding must stop with it. Before this, scans used context.Background() and outlived the app.
func TestScansStopWhenTheApplicationContextIsCancelled(t *testing.T) {
	e := &blockingEngine{started: make(chan struct{}, 4)}
	s := newTestService(e)
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx

	errc := make(chan error, 1)
	go func() { _, err := s.Scan(trivy.ScanRequest{Image: "nginx"}); errc <- err }()
	<-e.started
	cancel() // what Wails does first on quit

	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "cancelled") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the scan outlived the application context")
	}
}

func TestServiceShutdownStopsARunningScan(t *testing.T) {
	e := &blockingEngine{started: make(chan struct{}, 4)}
	s := newTestService(e) // no app context: the scan only ends because ServiceShutdown cancels it
	done := make(chan struct{})
	go func() { _, _ = s.Scan(trivy.ScanRequest{Image: "nginx"}); close(done) }()
	<-e.started

	start := time.Now()
	if err := s.ServiceShutdown(); err != nil {
		t.Fatalf("ServiceShutdown: %v", err)
	}
	if s.scanner.Running() {
		t.Error("a scan is still running after ServiceShutdown")
	}
	if took := time.Since(start); took > shutdownGrace {
		t.Errorf("shutdown took %v, over the %v budget", took, shutdownGrace)
	}
	<-done
}

func TestServiceShutdownWithNothingRunning(t *testing.T) {
	s := newTestService(&blockingEngine{})
	start := time.Now()
	if err := s.ServiceShutdown(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Errorf("idle shutdown took %v", took)
	}
}

// A scan that will not stop must be reported and must not hold up quitting.
func TestServiceShutdownDoesNotHangOnAStuckScan(t *testing.T) {
	old := shutdownGrace
	shutdownGrace = 30 * time.Millisecond
	t.Cleanup(func() { shutdownGrace = old })

	e := &blockingEngine{started: make(chan struct{}, 4), ignore: 400 * time.Millisecond}
	s := newTestService(e)
	done := make(chan struct{})
	go func() { _, _ = s.Scan(trivy.ScanRequest{Image: "nginx"}); close(done) }()
	<-e.started

	start := time.Now()
	err := s.ServiceShutdown()
	if err == nil || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("err = %v, want the stuck scan reported", err)
	}
	if took := time.Since(start); took > 300*time.Millisecond {
		t.Errorf("waited %v for a 30ms grace period", took)
	}
	<-done
}
