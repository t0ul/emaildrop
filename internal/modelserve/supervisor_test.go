package modelserve_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/internal/modelserve"
)

func TestWaitHealthyBecomesReady(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sup := &modelserve.Supervisor{
		Servers: []modelserve.Server{{Name: "planner", HealthURL: srv.URL + "/health"}},
		Stdout:  io.Discard,
	}
	if err := sup.WaitHealthy(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("expected server to become healthy, got %v", err)
	}
}

func TestWaitHealthyTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	sup := &modelserve.Supervisor{
		Servers: []modelserve.Server{{Name: "coder", HealthURL: srv.URL + "/health"}},
		Stdout:  io.Discard,
	}
	err := sup.WaitHealthy(context.Background(), 1*time.Second)
	if err == nil || !strings.Contains(err.Error(), "not healthy") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestStartAndShutdownTerminatesProcess(t *testing.T) {
	// A long sleep stands in for a model server; Shutdown must kill it promptly
	// rather than waiting for it to exit on its own.
	sup := &modelserve.Supervisor{
		Servers: []modelserve.Server{{Name: "sleeper", Bin: "sleep", Args: []string{"30"}}},
		Stdout:  io.Discard,
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	start := time.Now()
	sup.Shutdown()
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Shutdown took %s; did not terminate the child promptly", elapsed)
	}
}

func TestStartFailureReturnsError(t *testing.T) {
	sup := &modelserve.Supervisor{
		Servers: []modelserve.Server{{Name: "missing", Bin: "/nonexistent/llama-xyz", Args: []string{"serve"}}},
		Stdout:  io.Discard,
	}
	if err := sup.Start(context.Background()); err == nil {
		t.Fatal("expected error starting a nonexistent binary")
	}
}

func TestStartRefusesAlreadyServingPort(t *testing.T) {
	// A live endpoint stands in for a stale instance already holding the port.
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer live.Close()

	sup := &modelserve.Supervisor{
		Servers: []modelserve.Server{{Name: "planner", Bin: "sleep", Args: []string{"30"}, HealthURL: live.URL + "/health"}},
		Stdout:  io.Discard,
	}
	err := sup.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already serving") {
		sup.Shutdown()
		t.Fatalf("expected already-serving refusal, got %v", err)
	}
}

func TestWaitHealthyAbortsOnEarlyDeath(t *testing.T) {
	// The child exits immediately; its health endpoint never comes up. WaitHealthy
	// must return the death rather than spin until timeout.
	sup := &modelserve.Supervisor{
		Servers: []modelserve.Server{{Name: "crash", Bin: "false", HealthURL: "http://127.0.0.1:1/health"}},
		Stdout:  io.Discard,
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sup.Shutdown()
	err := sup.WaitHealthy(context.Background(), 10*time.Second)
	if err == nil || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("expected early-death error, got %v", err)
	}
}

func TestReadyProbeOverridesHealth(t *testing.T) {
	var calls int32
	sup := &modelserve.Supervisor{
		Servers: []modelserve.Server{{
			Name:      "planner",
			HealthURL: "http://127.0.0.1:1/health", // would never pass; Ready must win
			Ready: func(context.Context) bool {
				return atomic.AddInt32(&calls, 1) >= 3 // not ready until the 3rd poll
			},
		}},
		Stdout: io.Discard,
	}
	if err := sup.WaitHealthy(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("Ready probe should gate readiness, got %v", err)
	}
	if atomic.LoadInt32(&calls) < 3 {
		t.Fatalf("Ready probe polled %d times, expected to wait for generation", calls)
	}
}

func TestEmptyHealthURLSkips(t *testing.T) {
	sup := &modelserve.Supervisor{
		Servers: []modelserve.Server{{Name: "nohealth", HealthURL: ""}},
		Stdout:  io.Discard,
	}
	if err := sup.WaitHealthy(context.Background(), time.Second); err != nil {
		t.Fatalf("empty HealthURL should be treated as ready, got %v", err)
	}
}
