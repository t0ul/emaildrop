//go:build live

// Package livemodel boots the real llama/qwen models behind an in-process gouncer
// gateway for LIVE tests — the same stack cmd/livecheck runs, factored out so a
// `go test -tags live ./...` run can exercise the actual model path (extraction,
// injection defense, eval F1) instead of in-process stubs. It compiles only under
// the `live` build tag, so the default offline suite never pulls it in.
package livemodel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/t0ul/emaildrop/internal/modelserve"
	"github.com/t0ul/gouncer"
)

const (
	host        = "127.0.0.1"
	plannerPort = 11435
	coderPort   = 11436
	gatewayAddr = "127.0.0.1:4000"
)

// Harness owns the running models + gateway for a live test run.
type Harness struct {
	sup *modelserve.Supervisor
	srv *http.Server
}

func bin() string { h, _ := os.UserHomeDir(); return filepath.Join(h, ".llama-app", "llama") }
func dir() string { return "set-up/vm-assets" }

// Available reports whether the llama binary and both GGUFs are present, so a live
// test can Skip with a clear message rather than fail when models aren't set up.
func Available() (bool, string) {
	for _, p := range []string{bin(), filepath.Join(dir(), "llama-3.2-3b.gguf"), filepath.Join(dir(), "qwen1.5b.gguf")} {
		if _, err := os.Stat(p); err != nil {
			return false, fmt.Sprintf("live model not available: %s missing (run `go run ./cmd/preflight`)", p)
		}
	}
	return true, ""
}

// Start boots planner+coder (ready-gated) and the gouncer gateway on :4000, and
// points the extractor at the LLM path (EXTRACT_MODE=llm, GATEWAY_URL=:4000).
func Start(ctx context.Context, ready time.Duration) (*Harness, error) {
	for _, p := range []int{plannerPort, coderPort, 4000} {
		modelserve.ReclaimPort(p, os.Stdout)
	}
	sup := &modelserve.Supervisor{Servers: []modelserve.Server{
		modelserve.LlamaServer("planner", bin(), host, filepath.Join(dir(), "llama-3.2-3b.gguf"), plannerPort, 8192),
		modelserve.LlamaServer("coder", bin(), host, filepath.Join(dir(), "qwen1.5b.gguf"), coderPort, 4096),
	}}
	if err := sup.Start(ctx); err != nil {
		return nil, err
	}
	if err := sup.WaitHealthy(ctx, ready); err != nil {
		sup.Shutdown()
		return nil, err
	}
	gw, err := gouncer.New(gouncer.Config{
		Routes: map[string]gouncer.Route{
			"planner": {Upstream: fmt.Sprintf("http://%s:%d", host, plannerPort)},
			"coder":   {Upstream: fmt.Sprintf("http://%s:%d", host, coderPort)},
		},
		UpstreamTimeout: 120 * time.Second,
	})
	if err != nil {
		sup.Shutdown()
		return nil, err
	}
	srv := &http.Server{Addr: gatewayAddr, Handler: gw, ReadHeaderTimeout: 10 * time.Second}
	go srv.ListenAndServe()
	if err := waitListening(ctx, gatewayAddr, 5*time.Second); err != nil {
		srv.Close()
		sup.Shutdown()
		return nil, err
	}
	// EXTRACT_MODE=llm routes extraction through the model; GATEWAY_URL is left to
	// the extractor default (http://localhost:4000/v1/chat/completions) — our
	// gateway listens on :4000, so overriding it (and dropping the path) would
	// 404 and silently fall back. Matches cmd/livecheck.
	os.Setenv("EXTRACT_MODE", "llm")
	return &Harness{sup: sup, srv: srv}, nil
}

// Close stops the gateway and the model servers.
func (h *Harness) Close() {
	if h.srv != nil {
		h.srv.Close()
	}
	if h.sup != nil {
		h.sup.Shutdown()
	}
}

func waitListening(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %s", timeout)
}
