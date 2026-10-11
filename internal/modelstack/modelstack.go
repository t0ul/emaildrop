// Package modelstack boots the local model runtime (llama.cpp servers + an
// in-process gouncer gateway) from the DB-backed model catalog, so the webapp can
// bring the models up automatically on startup — no separate `modeld` + gateway
// processes to hand-run. It is the non-test twin of internal/livemodel (which is
// build-tagged for tests and hardcodes paths); this one is catalog-driven.
package modelstack

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/emaildrop/internal/modelserve"
	"github.com/t0ul/gouncer"
)

// Stack owns the running model servers + gateway.
type Stack struct {
	sup *modelserve.Supervisor
	srv *http.Server
}

// BinPath is the llama.cpp server binary location.
func BinPath() string { h, _ := os.UserHomeDir(); return filepath.Join(h, ".llama-app", "llama") }

// Available reports whether the llama binary and every catalog model's GGUF are
// present, so the caller can skip auto-start with a clear reason instead of failing.
// chatModels returns the catalog entries served by the chat stack — every entry that is
// NOT a trained embedding model (those are served by the dedicated embeddings server, so
// booting them here as chat/completions servers would be wrong). (B4.)
func chatModels(catalog []modelcatalog.Entry) []modelcatalog.Entry {
	out := make([]modelcatalog.Entry, 0, len(catalog))
	for _, e := range catalog {
		if !e.IsEmbedding() {
			out = append(out, e)
		}
	}
	return out
}

func Available(assetsDir string, catalog []modelcatalog.Entry) (bool, string) {
	if _, err := os.Stat(BinPath()); err != nil {
		return false, "llama binary missing at " + BinPath()
	}
	chat := chatModels(catalog)
	if len(chat) == 0 {
		return false, "model catalog has no chat models"
	}
	for _, e := range chat {
		p := filepath.Join(assetsDir, e.File)
		if _, err := os.Stat(p); err != nil {
			return false, "model file missing: " + p
		}
	}
	return true, ""
}

// Start boots every catalog model (ready-gated) and a gouncer gateway at
// gatewayAddr that routes each logical model name to its port. It reclaims the
// ports first, so a stale server from a prior run does not block startup.
func Start(ctx context.Context, assetsDir, gatewayAddr string, catalog []modelcatalog.Entry, ready time.Duration) (*Stack, error) {
	bin := BinPath()
	var servers []modelserve.Server
	routes := map[string]gouncer.Route{}
	for _, e := range chatModels(catalog) {
		host := e.Host
		if host == "" {
			host = "127.0.0.1"
		}
		modelserve.ReclaimPort(e.Port, os.Stdout)
		servers = append(servers, modelserve.LlamaServer(e.Name, bin, host, filepath.Join(assetsDir, e.File), e.Port, e.Ctx))
		routes[e.Name] = gouncer.Route{Upstream: fmt.Sprintf("http://%s:%d", host, e.Port)}
	}
	if _, portStr, err := net.SplitHostPort(gatewayAddr); err == nil {
		if p, perr := net.LookupPort("tcp", portStr); perr == nil {
			modelserve.ReclaimPort(p, os.Stdout)
		}
	}

	sup := &modelserve.Supervisor{Servers: servers}
	if err := sup.Start(ctx); err != nil {
		return nil, err
	}
	if err := sup.WaitHealthy(ctx, ready); err != nil {
		sup.Shutdown()
		return nil, err
	}
	gw, err := gouncer.New(gouncer.Config{Routes: routes, UpstreamTimeout: 120 * time.Second})
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
	return &Stack{sup: sup, srv: srv}, nil
}

// Close stops the gateway and the model servers.
func (s *Stack) Close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.sup != nil {
		s.sup.Shutdown()
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
	return fmt.Errorf("gateway did not come up within %s", timeout)
}
