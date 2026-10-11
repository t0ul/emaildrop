package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/netpolicy"
)

// TestEnrichDegradesWhenSandboxDown locks F2: when the MicroVM fetcher is unreachable,
// enrich must NOT index an empty body and report success — it refuses with an actionable
// message. Real Server + real HITL nonce flow + real egress policy; the only injected
// seam is the fetcher itself (down / empty), which is the condition under test.
func TestEnrichDegradesWhenSandboxDown(t *testing.T) {
	policy := netpolicy.Policy{
		Allow:   []string{"handbook.test"},
		Resolve: func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil },
	}
	indexed := false
	mk := func(fetch Fetcher) *httptest.Server {
		return httptest.NewServer(New(Config{
			Egress: policy,
			Fetch:  fetch,
			Index:  func(string, string) error { indexed = true; return nil },
		}).Handler())
	}

	do := func(srv *httptest.Server, body string) map[string]any {
		resp, err := http.Post(srv.URL+"/api/enrich", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m
	}

	// Phase 1: no nonce → HITL challenge with a single-use nonce.
	// Phase 2: confirm → the fetch runs (and here fails / returns empty).
	run := func(srv *httptest.Server) map[string]any {
		ch := do(srv, `{"url":"https://handbook.test/rules"}`)
		nonce, _ := ch["nonce"].(string)
		if nonce == "" {
			t.Fatalf("expected a HITL nonce challenge, got %v", ch)
		}
		return do(srv, `{"url":"https://handbook.test/rules","nonce":"`+nonce+`","confirm":true}`)
	}

	// VM down → fetch errors.
	down := mk(func(context.Context, string) (string, error) { return "", errors.New("dial tcp 127.0.0.1:5000: connect: connection refused") })
	defer down.Close()
	res := run(down)
	if ok, _ := res["ok"].(bool); ok {
		t.Fatalf("enrich must fail when the sandbox is down, got %v", res)
	}
	if ref, _ := res["refused"].(string); !strings.Contains(ref, "sandbox fetch failed") {
		t.Errorf("want a sandbox-failure message, got %q", ref)
	}
	if indexed {
		t.Error("nothing must be indexed when the fetch failed")
	}

	// VM reachable but returns an empty body → still refuse, do not index empty.
	indexed = false
	empty := mk(func(context.Context, string) (string, error) { return "   ", nil })
	defer empty.Close()
	res = run(empty)
	if ok, _ := res["ok"].(bool); ok || indexed {
		t.Fatalf("empty fetch must not index or report success, got %v indexed=%v", res, indexed)
	}
}
