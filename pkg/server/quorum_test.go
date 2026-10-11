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

// TestQuorumGatesEgressFetch locks the server wiring of A4/A5: when the quorum gate
// refuses, the egress fetch does NOT run (the fetcher is never called); when it approves,
// the fetch proceeds. Real Server + real HITL nonce flow.
func TestQuorumGatesEgressFetch(t *testing.T) {
	policy := netpolicy.Policy{
		Allow:   []string{"handbook.test"},
		Resolve: func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil },
	}
	fetched := false
	mk := func(quorum func(string) error) *httptest.Server {
		return httptest.NewServer(New(Config{
			Egress: policy,
			Quorum: quorum,
			Fetch:  func(context.Context, string) (string, error) { fetched = true; return "handbook body", nil },
			Index:  func(string, string) error { return nil },
		}).Handler())
	}
	run := func(srv *httptest.Server) map[string]any {
		post := func(body string) map[string]any {
			resp, err := http.Post(srv.URL+"/api/enrich", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var m map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&m)
			return m
		}
		ch := post(`{"url":"https://handbook.test/x"}`)
		nonce, _ := ch["nonce"].(string)
		return post(`{"url":"https://handbook.test/x","nonce":"` + nonce + `","confirm":true}`)
	}

	// Quorum refuses → fetch must not run.
	deny := mk(func(string) error { return errors.New("not enough distinct valid attestations") })
	defer deny.Close()
	res := run(deny)
	if ok, _ := res["ok"].(bool); ok {
		t.Fatalf("quorum refusal must block the fetch, got %v", res)
	}
	if ref, _ := res["refused"].(string); !strings.Contains(ref, "quorum") {
		t.Errorf("want a quorum refusal, got %q", ref)
	}
	if fetched {
		t.Error("the fetcher must NOT be called when the quorum refuses")
	}

	// Quorum approves → fetch runs.
	fetched = false
	ok := mk(func(string) error { return nil })
	defer ok.Close()
	res = run(ok)
	if okv, _ := res["ok"].(bool); !okv || !fetched {
		t.Fatalf("quorum approval must allow the fetch, got %v fetched=%v", res, fetched)
	}
}
