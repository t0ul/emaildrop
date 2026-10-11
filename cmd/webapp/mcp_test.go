package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/domain"
)

// TestMCPRegisterApproveCallDelete exercises the operator tool-server registry end to end on
// real objects: a real SQLite store, a real Safety kill switch, and the real gustoms sandbox
// gateway. `fetch` is the one injected seam (the egress-gated sandbox path in production); the
// test asserts the registry only reaches it once every gate passes, with the registered URL.
func TestMCPRegisterApproveCallDelete(t *testing.T) {
	inv, err := datastore.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	safety := controlplane.NewSafety(nil)
	gw := controlplane.NewToolGateway("sandbox", controlplane.SandboxFetchTool(controlplane.NewInterpreter("", nil)), safety.AllowToolExec)

	var gotURL string
	fetch := func(ctx context.Context, url string) (string, error) { gotURL = url; return "fetched:" + url, nil }
	reg := mcpRegistry{gw: gw, safety: safety, store: inv, fetch: fetch}

	find := func() (domain.MCPServer, bool) {
		for _, s := range reg.List() {
			if s.Name == "weather" {
				return s, true
			}
		}
		return domain.MCPServer{}, false
	}

	// Register + validation.
	if err := reg.Register("weather", "https://wx.test/api", []string{"forecast", "alerts"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register("sandbox", "https://x/", []string{"a"}); err == nil {
		t.Error("'sandbox' must be reserved")
	}
	if err := reg.Register("bad", "ftp://x/", []string{"a"}); err == nil {
		t.Error("a non-http url must be refused")
	}
	if err := reg.Register("notools", "https://x/", nil); err == nil {
		t.Error("a server with no tools must be refused")
	}

	// Listed as a registered, unapproved server.
	if w, ok := find(); !ok || w.Status != "unapproved" || !w.Registered {
		t.Fatalf("want registered+unapproved, got %+v ok=%v", w, ok)
	}

	// Fails closed before approval.
	if _, err := reg.Call(context.Background(), "weather", "forecast"); err == nil || !strings.Contains(err.Error(), "approved") {
		t.Fatalf("an unapproved call must be refused, got %v", err)
	}

	// Approve → pinned.
	if err := reg.Approve("weather"); err != nil {
		t.Fatal(err)
	}
	if w, _ := find(); w.Status != "pinned" {
		t.Fatalf("want pinned after approve, got %q", w.Status)
	}

	// A tool outside the declared manifest is refused.
	if _, err := reg.Call(context.Background(), "weather", "nope"); err == nil {
		t.Error("a tool outside the manifest must be refused")
	}

	// The kill switch blocks tools.
	safety.Set("test", controlplane.LevelBlockTools)
	if _, err := reg.Call(context.Background(), "weather", "forecast"); err == nil || !strings.Contains(err.Error(), "kill switch") {
		t.Fatalf("a halted call must be blocked, got %v", err)
	}
	safety.Set("test", controlplane.LevelNone)

	// Approved, in-manifest, tools allowed → reaches the sandbox with the registered URL.
	out, err := reg.Call(context.Background(), "weather", "forecast")
	if err != nil || out != "fetched:https://wx.test/api" || gotURL != "https://wx.test/api" {
		t.Fatalf("an approved call should reach the sandbox with the registered url: out=%q url=%q err=%v", out, gotURL, err)
	}

	// Re-register with a changed manifest → the prior pin no longer matches (rug-pull) until re-approve.
	if err := reg.Register("weather", "https://wx.test/api", []string{"forecast"}); err != nil {
		t.Fatal(err)
	}
	if w, _ := find(); w.Status != "rug-pull" {
		t.Fatalf("a changed manifest should read rug-pull, got %q", w.Status)
	}

	// Delete removes it.
	if err := reg.Delete("weather"); err != nil {
		t.Fatal(err)
	}
	if _, ok := find(); ok {
		t.Error("a deleted server must be gone")
	}
}
