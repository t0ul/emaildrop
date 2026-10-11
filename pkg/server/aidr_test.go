package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/pkg/aidr"
	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/ir"
	"github.com/t0ul/emaildrop/pkg/provenance"
)

// TestAIDRAutoContainsDenyStorm locks A7: a burst of capability denials (the App token
// probing operator endpoints) is detected by the controller and fed to a real aidr
// engine, which auto-escalates the real kill switch to block tools. Detection becomes
// containment — no human in the loop. Real Authority + Safety + aidr, no mocks.
func TestAIDRAutoContainsDenyStorm(t *testing.T) {
	signer, pub, err := provenance.NewSigner("op")
	if err != nil {
		t.Fatal(err)
	}
	authz := controlplane.NewAuthority(signer, provenance.NewVerifier().Trust("op", pub))
	appGrant, err := authz.IssueScoped(
		controlplane.Capability{Subject: "app", Action: controlplane.ActionList, Resource: "corpus", Tenant: "public"},
		nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	appTok := bearer(t, appGrant)

	safety := controlplane.NewSafety(nil)
	engine := aidr.New(func(level controlplane.KillLevel, reason string) {
		if level > safety.Level() {
			safety.Set("aidr", level)
		}
	})
	detect := func(span, event string, fields map[string]any) {
		engine.Observe(ir.Event{Service: "webapp", Span: span, Event: event, Fields: fields})
	}

	srv := httptest.NewServer(New(Config{
		Authz:   authz,
		Safety:  safety,
		Prompts: controlplane.NewPrompts(map[string]string{"chat_system": "x"}), // operator read
		Detect:  detect,
	}).Handler())
	defer srv.Close()

	if safety.Level() != controlplane.LevelNone {
		t.Fatalf("precondition: safety should start at None, got %v", safety.Level())
	}

	// Probe an operator endpoint with the under-privileged App token repeatedly.
	for i := 0; i < denyStormThreshold+2; i++ {
		req, _ := http.NewRequest("GET", srv.URL+"/api/prompts", nil)
		req.Header.Set("Authorization", appTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("probe %d: expected 403, got %d", i, resp.StatusCode)
		}
	}

	if got := safety.Level(); got < controlplane.LevelBlockTools {
		t.Fatalf("a deny storm must auto-contain (block tools), kill level is %v", got)
	}
	if safety.AllowToolExec() {
		t.Error("tool execution must be blocked after auto-containment")
	}
}

// TestAIDRIgnoresBudgetThrottling locks the review fix: a burst that trips the RATE
// budget (429 backpressure) is NOT a capability-probing signal and must NEVER auto-contain
// — otherwise normal traffic could self-DoS the agent. Real Authority + Safety + aidr.
func TestAIDRIgnoresBudgetThrottling(t *testing.T) {
	signer, pub, err := provenance.NewSigner("op")
	if err != nil {
		t.Fatal(err)
	}
	authz := controlplane.NewAuthority(signer, provenance.NewVerifier().Trust("op", pub))
	// A VALID grant for a consumer read (so it is NOT a capability refusal) — the only
	// denials will be rate-budget 429s.
	appGrant, err := authz.IssueScoped(
		controlplane.Capability{Subject: "app", Action: controlplane.ActionList, Resource: "corpus", Tenant: "public"},
		nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	appTok := bearer(t, appGrant)

	safety := controlplane.NewSafety(nil)
	engine := aidr.New(func(level controlplane.KillLevel, _ string) {
		if level > safety.Level() {
			safety.Set("aidr", level)
		}
	})
	srv := httptest.NewServer(New(Config{
		Authz:     authz,
		Safety:    safety,
		Budgets:   controlplane.NewBudgets(map[string]controlplane.BudgetConfig{"api": {RatePerMin: 3}}),
		OutboxDir: t.TempDir(), // registers /api/events (consumer read the App grant may use)
		Detect:    func(span, event string, f map[string]any) { engine.Observe(ir.Event{Span: span, Event: event, Fields: f}) },
	}).Handler())
	defer srv.Close()

	// Well over the rate budget → many 429s, all with a VALID capability.
	for i := 0; i < denyStormThreshold+10; i++ {
		req, _ := http.NewRequest("GET", srv.URL+"/api/events", nil)
		req.Header.Set("Authorization", appTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if safety.Level() != controlplane.LevelNone {
		t.Fatalf("rate-budget throttling must NOT auto-contain, kill level is %v", safety.Level())
	}
}
