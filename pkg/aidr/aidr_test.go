package aidr_test

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/aidr"
	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/ir"
)

func TestPolicyBlockEscalatesToBlockTools(t *testing.T) {
	var gotLevel controlplane.KillLevel
	var gotReason string
	e := aidr.New(func(l controlplane.KillLevel, r string) { gotLevel, gotReason = l, r })
	lvl, fired := e.Observe(ir.Event{Span: "policy", Event: "gate", Fields: map[string]any{"decision": "block"}})
	if !fired || lvl != controlplane.LevelBlockTools {
		t.Fatalf("policy block should trigger block-tools, got %s fired=%v", lvl, fired)
	}
	if gotLevel != controlplane.LevelBlockTools || gotReason != "policy-block" {
		t.Fatalf("response got level=%s reason=%q", gotLevel, gotReason)
	}
}

func TestCircuitBreakerHalts(t *testing.T) {
	e := aidr.New(nil)
	lvl, _ := e.Observe(ir.Event{Span: "planner", Event: "circuit_breaker_tripped"})
	if lvl != controlplane.LevelHalt {
		t.Fatalf("breaker should halt, got %s", lvl)
	}
}

func TestBenignEventNoResponse(t *testing.T) {
	called := false
	e := aidr.New(func(controlplane.KillLevel, string) { called = true })
	if _, fired := e.Observe(ir.Event{Span: "request", Event: "start"}); fired || called {
		t.Fatal("benign event must not trigger a response")
	}
}

func TestScanAutoEngagesSafety(t *testing.T) {
	// The response wires straight into the real layered kill switch.
	s := controlplane.NewSafety(nil)
	e := aidr.New(func(l controlplane.KillLevel, _ string) { s.Set("aidr", l) })
	events := []ir.Event{
		{Span: "request", Event: "start"},
		{Span: "gustoms", Event: "deny", Fields: map[string]any{"reason": "pin_mismatch"}},
	}
	e.Scan(events)
	if s.AllowToolExec() {
		t.Fatal("AIDR should have auto-engaged block-tools after the rug-pull signal")
	}
}
