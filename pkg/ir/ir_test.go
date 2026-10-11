package ir_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/ir"
	"github.com/t0ul/gledger"
)

func TestReplayReconstructsTimeline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := gledger.Open(path, "test")
	if err != nil {
		t.Fatal(err)
	}
	// An incident: one trace through the chain, plus unrelated noise.
	trace := gledger.NewTraceID()
	a.Emit(trace, "request", "start", gledger.F{"source": "poison.txt"})
	a.Emit(trace, "injection_guard", "detected", gledger.F{"indicators": "ignore-instructions"})
	a.Emit(trace, "policy", "gate", gledger.F{"decision": "block"})
	a.Emit(gledger.NewTraceID(), "other", "noise", nil) // different trace

	events, err := ir.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	tl := ir.Timeline(events, trace)
	if len(tl) != 3 {
		t.Fatalf("expected 3 events for the incident, got %d", len(tl))
	}
	if tl[0].Span != "request" || tl[2].Event != "gate" {
		t.Fatalf("timeline out of order: %+v", tl)
	}
	out := ir.Format(tl)
	if !strings.Contains(out, "injection_guard/detected") {
		t.Fatalf("formatted timeline missing a step:\n%s", out)
	}
	// The log must still verify (evidence is tamper-evident).
	if ok, _ := gledger.VerifyFile(path); !ok {
		t.Fatal("audit chain failed to verify")
	}
}
