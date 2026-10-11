package ensemble_test

import (
	"strings"
	"testing"

	"github.com/t0ul/ADD"
	"github.com/t0ul/emaildrop/pkg/agent/ensemble"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

// FuzzReconcileRejectsHallucination hunts for a raw email where the reconciler
// lets an LLM item through whose date (2026-12-25) is NOT present — the core
// security invariant (deterministic dates are the authority, M9). The fuzzed
// input is the raw text; a bypass is the invariant failing on some parser edge.
func FuzzReconcileRejectsHallucination(f *testing.F) {
	halluc := []schema.Event{{Title: "HALLUC", Start: "2026-12-25T19:00:00", Kind: schema.KindEvent}}
	seeds := []string{"Book fair October 2.", "", "December 25", "12/25/2026", "nothing dated here"}
	add.FuzzInvariant(f, seeds, func(t *testing.T, raw string) {
		out := ensemble.Reconcile(nil, halluc, raw, 2026)
		kept := false
		for _, e := range out {
			if e.Title == "HALLUC" {
				kept = true
			}
		}
		// Oracle: the item's date (Dec 25) is "present" exactly when the
		// case-insensitive month-name phrase is — matching dateparse, the
		// authority Reconcile uses. If absent, the hallucination MUST be dropped.
		lo := strings.ToLower(raw)
		if kept && !strings.Contains(lo, "december 25") {
			t.Fatalf("hallucination kept though its date is absent from %q", raw)
		}
	})
}
