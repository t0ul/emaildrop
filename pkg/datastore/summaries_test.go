package datastore_test

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

// TestSummariesProjectionRoundTrip: ReplaceSummaries persists sidecar JSON keyed by
// file + the fingerprint; LoadSummaries reads it back, and a rebuild replaces wholesale.
func TestSummariesProjectionRoundTrip(t *testing.T) {
	s := open(t)
	rows := []datastore.SummaryRow{
		{File: "1.summary.json", JSON: `{"digest":"newsletter","items":[{"title":"Field trip"}]}`},
		{File: "2.summary.json", JSON: `{"digest":"reminder"}`},
	}
	if err := s.ReplaceSummaries("sfp-1", rows); err != nil {
		t.Fatalf("ReplaceSummaries: %v", err)
	}
	fp, got, err := s.LoadSummaries()
	if err != nil || fp != "sfp-1" || len(got) != 2 {
		t.Fatalf("round-trip fp=%q n=%d err=%v", fp, len(got), err)
	}
	if got[0].File != "1.summary.json" || got[0].JSON == "" {
		t.Fatalf("row content lost: %+v", got[0])
	}
	// Rebuild replaces wholesale and updates the fingerprint.
	if err := s.ReplaceSummaries("sfp-2", rows[:1]); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	fp2, got2, _ := s.LoadSummaries()
	if fp2 != "sfp-2" || len(got2) != 1 {
		t.Fatalf("rebuild should replace wholesale, fp=%q n=%d", fp2, len(got2))
	}
}
