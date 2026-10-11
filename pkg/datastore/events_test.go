package datastore_test

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

// TestEventsProjectionRoundTrip: ReplaceEvents writes the deduped projection + its
// outbox fingerprint; LoadEvents reads it back in order with bools/fields intact.
func TestEventsProjectionRoundTrip(t *testing.T) {
	s := open(t)
	rows := []datastore.EventRow{
		{Title: "Back to School Night", Start: "2026-09-29 17:30", Kind: "event", Signed: true},
		{Title: "Permission slip", Due: "2026-10-15", Kind: "task", AllDay: true},
		{Title: "Field trip", Start: "2026-10-20", Kind: "event", AllDay: true, HasReminder: true, Signed: true, Location: "NYPL"},
	}
	if err := s.ReplaceEvents("fp-v1", rows); err != nil {
		t.Fatalf("ReplaceEvents: %v", err)
	}
	fp, got, err := s.LoadEvents()
	if err != nil || fp != "fp-v1" {
		t.Fatalf("LoadEvents fp=%q err=%v", fp, err)
	}
	if len(got) != 3 || got[0].Title != "Back to School Night" || got[2].Location != "NYPL" {
		t.Fatalf("round-trip order/fields wrong: %+v", got)
	}
	if !got[2].AllDay || !got[2].HasReminder || !got[2].Signed {
		t.Fatalf("bool fields lost: %+v", got[2])
	}
	if got[0].Signed != true || got[1].Signed != false {
		t.Fatalf("signed flag not preserved: %+v", got)
	}

	// Rebuild replaces wholesale (no duplicate accumulation) and updates the fp.
	if err := s.ReplaceEvents("fp-v2", rows[:1]); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	fp2, got2, _ := s.LoadEvents()
	if fp2 != "fp-v2" || len(got2) != 1 {
		t.Fatalf("rebuild should replace wholesale, fp=%q n=%d", fp2, len(got2))
	}
}
