package ics

import (
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

func TestRRULEWrittenAndSanitized(t *testing.T) {
	// A valid recurrence is emitted.
	out, _, err := Write([]schema.Event{{Title: "Band", Start: "2026-10-06T15:00:00", Recur: "FREQ=WEEKLY;BYDAY=TU"}}, "cal")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "RRULE:FREQ=WEEKLY;BYDAY=TU") {
		t.Fatalf("valid RRULE not written:\n%s", out)
	}

	// An attempt to smuggle an extra ICS line through the field is dropped.
	bad := "FREQ=WEEKLY\nSUMMARY:INJECTED"
	out2, _, _ := Write([]schema.Event{{Title: "X", Start: "2026-10-06T15:00:00", Recur: bad}}, "cal")
	if strings.Contains(out2, "INJECTED") || strings.Contains(out2, "RRULE:FREQ=WEEKLY\n") {
		t.Fatalf("malformed RRULE must be dropped, got:\n%s", out2)
	}
}

func TestSanitizeRRULE(t *testing.T) {
	if sanitizeRRULE("freq=daily") != "FREQ=DAILY" {
		t.Fatal("valid rule should normalize to uppercase")
	}
	for _, bad := range []string{"", "BYDAY=TU", "FREQ=WEEKLY; DROP", "FREQ=W\nX"} {
		if got := sanitizeRRULE(bad); got != "" {
			t.Errorf("malformed %q should be dropped, got %q", bad, got)
		}
	}
}
