package schema_test

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

func TestNeedsReview(t *testing.T) {
	ok := schema.Event{Title: "PTA", Start: "2026-09-24T08:30:00", Confidence: 0.9}
	if ok.NeedsReview() {
		t.Error("confident, warning-free event should not need review")
	}
	lowConf := schema.Event{Title: "x", Confidence: 0.5}
	if !lowConf.NeedsReview() {
		t.Error("low-confidence event must be flagged for review")
	}
	warned := schema.Event{Title: "x", Confidence: 1.0, Warnings: []string{"weekday_mismatch"}}
	if !warned.NeedsReview() {
		t.Error("warned event must be flagged for review")
	}
}
