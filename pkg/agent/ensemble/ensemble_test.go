package ensemble_test

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/ensemble"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

const raw = "PTA Update\nBook fair is on October 2.\nPTA meeting October 5.\n"

func TestRejectsHallucinatedDate(t *testing.T) {
	llm := []schema.Event{{Title: "Winter Gala", Start: "2026-12-25T19:00:00", Kind: schema.KindEvent, Confidence: 0.9}}
	out := ensemble.Reconcile(nil, llm, raw, 2026)
	for _, e := range out {
		if e.Title == "Winter Gala" {
			t.Fatalf("hallucinated event (date not in email) should be dropped: %+v", out)
		}
	}
}

func TestKeepsLLMItemWithRealDate(t *testing.T) {
	llm := []schema.Event{{Title: "Book Fair", Due: "2026-10-02", Kind: schema.KindEvent, Confidence: 0.9}}
	out := ensemble.Reconcile(nil, llm, raw, 2026)
	if len(out) != 1 || out[0].Confidence != 0.7 {
		t.Fatalf("LLM-only item with a real date should be kept at review confidence: %+v", out)
	}
}

func TestAgreementBoostsConfidence(t *testing.T) {
	rx := []schema.Event{{Title: "Book Fair", Start: "2026-10-02", AllDay: true, Kind: schema.KindEvent, Confidence: 0.75}}
	llm := []schema.Event{{Title: "Book fair", Due: "2026-10-02", Kind: schema.KindEvent, Confidence: 0.9}}
	out := ensemble.Reconcile(rx, llm, raw, 2026)
	if len(out) != 1 || out[0].Confidence < 0.95 {
		t.Fatalf("agreed item should be one high-confidence event: %+v", out)
	}
}

// The whitelist of dates seen in the email must include numeric dates, or every model
// item for a "Date: 10/28" email is rejected as a hallucination.
func TestKeepsLLMItemWithNumericDateInText(t *testing.T) {
	text := "Join us for an evening in the lobby.\nDate: 10/28\nTime: 5PM - 7PM\n"
	llm := []schema.Event{{Title: "Evening in the lobby", Start: "2026-10-28T17:00:00", Kind: schema.KindEvent, Confidence: 0.9}}
	out := ensemble.Reconcile(nil, llm, text, 2026)
	if len(out) != 1 || out[0].Start != "2026-10-28T17:00:00" {
		t.Fatalf("a model item whose date is written numerically must be kept: %+v", out)
	}
}

// The deterministic arm found "A cozy evening" at 17:00 to 19:00; the model proposes
// "RSVP" for the same slot. That is one event seen twice, not two events: the regex
// title wins and the pair counts as agreement.
func TestSameTimedSlotIsAgreement(t *testing.T) {
	text := "Join us for a cozy evening.\nDate: 10/28\nTime: 5PM - 7PM\n"
	regex := []schema.Event{{Title: "A cozy evening", Start: "2026-10-28T17:00:00", End: "2026-10-28T19:00:00", Kind: schema.KindEvent, Confidence: 0.9}}
	llm := []schema.Event{{Title: "RSVP", Start: "2026-10-28T17:00:00", End: "2026-10-28T19:00:00", Kind: schema.KindEvent, Confidence: 0.9}}
	out := ensemble.Reconcile(regex, llm, text, 2026)
	if len(out) != 1 || out[0].Title != "A cozy evening" || out[0].Confidence != 0.97 {
		t.Fatalf("same slot must merge onto the regex event at 0.97: %+v", out)
	}
}
