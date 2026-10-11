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
