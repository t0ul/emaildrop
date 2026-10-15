// Package ensemble reconciles two independent extractors — the deterministic
// regex path (agent/items) and the LLM path (agent/extractor) — so they
// cross-check each other (the robustness answer to format variance).
//
// The security-critical rule: the LLM read an UNTRUSTED email, so its output is
// untrusted. An LLM-proposed item whose date does not appear in the raw email is
// a hallucination and is REJECTED (deterministic dates are the authority, M9).
// Items both sources agree on get high confidence; a solo item is kept but
// flagged for review. This is CaMeL applied to extraction: the deterministic
// layer constrains the quarantined model.
package ensemble

import (
	"regexp"
	"strings"

	"github.com/t0ul/emaildrop/pkg/agent/dateparse"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func norm(s string) string {
	return strings.Join(strings.Fields(nonAlnum.ReplaceAllString(strings.ToLower(s), " ")), " ")
}

func dateKey(e schema.Event) string {
	d := e.Due
	if d == "" {
		d = e.Start
	}
	if len(d) >= 10 {
		return d[:10]
	}
	return d
}

// datesInText returns the set of ISO dates (YYYY-MM-DD) that actually appear in
// the raw email, per the deterministic date parser.
func datesInText(text string, year int) map[string]bool {
	set := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if dt := dateparse.ExtractDatetime(line, year); dt != nil {
			set[dt.Start[:10]] = true
		}
	}
	return set
}

// Reconcile merges the regex items with the LLM proposals against the raw email.
// An LLM item with a date absent from the raw text is dropped (hallucination);
// an item both sources found is boosted to high confidence; an LLM-only item is
// kept at review-level confidence.
func Reconcile(regexItems, llmItems []schema.Event, rawText string, year int) []schema.Event {
	if year == 0 {
		year = dateparse.DefaultYear
	}
	dates := datesInText(rawText, year)

	out := append([]schema.Event{}, regexItems...)
	key := func(e schema.Event) string { return norm(e.Title) + "|" + dateKey(e) }
	idx := map[string]int{}
	for i, e := range out {
		idx[key(e)] = i
	}

	// A timed slot the deterministic arm already filled: the model's item at the
	// same start (and end) is the same event under another name, not a second one.
	slot := map[string]int{}
	for i, e := range out {
		if strings.Contains(e.Start, "T") {
			slot[e.Start+"|"+e.End] = i
		}
	}
	for _, le := range llmItems {
		if d := dateKey(le); d != "" && !dates[d] {
			continue // hallucinated date — not in the email; reject (M9)
		}
		if i, ok := idx[key(le)]; ok {
			out[i].Confidence = 0.97 // both extractors agree
			continue
		}
		if i, ok := slot[le.Start+"|"+le.End]; ok && strings.Contains(le.Start, "T") {
			out[i].Confidence = 0.97 // same timed slot: agreement on the event, the regex title wins
			continue
		}
		le.Confidence = 0.7 // LLM-only — keep, but flag for review
		le.Warnings = append(le.Warnings, "llm_only: not confirmed by the deterministic parser")
		out = append(out, le)
		idx[key(le)] = len(out) - 1
	}
	return out
}
