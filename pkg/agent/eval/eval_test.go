package eval_test

import (
	"math"
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/eval"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

func ev(title, start, end, loc string) schema.Event {
	return schema.Event{Title: title, Start: start, End: end, Location: loc}
}
func gold(title, start, end, loc string) eval.GoldEvent {
	return eval.GoldEvent{Title: title, Start: start, End: end, Location: loc}
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestPerfectMatchF1One(t *testing.T) {
	g := []eval.GoldEvent{
		gold("Back-to-School Night", "2026-09-29T17:30:00", "2026-09-29T20:00:00", "School Building"),
		gold("PTA Meeting", "2026-09-24T08:30:00", "", "Gymnatorium"),
	}
	p := []schema.Event{
		// fuzzy title ("Night" subset) + same day; location substring
		ev("Back to School Night", "2026-09-29T17:30:00", "2026-09-29T20:00:00", "The School Building"),
		ev("PTA Meeting", "2026-09-24T08:30:00", "", "Gymnatorium"),
	}
	r := eval.ScoreEvents("x", g, p)
	if r.Matched != 2 || !approx(r.F1, 1.0) {
		t.Fatalf("expected 2 matches, F1=1.0; got matched=%d f1=%.3f", r.Matched, r.F1)
	}
	if r.StartOK != 2 || r.EndOK != 2 || r.LocOK != 2 {
		t.Errorf("field accuracy off: start=%d end=%d loc=%d", r.StartOK, r.EndOK, r.LocOK)
	}
}

func TestFalsePositiveAndNegative(t *testing.T) {
	g := []eval.GoldEvent{
		gold("Evacuation Drill", "2026-10-01T10:08:00", "", ""),
		gold("Title I Meeting", "2026-10-15T08:30:00", "", ""),
	}
	p := []schema.Event{
		ev("Evacuation Drill", "2026-10-01T10:08:00", "", ""), // tp
		ev("Bake Sale", "2026-10-20T09:00:00", "", ""),        // fp
	}
	r := eval.ScoreEvents("x", g, p)
	// tp=1 fp=1 fn=1 -> prec=.5 rec=.5 f1=.5
	if r.Matched != 1 || !approx(r.Precision, 0.5) || !approx(r.Recall, 0.5) || !approx(r.F1, 0.5) {
		t.Fatalf("got matched=%d prec=%.3f rec=%.3f f1=%.3f", r.Matched, r.Precision, r.Recall, r.F1)
	}
}

func TestDateMismatchBlocksMatch(t *testing.T) {
	g := []eval.GoldEvent{gold("PTA Meeting", "2026-09-24T08:30:00", "", "")}
	p := []schema.Event{ev("PTA Meeting", "2026-09-25T08:30:00", "", "")} // right title, wrong day
	r := eval.ScoreEvents("x", g, p)
	if r.Matched != 0 || r.F1 != 0 {
		t.Fatalf("date mismatch must not match: matched=%d f1=%.3f", r.Matched, r.F1)
	}
}

func TestFieldAccuracyPartial(t *testing.T) {
	g := []eval.GoldEvent{gold("Back to School Night", "2026-09-29T17:30:00", "2026-09-29T20:00:00", "School Building")}
	// matches on day+title, but end time wrong and location absent
	p := []schema.Event{ev("Back to School Night", "2026-09-29T17:30:00", "2026-09-29T19:00:00", "")}
	r := eval.ScoreEvents("x", g, p)
	if r.Matched != 1 || r.StartOK != 1 || r.EndOK != 0 || r.LocOK != 0 {
		t.Fatalf("partial fields: matched=%d start=%d end=%d loc=%d", r.Matched, r.StartOK, r.EndOK, r.LocOK)
	}
	if !approx(r.F1, 1.0) { // F1 counts the match; field accuracy is separate
		t.Errorf("F1 should be 1.0 on the single match, got %.3f", r.F1)
	}
}

func TestAllDayMatchByDay(t *testing.T) {
	g := []eval.GoldEvent{gold("Veterans Day (No School)", "2026-11-11", "", "")}
	p := []schema.Event{ev("Veterans Day", "2026-11-11", "", "")}
	r := eval.ScoreEvents("x", g, p)
	if r.Matched != 1 || !approx(r.F1, 1.0) {
		t.Fatalf("all-day match by day failed: matched=%d f1=%.3f", r.Matched, r.F1)
	}
}
