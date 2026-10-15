package server

import "testing"

func TestDedupCollapsesFragmentTitle(t *testing.T) {
	in := []Event{
		{Title: "The Science Fair is", Start: "2026-10-15 18:00", Kind: "event"},
		{Title: "Science Fair", Start: "2026-10-15 18:00", Kind: "event"},
	}
	got := dedupEvents(in)
	if len(got) != 1 {
		t.Fatalf("near-dup same-slot events should collapse to 1, got %d: %+v", len(got), got)
	}
	if got[0].Title != "Science Fair" {
		t.Fatalf("the cleaner title should win, got %q", got[0].Title)
	}
}

func TestDedupKeepsDistinctSameDayEvents(t *testing.T) {
	in := []Event{
		{Title: "Science Fair", Start: "2026-10-15 18:00", Kind: "event"},
		{Title: "Band Concert", Start: "2026-10-15 18:00", Kind: "event"}, // same slot, unrelated title
		{Title: "Science Fair", Start: "2026-10-16 18:00", Kind: "event"}, // same title, different day
	}
	if got := dedupEvents(in); len(got) != 3 {
		t.Fatalf("distinct events must not be merged, got %d: %+v", len(got), got)
	}
}

// TestDedupCollapsesNearDuplicateWording: the same holiday phrased differently across
// emails collapses, but distinct same-day events with long shared prefixes do not.
func TestDedupCollapsesNearDuplicateWording(t *testing.T) {
	in := []Event{
		{Title: "Italian Heritage/Indigenous Peoples' Day", Start: "2026-10-12", AllDay: true, Kind: "event"},
		{Title: "Italian Heritage and Indigenous Peoples' Day, schools closed", Start: "2026-10-12", AllDay: true, Kind: "event"},
	}
	if got := dedupEvents(in); len(got) != 1 {
		t.Fatalf("near-duplicate wording of the same event must collapse, got %d: %+v", len(got), got)
	}
	// Distinct conferences on the SAME day (shared prefix) must NOT merge.
	in2 := []Event{
		{Title: "Evening Parent-Teacher Conferences for middle schools and D75", Start: "2026-11-05", AllDay: true, Kind: "event"},
		{Title: "Evening Parent-Teacher Conferences for high schools, K-12, and 6-12 schools", Start: "2026-11-05", AllDay: true, Kind: "event"},
	}
	if got := dedupEvents(in2); len(got) != 2 {
		t.Fatalf("distinct same-day conferences must stay separate, got %d: %+v", len(got), got)
	}
}

func TestDedupSeparatesEventFromTask(t *testing.T) {
	in := []Event{
		{Title: "Permission slip", Start: "2026-10-15", Kind: "event"},
		{Title: "Permission slip", Due: "2026-10-15", Kind: "task"},
	}
	if got := dedupEvents(in); len(got) != 2 {
		t.Fatalf("an event and a task must stay distinct, got %d", len(got))
	}
}

// TestDedupCollapsesSameDayDifferentTime is the per-day fix: the same event on the
// same day with a different (often fabricated) time collapses to one, and the
// all-day version wins over the mis-timed one.
func TestDedupCollapsesSameDayDifferentTime(t *testing.T) {
	in := []Event{
		{Title: "Evacuation Drill", Start: "2026-10-14 22:27", Kind: "event"},
		{Title: "Evacuation Drill", Start: "2026-10-14", Kind: "event", AllDay: true},
	}
	got := dedupEvents(in)
	if len(got) != 1 {
		t.Fatalf("same event, same day should collapse to 1, got %d: %+v", len(got), got)
	}
	if !got[0].AllDay {
		t.Fatalf("the all-day entry should win over the mis-timed one, got %+v", got[0])
	}
}

// TestDropFragments removes lowercase-start sentence fragments but keeps real titles.
func TestDropFragments(t *testing.T) {
	in := []Event{
		{Title: "went smoothly. See below for the dates", Start: "2026-09-15", Kind: "event"},
		{Title: "Our first evacuation drill", Start: "2026-09-15", Kind: "event"},
		{Title: "3-407 visits the Columbus Branch", Start: "2026-10-08", Kind: "event"},
	}
	got := dropFragments(in)
	if len(got) != 2 {
		t.Fatalf("one fragment should be dropped, got %d: %+v", len(got), got)
	}
	for _, e := range got {
		if e.Title[0] >= 'a' && e.Title[0] <= 'z' {
			t.Fatalf("a fragment survived: %q", e.Title)
		}
	}
}

// TestDedupPrefersDescription: when two same-day events have the same title, the one whose
// note adds context (a description) is kept, so the useful description isn't deduped away.
func TestDedupPrefersDescription(t *testing.T) {
	in := []Event{
		{Title: "Back To School Night", Start: "2026-09-29T17:30:00", Kind: "event", Notes: "Back To School Night"},
		{Title: "Back To School Night", Start: "2026-09-29T17:30:00", Kind: "event", Notes: "Thursday Sept 29th, 5:30-8pm in the gym"},
	}
	got := dedupEvents(in)
	if len(got) != 1 {
		t.Fatalf("same-day duplicates should collapse to 1, got %d", len(got))
	}
	if got[0].Notes != "Thursday Sept 29th, 5:30-8pm in the gym" {
		t.Errorf("dedup should keep the event WITH a description, got notes %q", got[0].Notes)
	}
}

// The same event lands in two files: the events .ics with the venue, the items .ics
// with the source notes. The merged entry must keep both, whichever wins the title.
func TestDedupMergeKeepsVenueAndNotes(t *testing.T) {
	in := []Event{
		{Title: "Cozy and fun evening in The Glass House", Start: "2026-10-28 17:00", End: "2026-10-28 19:00", Location: "The Glass House (In the Lobby)", File: "x.events.ics", Kind: "event"},
		{Title: "Cozy and fun evening in The Glass House", Start: "2026-10-28 17:00", End: "2026-10-28 19:00", Notes: "join us for a cozy evening", File: "x.items.ics", Kind: "event"},
	}
	out := dedupEvents(in)
	if len(out) != 1 {
		t.Fatalf("want one merged event, got %d", len(out))
	}
	if out[0].Location != "The Glass House (In the Lobby)" || out[0].Notes != "join us for a cozy evening" {
		t.Fatalf("merge must keep the venue and the notes, got %+v", out[0])
	}
}
