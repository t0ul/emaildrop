package server

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

func itm(title, day, kind string) itemRow {
	return itemRow{Event: schema.Event{Title: title, Start: day, Kind: kind}}
}

// TestDedupItemsNearDup locks the Tasks near-dup merge: same-day items whose titles are
// subset-related collapse to one (the cleaner title wins), while distinct same-day items
// and the same title on a different day stay separate. Pure logic, no mocks.
func TestDedupItemsNearDup(t *testing.T) {
	// Subset-related on the same day → one, the fuller/cleaner title kept.
	got := dedupItems([]itemRow{
		itm("Italian Heritage Day", "2026-10-13", "heads_up"),
		itm("Italian Heritage and Indigenous Peoples' Day, schools closed", "2026-10-13", "heads_up"),
	})
	if len(got) != 1 {
		t.Fatalf("subset-related same-day items must collapse to 1, got %d: %+v", len(got), got)
	}
	if got[0].Title != "Italian Heritage and Indigenous Peoples' Day, schools closed" {
		t.Errorf("cleaner (fuller) title should win, got %q", got[0].Title)
	}

	// Exact duplicate on the same day → one.
	if got := dedupItems([]itemRow{
		itm("Picture Day", "2026-10-13", "task"),
		itm("Picture Day", "2026-10-13", "task"),
	}); len(got) != 1 {
		t.Errorf("exact same-day dup must collapse to 1, got %d", len(got))
	}

	// Distinct same-day items (not subset-related) → kept separate.
	if got := dedupItems([]itemRow{
		itm("Picture Day", "2026-10-13", "task"),
		itm("Book Fair", "2026-10-13", "task"),
	}); len(got) != 2 {
		t.Errorf("distinct same-day items must stay separate, got %d", len(got))
	}

	// Same title on different days → kept (a recurring thing).
	if got := dedupItems([]itemRow{
		itm("Picture Day", "2026-10-13", "task"),
		itm("Picture Day", "2026-10-20", "task"),
	}); len(got) != 2 {
		t.Errorf("same title on different days must stay separate, got %d", len(got))
	}

	// Blank titles are dropped.
	if got := dedupItems([]itemRow{itm("   ", "2026-10-13", "task")}); len(got) != 0 {
		t.Errorf("blank-title items must be dropped, got %d", len(got))
	}
}
