package extractor

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

func TestAnnouncedEvent(t *testing.T) {
	keep := []schema.Event{
		{Title: "Parent-Teacher Conferences", Start: "2026-11-05"}, // 2+ real words
		{Title: "Back-to-School Night", Start: "2026-09-29"},       // hyphenated name
		{Title: "Picnic", Start: "2026-10-15T12:00:00"},            // has a time
	}
	for _, e := range keep {
		if !announcedEvent(e) {
			t.Errorf("should keep announced event %q", e.Title)
		}
	}
	drop := []schema.Event{
		{Title: "September 8", Start: "2026-09-08"},           // a bare prose date
		{Title: "began", Start: "2026-09-08"},                 // single weak word, no time
		{Title: "The school year began", Start: "2026-09-08"}, // a narrative sentence, not an event
	}
	for _, e := range drop {
		if announcedEvent(e) {
			t.Errorf("should drop prose-date event %q on a reference doc", e.Title)
		}
	}
}
