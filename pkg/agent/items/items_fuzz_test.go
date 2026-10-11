package items_test

import (
	"testing"

	"github.com/t0ul/ADD"
	"github.com/t0ul/emaildrop/pkg/agent/items"
)

// FuzzClassifyNoPanic hunts for an email body that panics or hangs the
// line/sentence/date regex pipeline (robustness of the deterministic extractor).
func FuzzClassifyNoPanic(f *testing.F) {
	seeds := []string{
		sample,
		"",
		"\n\n\n",
		"October 5",
		"PS 51 PTA Potluck Friday October 23rd from 5:30-:00 PM! 💛",
		"Upcoming Evacuation Drills\nThursday, October 1st at 10:08 AM\n",
		"- - - • ● Please bring a dish by September 30th.",
	}
	add.FuzzInvariant(f, seeds, func(t *testing.T, in string) {
		_ = items.Classify(in, 2026) // a panic/hang is the failure the fuzzer reports
	})
}
