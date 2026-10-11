package extractor_test

import (
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/extractor"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
	"github.com/t0ul/emaildrop/pkg/agent/tool"
)

const sampleEmail = `PS 123 Family Newsletter

Back to School Night: Thursday, September 29th at 6:00 PM in the auditorium
Please refer to the earlier email we sent on September 18 for more details.

Days Off / No School:
Monday, October 12th - Italian Heritage Day
Wednesday, November 11th - Veterans Day. Offices closed.

Picture Day: October 10th
`

func find(events []schema.Event, titleContains string) *schema.Event {
	for i := range events {
		if strings.Contains(events[i].Title, titleContains) {
			return &events[i]
		}
	}
	return nil
}

func TestExtractEventsRegex(t *testing.T) {
	events := extractor.ExtractEvents(sampleEmail, "sample", 2026)

	bts := find(events, "Back to School Night")
	if bts == nil {
		t.Fatalf("missing Back to School Night; got %+v", titles(events))
	}
	if bts.Start != "2026-09-29T18:00:00" || bts.AllDay {
		t.Errorf("BTS night date wrong: start=%q allDay=%v", bts.Start, bts.AllDay)
	}
	if !hasWarn(bts.Warnings, "weekday_mismatch") {
		t.Errorf("expected weekday_mismatch warning, got %v", bts.Warnings)
	}

	pic := find(events, "Picture Day")
	if pic == nil || pic.Start != "2026-10-10" || !pic.AllDay {
		t.Errorf("Picture Day wrong: %+v", pic)
	}

	// The prose "Please refer to the email ... September 18" is a date REFERENCE,
	// not an event, and must be rejected.
	if ref := find(events, "refer"); ref != nil {
		t.Errorf("prose date reference was wrongly extracted: %+v", ref)
	}
}

func TestExtractDaysOff(t *testing.T) {
	net := extractor.ExtractDaysOff(sampleEmail, "sample", 2026)
	if len(net) != 2 {
		t.Fatalf("expected 2 days-off events, got %d: %v", len(net), titles(net))
	}
	ital := find(net, "Italian Heritage Day")
	if ital == nil || ital.Start != "2026-10-12" || !ital.AllDay || ital.Confidence != 0.8 {
		t.Errorf("Italian Heritage Day wrong: %+v", ital)
	}
	vet := find(net, "Veterans Day")
	if vet == nil || vet.Start != "2026-11-11" {
		t.Errorf("Veterans Day wrong: %+v", vet)
	}
	// "first clause only": the trailing ". Offices closed." must be dropped.
	if vet != nil && strings.Contains(vet.Title, "Offices") {
		t.Errorf("days-off title kept a second clause: %q", vet.Title)
	}
}

func TestRunRegexModeMergesNetAndWritesICS(t *testing.T) {
	ex := extractor.New()
	if ex.Name() != "event_extractor" || ex.Capability() != tool.WriteICS {
		t.Fatalf("contract wrong: name=%s cap=%s", ex.Name(), ex.Capability())
	}
	res := ex.Run(sampleEmail, tool.Ctx{Source: "sample.txt", DefaultYear: 2026, Mode: "regex"})

	// 09-29 + 10-10 from the regex pass, 10-12 + 11-11 from the authoritative net.
	if len(res.Events) != 4 {
		t.Fatalf("expected 4 merged events, got %d: %v", len(res.Events), titles(res.Events))
	}
	// sorted by start
	for i := 1; i < len(res.Events); i++ {
		if res.Events[i-1].Start > res.Events[i].Start {
			t.Errorf("events not sorted by start: %v", titles(res.Events))
		}
	}
	ics := res.Artifacts["events.ics"]
	if !strings.Contains(ics, "BEGIN:VCALENDAR") || strings.Count(ics, "BEGIN:VEVENT") != 4 {
		t.Errorf("ics artifact wrong: %d VEVENTs", strings.Count(ics, "BEGIN:VEVENT"))
	}
	if !hasWarn(res.Warnings, "extractor_mode=regex") {
		t.Errorf("missing extractor_mode warning: %v", res.Warnings)
	}
	if !hasWarn(res.Warnings, "days-off net authoritative on 2 date(s)") {
		t.Errorf("missing days-off net warning: %v", res.Warnings)
	}
}

func titles(events []schema.Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Title + "@" + e.Start
	}
	return out
}

func hasWarn(ws []string, substr string) bool {
	for _, w := range ws {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}
