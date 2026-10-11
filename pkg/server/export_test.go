package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/ics"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
	"github.com/t0ul/emaildrop/pkg/datastore"
)

// TestCalendarExportCombinesEventsAndReminders: the one-click export returns a single .ics
// with events as VEVENTs and reminders (tasks) as all-day VEVENTs prefixed "Reminder:" —
// never VTODO, which Google Calendar ignores. Real outbox .ics, real handler, no mocks.
func TestCalendarExportCombinesEventsAndReminders(t *testing.T) {
	dir := t.TempDir()
	src := []schema.Event{
		{Title: "Picture Day", Start: "2026-10-13", AllDay: true, Kind: schema.KindEvent},
		{Title: "Bring a dish", Due: "2026-10-20", AllDay: true, Kind: schema.KindTask},
	}
	body, _, err := ics.Write(src, "seed")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "7.items.ics"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(New(Config{OutboxDir: dir}).Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/calendar.ics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/calendar") {
		t.Errorf("want a calendar content-type, got %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "family-calendar.ics") {
		t.Errorf("want an attachment filename, got %q", cd)
	}
	b, _ := io.ReadAll(resp.Body)
	out := string(b)
	if !strings.Contains(out, "Picture Day") {
		t.Error("the event is missing from the export")
	}
	if !strings.Contains(out, "Reminder: Bring a dish") {
		t.Error("the reminder is missing or not prefixed in the export")
	}
	if strings.Contains(out, "BEGIN:VTODO") {
		t.Error("reminders must be exported as VEVENTs, not VTODO (Google Calendar ignores VTODO)")
	}
}

// TestCalendarIncrementalExport: the first "download new" export includes everything and marks
// it; a second export returns nothing new; resetting makes everything new again. Real SQLite.
func TestCalendarIncrementalExport(t *testing.T) {
	dir := t.TempDir()
	src := []schema.Event{
		{Title: "Picture Day", Start: "2026-10-13", AllDay: true, Kind: schema.KindEvent},
		{Title: "Book Fair", Start: "2026-10-20", AllDay: true, Kind: schema.KindEvent},
	}
	body, _, err := ics.Write(src, "seed")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1.events.ics"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := datastore.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()

	srv := httptest.NewServer(New(Config{OutboxDir: dir, Exported: inv}).Handler())
	defer srv.Close()
	count := func(path string) string {
		r, err := http.Post(srv.URL+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		_, _ = io.ReadAll(r.Body)
		return r.Header.Get("X-New-Count")
	}
	if c := count("/api/calendar/export"); c != "2" {
		t.Fatalf("first export should have 2 new events, got %q", c)
	}
	if c := count("/api/calendar/export"); c != "0" {
		t.Fatalf("second export should have 0 new (already exported), got %q", c)
	}
	count("/api/calendar/reset-exported")
	if c := count("/api/calendar/export"); c != "2" {
		t.Fatalf("after reset, export should have 2 new again, got %q", c)
	}
}

// TestCalendarExportIsValidICS validates the exported .ics against RFC-5545 essentials,
// INDEPENDENTLY of the writer that produced it — the structure Google/Apple Calendar require
// to import cleanly. This is the safe proxy for "does it import?": if these hold, it imports,
// so there is no need to test on a real calendar. Covers a timed event, an all-day closure,
// and a reminder (which must be a VEVENT, not a VTODO).
func TestCalendarExportIsValidICS(t *testing.T) {
	dir := t.TempDir()
	src := []schema.Event{
		{Title: "Back To School Night", Start: "2026-09-29T17:30:00", End: "2026-09-29T20:00:00", Kind: schema.KindEvent},
		{Title: "Yom Kippur, schools closed", Start: "2026-09-21", AllDay: true, Kind: schema.KindEvent},
		{Title: "Bring a dish", Due: "2026-10-20", AllDay: true, Kind: schema.KindTask},
	}
	body, _, err := ics.Write(src, "seed")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1.events.ics"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{OutboxDir: dir}).Handler())
	defer srv.Close()
	r, err := http.Get(srv.URL + "/api/calendar.ics")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	out := string(b)

	// VCALENDAR envelope + version.
	if !strings.HasPrefix(out, "BEGIN:VCALENDAR\r\n") {
		t.Error("must start with BEGIN:VCALENDAR and CRLF")
	}
	if !strings.Contains(out, "VERSION:2.0\r\n") {
		t.Error("missing VERSION:2.0")
	}
	if !strings.HasSuffix(out, "END:VCALENDAR\r\n") {
		t.Error("must end with END:VCALENDAR + CRLF")
	}
	// CRLF line endings throughout — strict parsers reject bare LF.
	for _, ln := range strings.Split(out, "\r\n") {
		if strings.Contains(ln, "\n") {
			t.Errorf("a line uses a bare LF instead of CRLF: %q", ln)
		}
	}
	// Balanced blocks; reminders are VEVENTs, never VTODO (Google ignores VTODO).
	if nB, nE := strings.Count(out, "BEGIN:VEVENT"), strings.Count(out, "END:VEVENT"); nB == 0 || nB != nE {
		t.Fatalf("unbalanced VEVENT blocks: %d BEGIN vs %d END", nB, nE)
	}
	if strings.Contains(out, "BEGIN:VTODO") {
		t.Error("reminders must be exported as VEVENTs, not VTODO")
	}
	// Every VEVENT carries the properties a calendar needs, and UIDs are unique (a duplicate
	// UID makes an import silently drop or overwrite events).
	uidRE := regexp.MustCompile(`UID:([^\r\n]+)`)
	uids := map[string]bool{}
	for _, blk := range strings.Split(out, "BEGIN:VEVENT\r\n")[1:] {
		ev := blk[:strings.Index(blk, "END:VEVENT")]
		for _, req := range []string{"UID:", "DTSTAMP:", "DTSTART", "SUMMARY:"} {
			if !strings.Contains(ev, req) {
				t.Errorf("a VEVENT is missing required property %q:\n%s", req, ev)
			}
		}
		if m := uidRE.FindStringSubmatch(ev); m != nil {
			if uids[m[1]] {
				t.Errorf("duplicate UID %q — would corrupt a calendar import", m[1])
			}
			uids[m[1]] = true
		}
	}
	// The actual events are present with the right dates/shape.
	for _, want := range []string{
		"SUMMARY:Back To School Night", "DTSTART:20260929T173000", "DTEND:20260929T200000",
		"SUMMARY:Yom Kippur\\, schools closed", "DTSTART;VALUE=DATE:20260921",
		"SUMMARY:Reminder: Bring a dish", "DTSTART;VALUE=DATE:20261020",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("export is missing expected line %q", want)
		}
	}
}

// TestCalendarIncrementalAcrossNewEmails is the real usage loop that protects your personal
// calendar: as new school emails arrive (re-mentioning old events AND adding new ones), the
// "download new" export yields ONLY the genuinely new events — so re-importing never creates
// duplicates. Real SQLite, real outbox files, real handlers.
func TestCalendarIncrementalAcrossNewEmails(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, evs []schema.Event) {
		body, _, err := ics.Write(evs, "seed")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := datastore.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	srv := httptest.NewServer(New(Config{OutboxDir: dir, Exported: inv}).Handler())
	defer srv.Close()
	exportNew := func() (int, string) {
		r, err := http.Post(srv.URL+"/api/calendar/export", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		n, _ := strconv.Atoi(r.Header.Get("X-New-Count"))
		return n, string(b)
	}

	// Email 1 arrives with one event; the first export includes it.
	write("1.events.ics", []schema.Event{{Title: "Picture Day", Start: "2026-10-13", AllDay: true, Kind: schema.KindEvent}})
	if n, out := exportNew(); n != 1 || !strings.Contains(out, "Picture Day") {
		t.Fatalf("first export should contain the one event, got n=%d", n)
	}

	// Email 2 arrives: it re-mentions Picture Day (a duplicate) AND adds Book Fair.
	write("2.events.ics", []schema.Event{
		{Title: "Picture Day", Start: "2026-10-13", AllDay: true, Kind: schema.KindEvent},
		{Title: "Book Fair", Start: "2026-10-20", AllDay: true, Kind: schema.KindEvent},
	})
	n, out := exportNew()
	if n != 1 {
		t.Fatalf("after the new email, exactly 1 new event should export, got %d", n)
	}
	if !strings.Contains(out, "Book Fair") || strings.Contains(out, "Picture Day") {
		t.Errorf("incremental export must contain ONLY the new Book Fair, never the already-exported Picture Day:\n%s", out)
	}

	// Nothing else arrives: a further export yields nothing.
	if n, _ := exportNew(); n != 0 {
		t.Errorf("with no new emails, export should be empty, got %d", n)
	}
}

// TestParseICSIgnoresAlarmDescription locks the fix for the root cause of "descriptions not
// showing": a VEVENT's VALARM carries its own DESCRIPTION (the alarm text = the title), and
// parseICS must not let that overwrite the event's real DESCRIPTION.
func TestParseICSIgnoresAlarmDescription(t *testing.T) {
	dir := t.TempDir()
	src := []schema.Event{{Title: "Back To School Night", Start: "2026-09-29T17:30:00", Kind: schema.KindEvent,
		Notes: "Thursday Sept 29th, 5:30-8pm in the gym"}}
	body, _, err := ics.Write(src, "seed")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1.events.ics"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{OutboxDir: dir}).Handler())
	defer srv.Close()
	r, err := http.Get(srv.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var d struct {
		Events []map[string]any `json:"events"`
	}
	_ = json.NewDecoder(r.Body).Decode(&d)
	if len(d.Events) != 1 {
		t.Fatalf("want 1 event, got %d", len(d.Events))
	}
	if got := d.Events[0]["notes"]; got != "Thursday Sept 29th, 5:30-8pm in the gym" {
		t.Errorf("event notes should be the event DESCRIPTION, not the alarm text; got %q", got)
	}
}
