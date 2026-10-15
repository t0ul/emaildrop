package dateparse

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseTimesRangeSharedAMPM(t *testing.T) {
	// "5:30-8:00 PM": the earlier time inherits the later token's pm.
	got := ParseTimes("doors 5:30-8:00 PM in the gym")
	want := []HM{{17, 30}, {20, 0}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseTimes = %v, want %v", got, want)
	}
}

func TestParseTimesRejectsBareIntegers(t *testing.T) {
	for _, s := range []string{"Room 205", "Grades 2-5", "see page 7"} {
		if got := ParseTimes(s); len(got) != 0 {
			t.Errorf("ParseTimes(%q) = %v, want none", s, got)
		}
	}
}

// TestParseTimesRejectsOutOfRange: an impossible clock value is dropped, not silently
// rolled over by time.Date (e.g. "25:99" would have normalized to the next day).
func TestParseTimesRejectsOutOfRange(t *testing.T) {
	for _, s := range []string{"drill at 25:99", "meet at 24:00", "at 9:75", "13:00 PM"} {
		if got := ParseTimes(s); len(got) != 0 {
			t.Errorf("ParseTimes(%q) = %v, want none (out of range)", s, got)
		}
	}
	// A valid neighbor in the same string is still parsed.
	if got := ParseTimes("bad 25:99 but real 6:30 PM"); !reflect.DeepEqual(got, []HM{{18, 30}}) {
		t.Errorf("want [{18 30}], got %v", got)
	}
}

func TestParseTimesNoonMidnight(t *testing.T) {
	if got := ParseTimes("12:00 PM"); !reflect.DeepEqual(got, []HM{{12, 0}}) {
		t.Errorf("noon: got %v", got)
	}
	if got := ParseTimes("12:00 AM"); !reflect.DeepEqual(got, []HM{{0, 0}}) {
		t.Errorf("midnight: got %v", got)
	}
	if got := ParseTimes("8:30 AM"); !reflect.DeepEqual(got, []HM{{8, 30}}) {
		t.Errorf("morning: got %v", got)
	}
}

func TestWeekdayMismatchIntegrity(t *testing.T) {
	dp := ParseDatePhrase("Back to School Night, Thursday, September 29", DefaultYear)
	if dp == nil {
		t.Fatal("expected a date phrase")
	}
	if dp.ActualWeekday != "Tuesday" {
		t.Fatalf("2026-09-29 should be Tuesday, got %s", dp.ActualWeekday)
	}
	if !dp.Mismatch || dp.StatedWeekday != "Thursday" {
		t.Fatalf("expected stated Thursday mismatch, got stated=%q mismatch=%v", dp.StatedWeekday, dp.Mismatch)
	}
	if !strings.Contains(dp.Warning, "weekday_mismatch") {
		t.Errorf("warning not set: %q", dp.Warning)
	}
}

func TestExtractDatetimeWithRange(t *testing.T) {
	r := ExtractDatetime("September 29 2026 from 5:30-8:00 PM", DefaultYear)
	if r == nil {
		t.Fatal("expected a result")
	}
	if r.AllDay {
		t.Error("should not be all-day")
	}
	if r.Start != "2026-09-29T17:30:00" || r.End != "2026-09-29T20:00:00" {
		t.Fatalf("got start=%q end=%q", r.Start, r.End)
	}
}

func TestExtractDatetimeAllDayAndAssumedYear(t *testing.T) {
	r := ExtractDatetime("Picture Day is October 10", DefaultYear)
	if r == nil || !r.AllDay {
		t.Fatalf("expected an all-day result, got %+v", r)
	}
	if r.Start != "2026-10-10" {
		t.Errorf("start = %q", r.Start)
	}
	foundAssumed := false
	for _, w := range r.Warnings {
		if strings.HasPrefix(w, "assumed_year:2026") {
			foundAssumed = true
		}
	}
	if !foundAssumed {
		t.Errorf("expected assumed_year warning, got %v", r.Warnings)
	}
}

func TestInvalidDateRejected(t *testing.T) {
	if dp := ParseDatePhrase("February 30 2026", DefaultYear); dp != nil {
		t.Errorf("February 30 should be rejected, got %+v", dp)
	}
	if ExtractDatetime("the meeting on February 30", DefaultYear) != nil {
		t.Error("extract should be nil for an impossible date")
	}
}

func TestNoDate(t *testing.T) {
	if ExtractDatetime("there is no date in this sentence", DefaultYear) != nil {
		t.Error("expected nil when no date present")
	}
}

// Numeric dates: building and community emails write "Date: 10/28", not "October 28".
// They are accepted when a year is present or when the token is introduced the way a
// date is (start of the phrase, after a label colon, after "on", or after a weekday), so
// a fraction in prose ("1/2 hour") is still not a date.
func TestParseDatePhraseNumeric(t *testing.T) {
	cases := map[string]string{
		"Date: 10/28":                 "2026-10-28",
		"10/28":                       "2026-10-28",
		"on 9/10/2026 at noon":        "2026-09-10",
		"Friday 11/5 early dismissal": "2026-11-05",
		"due 12/01/26":                "2026-12-01",
	}
	for in, want := range cases {
		dp := ParseDatePhrase(in, 2026)
		if dp == nil {
			t.Errorf("ParseDatePhrase(%q) = nil, want %s", in, want)
			continue
		}
		if got := dp.Date.Format("2006-01-02"); got != want {
			t.Errorf("ParseDatePhrase(%q) = %s, want %s", in, got, want)
		}
	}
	if dp := ParseDatePhrase("on 9/10/2026", 2026); dp == nil || dp.AssumedYear {
		t.Errorf("an explicit year must not be reported as assumed: %+v", dp)
	}
	for _, in := range []string{"a 1/2 hour session", "scored 13/40", "grades 3/4 and 5", "call 555/1234", "the 0/28 case"} {
		if dp := ParseDatePhrase(in, 2026); dp != nil {
			t.Errorf("ParseDatePhrase(%q) = %s, want nil", in, dp.Date.Format("2006-01-02"))
		}
	}
}

func TestExtractDatetimeNumericWithTimes(t *testing.T) {
	r := ExtractDatetime("Date: 10/28 Time: 5PM - 7PM", 2026)
	if r == nil || r.AllDay || r.Start != "2026-10-28T17:00:00" || r.End != "2026-10-28T19:00:00" {
		t.Fatalf("want 17:00 to 19:00 on 2026-10-28, got %+v", r)
	}
	if idx := MonthDayIndex("Date: 10/28"); idx == nil || idx[0] != 6 {
		t.Fatalf("MonthDayIndex must find a numeric date, got %v", idx)
	}
}
