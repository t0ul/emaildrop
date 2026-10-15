// Package dateparse is deterministic date/time parsing + integrity checking
// (Module 9). School emails bury dates in prose, omit the year, and sometimes
// state the WRONG weekday (the real corpus lists Back-to-School Night as both
// Tuesday and Thursday, Sept 29). We never trust an LLM's date arithmetic: a
// model may propose the text span, but normalization and the weekday-vs-date
// consistency check happen here, deterministically, in the standard library.
package dateparse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultYear is assumed when a phrase omits the year.
const DefaultYear = 2026

var months = map[string]int{
	"january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
	"july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
}

// weekdays is Monday-indexed to mirror Python's date.weekday() (Monday == 0).
var weekdays = []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}

var wdIndex = func() map[string]int {
	m := make(map[string]int, 7)
	for i, w := range weekdays {
		m[strings.ToLower(w)] = i
	}
	return m
}()

const (
	monthsAlt   = `January|February|March|April|May|June|July|August|September|October|November|December`
	weekdaysAlt = `Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday`
)

var (
	reWeekday  = regexp.MustCompile(`(?i)\b(` + weekdaysAlt + `)\b`)
	reMonthDay = regexp.MustCompile(`(?i)\b(` + monthsAlt + `)\s+(\d{1,2})(?:st|nd|rd|th)?\b`)
	reYear     = regexp.MustCompile(`\b(20\d{2})\b`)
	// A numeric date, "10/28", "9/10/2026" or "12/01/26". Community and building emails
	// write dates this way; school newsletters almost never do. Because "1/2 hour" and
	// "scored 13/40" look the same, a numeric date counts only when it is introduced
	// the way a date is: see numericDate.
	reNumDate = regexp.MustCompile(`\b(\d{1,2})/(\d{1,2})(?:/(\d{4}|\d{2}))?\b`)
	// What may stand right before a numeric date: nothing (start of the phrase), a
	// label colon ("Date: 10/28"), "on", "by", "due", "until", or a weekday name.
	reNumDateLead = regexp.MustCompile(`(?i)(?:^|:|\b(?:on|by|due|until|through|from|to|` + weekdaysAlt + `),?)\s*$`)
	// A time token: hour, optional :minutes, optional am/pm. A token counts as a
	// TIME only if it has minutes (a colon) or an am/pm marker, so bare integers
	// ("Room 205", "Grades 2-5") are never mistaken for times.
	reTimeTok = regexp.MustCompile(`(?i)\b(\d{1,2})(?::(\d{2}))?\s*([ap]\.?m\.?)?`)
)

// HM is an hour (0..23) and minute (0..59).
type HM struct {
	Hour   int
	Minute int
}

func normAMPM(s string) string {
	if s == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(s), "p") {
		return "pm"
	}
	return "am"
}

// ParseTimes returns the time tokens in order. It handles ranges where am/pm is
// written once, e.g. "5:30-8:00 PM" -> 17:30 and 20:00 (the earlier time
// inherits the later token's am/pm).
func ParseTimes(text string) []HM {
	type tok struct {
		h, mi int
		ap    string
	}
	var toks []tok
	for _, m := range reTimeTok.FindAllStringSubmatch(text, -1) {
		hStr, miStr, apStr := m[1], m[2], m[3]
		if miStr == "" && apStr == "" {
			continue // bare integer, not a time
		}
		h, _ := strconv.Atoi(hStr)
		mi := 0
		if miStr != "" {
			mi, _ = strconv.Atoi(miStr)
		}
		ap := normAMPM(apStr)
		// Reject impossible clock values rather than letting time.Date silently roll
		// them over (e.g. "25:99" would normalize to the next day +1h39m). Minute 0..59;
		// with am/pm the hour is 1..12, otherwise 0..23.
		if mi > 59 || h > 23 || (ap != "" && (h < 1 || h > 12)) {
			continue
		}
		toks = append(toks, tok{h: h, mi: mi, ap: ap})
	}
	// Back-fill a missing am/pm from the next token that has one.
	next := ""
	for i := len(toks) - 1; i >= 0; i-- {
		if toks[i].ap == "" {
			toks[i].ap = next
		} else {
			next = toks[i].ap
		}
	}
	out := make([]HM, 0, len(toks))
	for _, t := range toks {
		hour := t.h
		switch {
		case t.ap == "pm" && t.h < 12:
			hour = t.h + 12
		case t.ap == "am" && t.h == 12:
			hour = 0
		}
		out = append(out, HM{Hour: hour, Minute: t.mi})
	}
	return out
}

// DatePhrase is the resolved date for a phrase plus its integrity flags.
type DatePhrase struct {
	Date          time.Time
	StatedWeekday string
	ActualWeekday string
	Mismatch      bool
	Warning       string
	AssumedYear   bool
}

func canonWeekday(s string) string {
	if i, ok := wdIndex[strings.ToLower(s)]; ok {
		return weekdays[i]
	}
	return ""
}

// numericDate finds the first "M/D", "M/D/YYYY" or "M/D/YY" in text that is
// introduced like a date (reNumDateLead) and has a possible month and day. It
// returns the match offsets, the parts and whether a year was written.
func numericDate(text string) (idx []int, month, day, year int, hasYear bool) {
	for _, m := range reNumDate.FindAllStringSubmatchIndex(text, -1) {
		if !reNumDateLead.MatchString(text[:m[0]]) {
			continue
		}
		mo, _ := strconv.Atoi(text[m[2]:m[3]])
		d, _ := strconv.Atoi(text[m[4]:m[5]])
		if mo < 1 || mo > 12 || d < 1 || d > 31 {
			continue
		}
		y, hy := 0, false
		if m[6] >= 0 {
			y, _ = strconv.Atoi(text[m[6]:m[7]])
			if m[7]-m[6] == 2 {
				y += 2000
			}
			hy = true
		}
		return m[0:2], mo, d, y, hy
	}
	return nil, 0, 0, 0, false
}

// ParseDatePhrase pulls month/day (+ optional stated weekday, optional explicit
// year) from a phrase, returning the resolved date and an integrity flag, or nil
// if no date is present (or the date is impossible, e.g. February 30). A written
// month ("October 28") wins; a numeric date ("10/28") is the fallback.
func ParseDatePhrase(text string, defaultYear int) *DatePhrase {
	var month, day int
	year := defaultYear
	assumedYear := true
	if md := reMonthDay.FindStringSubmatch(text); md != nil {
		month = months[strings.ToLower(md[1])]
		day, _ = strconv.Atoi(md[2])
		if ym := reYear.FindStringSubmatch(text); ym != nil {
			year, _ = strconv.Atoi(ym[1])
			assumedYear = false
		}
	} else if idx, mo, d, y, hasYear := numericDate(text); idx != nil {
		month, day = mo, d
		if hasYear {
			year, assumedYear = y, false
		}
	} else {
		return nil
	}

	d := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	if d.Year() != year || int(d.Month()) != month || d.Day() != day {
		return nil // time.Date normalizes; reject what Python's date() would refuse
	}

	statedWd := ""
	if w := reWeekday.FindStringSubmatch(text); w != nil {
		statedWd = canonWeekday(w[1])
	}
	actualWd := weekdays[(int(d.Weekday())+6)%7] // Go Sunday==0 -> Monday-indexed
	mismatch := statedWd != "" && statedWd != actualWd
	warning := ""
	if mismatch {
		warning = fmt.Sprintf("weekday_mismatch: stated %s, but %s is %s",
			statedWd, d.Format("2006-01-02"), actualWd)
	}
	return &DatePhrase{
		Date: d, StatedWeekday: statedWd, ActualWeekday: actualWd,
		Mismatch: mismatch, Warning: warning, AssumedYear: assumedYear,
	}
}

// Result is phrase -> start/end ISO strings + all-day flag + warnings.
type Result struct {
	Start    string
	End      string
	AllDay   bool
	Warnings []string
}

// ExtractDatetime resolves a phrase into a Result, or nil when it has no date.
func ExtractDatetime(phrase string, defaultYear int) *Result {
	dp := ParseDatePhrase(phrase, defaultYear)
	if dp == nil {
		return nil
	}
	d := dp.Date
	times := ParseTimes(phrase)
	warnings := []string{}
	if dp.Warning != "" {
		warnings = append(warnings, dp.Warning)
	}
	if dp.AssumedYear {
		warnings = append(warnings, fmt.Sprintf("assumed_year:%d", d.Year()))
	}

	if len(times) == 0 {
		return &Result{Start: d.Format("2006-01-02"), End: "", AllDay: true, Warnings: warnings}
	}

	start := time.Date(d.Year(), d.Month(), d.Day(), times[0].Hour, times[0].Minute, 0, 0, time.UTC)
	res := &Result{Start: start.Format("2006-01-02T15:04:05"), AllDay: false, Warnings: warnings}
	if len(times) > 1 {
		end := time.Date(d.Year(), d.Month(), d.Day(), times[1].Hour, times[1].Minute, 0, 0, time.UTC)
		res.End = end.Format("2006-01-02T15:04:05")
	}
	return res
}

// MonthDayIndex returns the [start,end] byte offsets of the first date in s, a
// "Month Day" phrase or a numeric "M/D", or nil if none. Byte offsets land on
// rune boundaries, so slicing s at them yields the same text Python's codepoint
// indices would.
func MonthDayIndex(s string) []int {
	if idx := reMonthDay.FindStringIndex(s); idx != nil {
		return idx
	}
	idx, _, _, _, _ := numericDate(s)
	return idx
}

// WeekdayIndex returns the [start,end] byte offsets of the first weekday name, or nil.
func WeekdayIndex(s string) []int { return reWeekday.FindStringIndex(s) }
