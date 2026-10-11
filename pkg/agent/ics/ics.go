// Package ics generates an inert iCalendar (.ics) artifact and sanitizes every
// field (Module 5: improper output handling). The .ics executes nothing — the
// user accepts it by double-click — but event fields are an exfiltration
// surface (a URL in NOTES/LOCATION can beacon when a client renders it), so we
// strip links and active schemes from every field, and escape per RFC 5545 so
// content can't break the line structure (the calendar analog of the
// markdown-image sanitizer).
package ics

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

var (
	reURL    = regexp.MustCompile(`(?i)\b(?:https?|ftp)://\S+`)
	reScheme = regexp.MustCompile(`(?i)\b(?:javascript|data|file|vbscript):\S+`)
)

// SanitizeField strips exfil vectors from a field and returns the cleaned value
// plus how many links/schemes were removed.
func SanitizeField(value string) (string, int) {
	if value == "" {
		return "", 0
	}
	removed := len(reURL.FindAllString(value, -1)) + len(reScheme.FindAllString(value, -1))
	value = reURL.ReplaceAllString(value, "[link removed]")
	value = reScheme.ReplaceAllString(value, "[blocked]")
	return value, removed
}

// escape applies RFC 5545 text escaping. Order matters: backslash first, then
// the structural characters, then any newline folded to a literal \n so a field
// can never inject a new content line.
func escape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, ";", `\;`)
	value = strings.ReplaceAll(value, ",", `\,`)
	value = strings.ReplaceAll(value, "\r\n", `\n`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, "\r", `\n`)
	return value
}

// sanitizeRRULE admits only a well-formed iCalendar recurrence rule (uppercase
// keywords, digits, and the RRULE separators = ; ,). It must begin FREQ= or it is
// dropped, so an attacker can't smuggle extra ICS lines/props through the field.
func sanitizeRRULE(r string) string {
	r = strings.ToUpper(strings.TrimSpace(r))
	if !strings.HasPrefix(r, "FREQ=") {
		return ""
	}
	for _, c := range r {
		ok := (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '=' || c == ';' || c == ','
		if !ok {
			return ""
		}
	}
	return r
}

func formatDT(value string, allDay bool) (string, error) {
	if allDay {
		if len(value) < 10 {
			return "", fmt.Errorf("ics: bad all-day date %q", value)
		}
		d, err := time.Parse("2006-01-02", value[:10])
		if err != nil {
			return "", err
		}
		return d.Format("20060102"), nil
	}
	t, err := time.Parse("2006-01-02T15:04:05", value)
	if err != nil {
		return "", err
	}
	return t.Format("20060102T150405"), nil
}

func uid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fail to a time-based id rather than an all-zero (colliding) UID.
		return fmt.Sprintf("%d@email-to-calendar", time.Now().UnixNano())
	}
	return hex.EncodeToString(b) + "@email-to-calendar"
}

// Write renders events to an inert .ics. It returns the text (CRLF line
// endings, per RFC 5545) and the total number of links/schemes removed.
func Write(events []schema.Event, calname string) (string, int, error) {
	now := time.Now().UTC().Format("20060102T150405Z")
	removedTotal := 0
	lines := []string{
		"BEGIN:VCALENDAR",
		"VERSION:2.0",
		"PRODID:-//ai-security-engineering//email-to-calendar//EN",
		"X-WR-CALNAME:" + escape(calname),
	}
	for _, ev := range events {
		var r int
		var err error
		switch ev.ResolvedKind() {
		case schema.KindTask, schema.KindAction:
			r, err = writeVTodo(&lines, ev, now) // a to-do / actionable item
		default:
			r, err = writeVEvent(&lines, ev, now) // event or heads-up
		}
		if err != nil {
			return "", removedTotal, err
		}
		removedTotal += r
	}
	lines = append(lines, "END:VCALENDAR")
	return strings.Join(lines, "\r\n") + "\r\n", removedTotal, nil
}

// writeVEvent emits a VEVENT for a meeting (KindEvent) or a heads-up
// (KindHeadsUp, forced all-day with a day-before alarm).
func writeVEvent(lines *[]string, ev schema.Event, now string) (int, error) {
	title, r1 := SanitizeField(orUntitled(ev.Title))
	location, r2 := SanitizeField(ev.Location)
	removed := r1 + r2

	headsUp := ev.ResolvedKind() == schema.KindHeadsUp
	allDay := ev.AllDay || headsUp

	*lines = append(*lines, "BEGIN:VEVENT", "UID:"+uid(), "DTSTAMP:"+now, "X-KIND:"+ev.ResolvedKind())
	if allDay {
		dt, err := formatDT(ev.Start, true)
		if err != nil {
			return removed, err
		}
		*lines = append(*lines, "DTSTART;VALUE=DATE:"+dt)
	} else {
		dt, err := formatDT(ev.Start, false)
		if err != nil {
			return removed, err
		}
		*lines = append(*lines, "DTSTART:"+dt)
		if ev.End != "" {
			de, err := formatDT(ev.End, false)
			if err != nil {
				return removed, err
			}
			*lines = append(*lines, "DTEND:"+de)
		}
	}
	*lines = append(*lines, "SUMMARY:"+escape(title))
	if location != "" {
		*lines = append(*lines, "LOCATION:"+escape(location))
	}
	if r := sanitizeRRULE(ev.Recur); r != "" {
		*lines = append(*lines, "RRULE:"+r) // recurring event (R3/R6 half-day/RRULE)
	}
	removed += appendDescription(lines, ev)

	// Inert DISPLAY alarm: 30m before a timed event; 9am for an all-day event;
	// 9am the day before for a heads-up (so you have time to prepare).
	trigger := "-PT30M"
	if headsUp {
		trigger = "-PT15H" // 15h before 00:00 = 09:00 the previous day
	} else if allDay {
		trigger = "PT9H"
	}
	appendAlarm(lines, title, trigger)
	*lines = append(*lines, "END:VEVENT")
	return removed, nil
}

// writeVTodo emits a VTODO for a task (KindTask) or an actionable item
// (KindAction, which also carries a validated URL).
func writeVTodo(lines *[]string, ev schema.Event, now string) (int, error) {
	title, removed := SanitizeField(orUntitled(ev.Title))

	due := ev.Due
	if due == "" {
		due = ev.Start
	}
	*lines = append(*lines, "BEGIN:VTODO", "UID:"+uid(), "DTSTAMP:"+now, "X-KIND:"+ev.ResolvedKind())
	if due != "" {
		if ev.AllDay {
			dt, err := formatDT(due, true)
			if err != nil {
				return removed, err
			}
			*lines = append(*lines, "DUE;VALUE=DATE:"+dt)
		} else {
			dt, err := formatDT(due, false)
			if err != nil {
				return removed, err
			}
			*lines = append(*lines, "DUE:"+dt)
		}
	}
	*lines = append(*lines, "SUMMARY:"+escape(title), "STATUS:NEEDS-ACTION")
	removed += appendDescription(lines, ev)

	// Action URL: kept (the link is the whole point), but ONLY if it is a valid
	// http(s) URL — so it is NOT run through SanitizeField's link stripper. The
	// click itself is egress-gated by netpolicy + fetched in the VM at action
	// time (see APP-FEATURES-PLAN A6); this only records a well-formed target.
	if ev.ResolvedKind() == schema.KindAction && ev.URL != "" {
		if u, err := url.Parse(strings.TrimSpace(ev.URL)); err == nil &&
			(u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			*lines = append(*lines, "URL:"+escape(ev.URL))
		}
	}

	// An alarm is only meaningful relative to a DUE date; a dateless to-do just
	// sits in the list with no reminder.
	if due != "" {
		trigger := "-PT30M"
		if ev.AllDay {
			trigger = "-PT15H" // 09:00 the day before the due date
		}
		appendAlarm(lines, title, trigger)
	}
	*lines = append(*lines, "END:VTODO")
	return removed, nil
}

// appendDescription writes a DESCRIPTION from Notes + any warnings (sanitized).
func appendDescription(lines *[]string, ev schema.Event) int {
	removed := 0
	var parts []string
	if ev.Notes != "" {
		n, r := SanitizeField(ev.Notes)
		removed += r
		parts = append(parts, n)
	}
	if len(ev.Warnings) > 0 {
		w, r := SanitizeField(strings.Join(ev.Warnings, " | "))
		removed += r
		parts = append(parts, "⚠ "+w)
	}
	if len(parts) > 0 {
		*lines = append(*lines, "DESCRIPTION:"+escape(strings.Join(parts, " — ")))
	}
	return removed
}

func appendAlarm(lines *[]string, title, trigger string) {
	*lines = append(*lines,
		"BEGIN:VALARM",
		"ACTION:DISPLAY",
		"DESCRIPTION:"+escape(title),
		"TRIGGER:"+trigger,
		"END:VALARM")
}

func orUntitled(s string) string {
	if s == "" {
		return "Untitled"
	}
	return s
}
