package server

import "strings"

// dedupEvents collapses duplicate events the calendar and timeline aggregate across
// multiple .ics files (the event extractor and the item extractor can both emit the
// same real event, sometimes with a different or fabricated time — e.g. an all-day
// drill and the same drill mis-timed at 22:27). The rule is per-DAY: two events of
// the SAME KIND on the SAME DAY whose normalized titles match collapse to one. That
// catches same-day/different-time duplicates (the common noise) while keeping events
// and tasks distinct (a dated to-do is not the calendar event) and keeping the same
// event on different days (a recurring drill). The cleaner, better-dated entry wins.
func dedupEvents(in []Event) []Event {
	keep := make([]Event, 0, len(in))
	for _, e := range in {
		ne := normTitle(e.Title)
		merged := false
		for j := range keep {
			if !sameDay(e, keep[j]) {
				continue
			}
			nk := normTitle(keep[j].Title)
			if ne == "" || nk == "" || ne == nk || strings.Contains(nk, ne) || strings.Contains(ne, nk) || titleSubset(e.Title, keep[j].Title) {
				keep[j] = betterEvent(e, keep[j])
				merged = true
				break
			}
		}
		if !merged {
			keep = append(keep, e)
		}
	}
	return keep
}

// sameDay reports whether two events are the same kind on the same calendar day
// (ignoring the time of day, so a fabricated time doesn't dodge dedup).
func sameDay(a, b Event) bool {
	if a.Kind != b.Kind {
		return false
	}
	da, db := dayOf(a), dayOf(b)
	return da != "" && da == db
}

// dayOf is an event's date (yyyy-mm-dd), from Start or, for dated tasks, Due.
func dayOf(e Event) string {
	d := e.Start
	if d == "" {
		d = e.Due
	}
	if len(d) >= 10 {
		return d[:10]
	}
	return d
}

// betterEvent picks the keeper when two same-day duplicates merge: the cleaner title
// wins, then the one whose description adds context (a note that is more than the title),
// then an all-day entry beats a timed one (a school event mis-stamped with a time like
// 22:27 is noise), then the one carrying a reminder.
// betterEvent picks the entry to keep when two describe the same event, then
// fills what the winner lacks from the loser: the venue, the end time and the
// source notes live in whichever file had them (the events .ics carries the
// location, the items .ics the description), and merging must not lose either.
func betterEvent(a, b Event) Event {
	w, l := pickEvent(a, b), a
	if w.File == a.File && w.Title == a.Title && w.Start == a.Start {
		l = b
	}
	if w.Location == "" {
		w.Location = l.Location
	}
	if w.End == "" && !w.AllDay {
		w.End = l.End
	}
	if w.Notes == "" {
		w.Notes = l.Notes
	}
	w.HasReminder = w.HasReminder || l.HasReminder
	return w
}

func pickEvent(a, b Event) Event {
	if sa, sb := titleScore(a), titleScore(b); sa != sb {
		if sa > sb {
			return a
		}
		return b
	}
	if an, bn := hasDescription(a), hasDescription(b); an != bn {
		if an {
			return a
		}
		return b
	}
	if a.AllDay != b.AllDay {
		if a.AllDay {
			return a
		}
		return b
	}
	if a.HasReminder && !b.HasReminder {
		return a
	}
	return b
}

// hasDescription reports whether an event's note adds information beyond its title.
func hasDescription(e Event) bool {
	n := strings.TrimSpace(e.Notes)
	return n != "" && !strings.EqualFold(n, strings.TrimSpace(e.Title))
}

// titleTokens is the set of significant word tokens in a title — lowercased, split on
// non-alphanumerics, with filler and "schools closed"-style status words dropped — so two
// phrasings of the same event compare by their meaningful words.
func titleTokens(t string) map[string]bool {
	stop := map[string]bool{"and": true, "the": true, "for": true, "of": true, "a": true,
		"to": true, "in": true, "on": true, "schools": true, "school": true, "closed": true, "no": true}
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(t), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		if len(w) >= 2 && !stop[w] {
			out[w] = true
		}
	}
	return out
}

// titleSubset reports whether one title's significant tokens are a subset of the other's
// (both non-empty). Same-day events whose names are subset-related are the same event with
// different wording ("Italian Heritage/Indigenous Peoples' Day" vs "Italian Heritage and
// Indigenous Peoples' Day, schools closed"), but two distinct same-day events (e.g. middle-
// vs high-school conferences) are NOT subset-related, so they stay separate.
func titleSubset(a, b string) bool {
	ta, tb := titleTokens(a), titleTokens(b)
	if len(ta) == 0 || len(tb) == 0 {
		return false
	}
	small, big := ta, tb
	if len(tb) < len(ta) {
		small, big = tb, ta
	}
	for w := range small {
		if !big[w] {
			return false
		}
	}
	return true
}

// normTitle lowercases a title, strips leading articles and trailing linking words,
// and normalizes a standalone Roman "i" to the digit "1" so near-duplicates like
// "Annual Title I Meeting" and "Annual Title 1 Meeting" compare equal.
func normTitle(t string) string {
	s := strings.ToLower(strings.TrimSpace(t))
	s = strings.TrimPrefix(s, "the ")
	for _, suf := range []string{" is", " are", " on", " at", " will be", " begins", " starts"} {
		s = strings.TrimSuffix(s, suf)
	}
	toks := strings.Fields(s)
	for i, tok := range toks {
		if tok == "i" { // Roman numeral one vs digit one
			toks[i] = "1"
		}
	}
	return strings.Join(toks, " ")
}

// titleScore rates a title's quality: a clean, Title-Case noun phrase beats a
// sentence fragment.
func titleScore(e Event) int {
	t := strings.TrimSpace(e.Title)
	s := 0
	if len(t) >= 4 {
		s++
	}
	if t != "" && t[0] >= 'A' && t[0] <= 'Z' {
		s++
	}
	low := strings.ToLower(t)
	if strings.HasPrefix(low, "the ") {
		s--
	}
	for _, bad := range []string{" is", " on ", " at ", " are "} {
		if strings.HasSuffix(low, strings.TrimRight(bad, " ")) || strings.Contains(low, bad) {
			s--
		}
	}
	return s
}
