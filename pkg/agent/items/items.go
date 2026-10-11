// Package items is the deterministic (regex/offline) extractor of calendar items
// from an email: meetings/events, tasks ("buy popcorn"), heads-ups ("guest
// author visiting"), and actions (an invite/RSVP link). It is a WriteICS tool
// emitting one inert .ics the user accepts.
//
// It is line-aware so it survives real-world layout: a section header becomes
// the title of the dated lines beneath it ("Upcoming Evacuation Drills"), and a
// date line with the time on a nearby line is assembled into one timed event
// (Back-to-School Night). Long reference documents (a family handbook) are
// detected and left for the corpus/Q&A rather than shredded into fake tasks.
//
// This is the robust offline FLOOR and the deterministic half of the planned
// LLM ensemble: the LLM handles format variance, this verifies dates (M9) and
// catches hallucinations. See docs/APP-FEATURES-PLAN.md.
package items

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/t0ul/emaildrop/pkg/agent/dateparse"
	"github.com/t0ul/emaildrop/pkg/agent/ics"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
	"github.com/t0ul/emaildrop/pkg/agent/tool"
)

var (
	// reAction: an actionable ask — the sentence wants the reader to DO something.
	// ("join" is deliberately absent — "join us for the potluck" is event flavor,
	// not a task; real joins carry a link and are caught as actions.)
	reAction = regexp.MustCompile(`(?i)\b(buy|purchase|bring|donate|donation|drop[- ]?off|rsvp|accept|confirm|sign up|sign-up|sign and return|return the|return your|submit|register|complete the|pay|volunteer|no later than|don't forget|do not forget|reminder to|must|deadline|due by|due)\b`)
	// reHeadsUp: informational, dated — something is happening, no action needed.
	reHeadsUp  = regexp.MustCompile(`(?i)\b(visiting|will visit|guest (author|speaker|reader)|coming to|assembly|book fair|spirit week|picture day|no school|early dismissal|field trip|week of)\b`)
	reURL      = regexp.MustCompile(`(?i)\bhttps?://\S+`)
	reBullet   = regexp.MustCompile(`^\s*[-*•●\x{25cf}\x{25cb}\x{2022}]+\s*`)
	reSpace    = regexp.MustCompile(`\s+`)
	reSentence = regexp.MustCompile(`[.!?]+\s+`)
	reYear     = regexp.MustCompile(`^(?:19|20)\d\d$`) // a standalone 4-digit year token
	// reOrgPrefix strips leading org/sender tags from a subject/header so the
	// event name is left ("PS 51 PTA Multicultural Potluck" -> "Multicultural
	// Potluck"; "Upcoming Evacuation Drills" -> "Evacuation Drills").
	reOrgPrefix = regexp.MustCompile(`(?i)^(p\.?\s?s\.?\s*\d+|pta|pto|ps\d+|upcoming|our)\b[\s:–—-]*`)
	// rePolicyModal marks reference/policy prose (handbooks), not a parent's asks.
	rePolicyModal = regexp.MustCompile(`(?i)\b(must|may not|are required|is required|are trained to|will be permitted|are not able|shall|prohibit)\b`)
)

var weekdaySet = map[string]bool{"monday": true, "tuesday": true, "wednesday": true, "thursday": true,
	"friday": true, "saturday": true, "sunday": true}
var monthSet = map[string]bool{"january": true, "february": true, "march": true, "april": true, "may": true,
	"june": true, "july": true, "august": true, "september": true, "october": true, "november": true, "december": true}
var trailWords = map[string]bool{"on": true, "from": true, "will": true, "be": true, "is": true, "are": true,
	"at": true, "the": true, "a": true, "an": true, "our": true, "in": true, "for": true, "of": true, "to": true, "and": true}

func normTitle(s string) string {
	return strings.Join(strings.Fields(nonAlnum.ReplaceAllString(strings.ToLower(s), " ")), " ")
}

var (
	reGreeting = regexp.MustCompile(`(?i)^(dear|hi|hello|hey|greetings|good (morning|afternoon|evening))\b`)
	reNoEvents = regexp.MustCompile(`(?i)\bno (new )?(meetings|events|field trips)\b|\bnothing (scheduled|planned)\b|\bno events scheduled\b`)
	reOrdinal  = regexp.MustCompile(`^\d{1,2}(st|nd|rd|th)?$`) // 28th, 1st, 3, 22
	reLeadTime = regexp.MustCompile(`^\s*\d{1,2}:\d{2}`)       // a title starting with a clock time is a fragment
	// reModifierOnly: a title that is ONLY an event modifier (a detail of some other event,
	// e.g. a standalone "In-Person!" sub-bullet), not the name of an event in its own right.
	reModifierOnly = regexp.MustCompile(`(?i)^(in-?person|virtual|online|remote|hybrid|cancell?ed|postponed|rescheduled|tba|tbd)[!.]*$`)
	// reGenericLabel: a bare field label — usually an email header ("Date:", "Subject:")
	// grabbed as an event, not an event name.
	reGenericLabel = regexp.MustCompile(`(?i)^(date|time|when|where|location|subject|from|to|re|details?|info|information|notes?|agenda)$`)
)

// IsJunkTitle reports whether a "title" is really a date, a greeting, or a bulletin
// "nothing scheduled" line rather than the name of an event — the residual noise the
// regex extractor grabbed. Used to drop such entries from the calendar/export.
func IsJunkTitle(t string) bool {
	s := strings.TrimSpace(t)
	if s == "" {
		return true
	}
	if reGreeting.MatchString(s) || reNoEvents.MatchString(s) || reLeadTime.MatchString(s) ||
		reModifierOnly.MatchString(s) || reGenericLabel.MatchString(s) {
		return true // greeting, "nothing scheduled", clock-time fragment, bare modifier, or field label
	}
	// Date-only: nothing of substance remains after dropping date/weekday/month/ordinal
	// /year and bare connector tokens (so "September 28th" or "Thursday October 1st" → junk).
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		if weekdaySet[w] || monthSet[w] || reYear.MatchString(w) || reOrdinal.MatchString(w) ||
			w == "the" || w == "of" || w == "on" || w == "at" || w == "a" || w == "an" {
			continue
		}
		if len(w) >= 2 {
			return false // a real word survives → not junk
		}
	}
	return true
}

func isJunkTitle(t string) bool { return IsJunkTitle(t) }

// nextBulletFollows reports whether the next non-blank line after i is a bulleted item —
// the signal that a bare date line heads a daily-agenda list rather than naming an event.
func nextBulletFollows(lines []string, bullet []bool, i int) bool {
	for j := i + 1; j < len(lines); j++ {
		if lines[j] == "" {
			continue
		}
		return bullet[j]
	}
	return false
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// keepWarnings drops noise that shouldn't force human review (assumed_year is
// normal — emails rarely state the year); real integrity flags stay.
func keepWarnings(ws []string) []string {
	var out []string
	for _, w := range ws {
		if !strings.HasPrefix(w, "assumed_year") {
			out = append(out, w)
		}
	}
	return out
}

// genericWord: a word too generic to be an event name on its own. If stripping the org
// prefix leaves only one of these ("PTA Meeting" -> "Meeting"), the prefix was part of the
// name, so it is kept.
var genericWord = map[string]bool{"meeting": true, "event": true, "day": true, "night": true,
	"date": true, "time": true, "update": true, "reminder": true, "notice": true, "announcement": true, "info": true}

func cleanSubject(s string) string {
	orig := strings.TrimSpace(strings.Trim(s, " :–—-"))
	for {
		n := reOrgPrefix.ReplaceAllString(s, "")
		if n == s {
			break
		}
		s = n
	}
	s = strings.TrimSpace(strings.Trim(s, " :–—-"))
	// Don't strip an org tag into a bare generic word: "PTA Meeting" -> keep "PTA Meeting",
	// not "Meeting". (But "Our Potluck" -> "Potluck" is fine — "Potluck" is not generic.)
	if f := strings.Fields(s); len(f) == 1 && genericWord[strings.ToLower(f[0])] && len(strings.Fields(orig)) >= 2 {
		s = orig
	}
	if s == strings.ToUpper(s) { // de-SHOUT an all-caps header
		s = strings.Title(strings.ToLower(s))
	}
	return s
}

// sharesWord reports whether a and b share a significant (>4 rune) word.
func sharesWord(a, b string) bool {
	bl := strings.ToLower(b)
	for _, w := range strings.Fields(strings.ToLower(a)) {
		w = strings.Trim(w, ",.!?:;")
		if len([]rune(w)) > 4 && strings.Contains(bl, w) {
			return true
		}
	}
	return false
}

var reLetters = regexp.MustCompile(`[a-z]{4,}`)

// significant reports whether a fragment has a real word: a run of 4+ letters
// that is not a weekday or month name (so "10:08 AM" / "Thursday" do not count).
func significant(frag string) bool {
	for _, w := range reLetters.FindAllString(strings.ToLower(frag), -1) {
		if !weekdaySet[w] && !monthSet[w] {
			return true
		}
	}
	return false
}

func trimEnds(c string) string {
	// Strip, from either end: a trailing connector/weekday word, a standalone 4-digit
	// year (e.g. "2026") left behind when a date phrase carried an explicit year the
	// month-day match didn't cover, and a bare separator token (-, –, — after punctuation
	// trimming). So "…, 2026 — First day of school" yields "First day of school".
	clean := func(w string) string { return strings.ToLower(strings.Trim(w, ",.-–—:")) }
	strip := func(w string) bool { return w == "" || trailWords[w] || weekdaySet[w] || reYear.MatchString(w) }
	words := strings.Fields(c)
	for len(words) > 0 {
		if strip(clean(words[len(words)-1])) {
			words = words[:len(words)-1]
			continue
		}
		break
	}
	for len(words) > 0 {
		if strip(clean(words[0])) {
			words = words[1:]
			continue
		}
		break
	}
	return strings.Join(words, " ")
}

// eventTitleOrEmpty derives a short event name from a line by taking the text
// around the date phrase (a title can sit before OR after the date — "Multicultural
// Potluck will be on Oct 23" vs "October 12th - Italian Heritage Day") and
// stripping connector/weekday words. Returns "" for a bare date line
// ("Thursday, October 1st at 10:08 AM"), so the caller falls back to the header.
func eventTitleOrEmpty(s string) string {
	before, after := s, ""
	if idx := dateparse.MonthDayIndex(s); idx != nil {
		before, after = s[:idx[0]], s[idx[1]:]
	}
	b := trimEnds(strings.TrimSpace(strings.Trim(before, " ,.-–—:")))
	a := trimEnds(strings.TrimSpace(strings.Trim(after, " ,.-–—:")))
	// Prefer whichever side carries a real name (the longer, if both do).
	switch {
	case significant(a) && (!significant(b) || len(a) >= len(b)):
		return a
	case significant(b):
		return b
	default:
		return ""
	}
}

func isHeader(line string) bool {
	if line == "" || len(strings.Fields(line)) > 8 {
		return false
	}
	t := strings.TrimRight(line, " ")
	if strings.HasSuffix(t, ".") || strings.Contains(t, ": ") {
		return false // a sentence, not a heading
	}
	return reSentence.FindStringIndex(line) == nil
}

// DocumentType classifies an email at ingest (R2): "reference" for a standing
// policy/handbook doc (feed the corpus for Q&A, extract conservatively) vs
// "bulletin" for an actionable newsletter (full extraction). First-class routing
// signal recorded by the pipeline.
func DocumentType(email string) string {
	if referenceLike(email) {
		return "reference"
	}
	return "bulletin"
}

// referenceLike detects a long policy/reference document (a handbook): it should
// feed the corpus for Q&A, not be shredded into fake tasks.
func referenceLike(email string) bool {
	lower := strings.ToLower(email)
	head := lower
	if len(head) > 400 {
		head = head[:400]
	}
	if strings.Contains(head, "handbook") || strings.Contains(head, "family and student") || strings.Contains(head, "policy manual") {
		return true
	}
	lines := strings.Count(email, "\n")
	modals := len(rePolicyModal.FindAllString(email, -1))
	return lines > 150 && modals >= 12
}

// combineDT attaches a time to an all-day date (2026-09-29 -> 2026-09-29T17:30:00).
func combineDT(dateISO string, hm dateparse.HM) string {
	return fmt.Sprintf("%sT%02d:%02d:00", dateISO[:10], hm.Hour, hm.Minute)
}

// reClock matches a clock time ("8:45 AM", "5:30pm", "8 am") so a time-only line can
// be told apart from an event line that merely mentions a time.
var reClock = regexp.MustCompile(`(?i)\b\d{1,2}:\d{2}\s*(?:am|pm)?\b|\b\d{1,2}\s*(?:am|pm)\b`)

// timeDominant reports whether a line is essentially JUST a time or time range ("5:30pm
// to 8:00pm") rather than its own event that happens to carry a time ("Safety Committee
// Meeting at 8:45 AM"). Only a time-dominant line's time may be borrowed by a nearby date.
func timeDominant(line string) bool {
	return !significant(reClock.ReplaceAllString(line, " "))
}

// eventContext gathers the source line for an event plus the detail that immediately
// follows it (time/location/blurb), so a clean "Back to School Night" line gains a
// description. It stops at the next dated event or bulleted item, so it never bleeds a
// neighbouring event's text in; at most two detail lines are taken.
func eventContext(lines []string, bullet []bool, i, year int) string {
	parts := []string{lines[i]}
	taken := 0
	for j := i + 1; j < len(lines) && taken < 2; j++ {
		ln := lines[j]
		if ln == "" {
			continue // skip a blank line but keep looking for the detail
		}
		if bullet[j] || dateparse.ExtractDatetime(ln, year) != nil {
			break // the next item/date — not this event's detail
		}
		parts = append(parts, ln)
		taken++
	}
	return strings.Join(parts, " ")
}

// nearbyTimes returns the times from the closest TIME-ONLY line around index i, so
// "Tuesday Sept 29" + "5:30pm to 8:00pm" one line apart become a single timed event.
// It refuses to borrow a time from a line that is its own event ("… Meeting at 8:45 AM"),
// which would stamp a fabricated time on an unrelated date (a sibling in a daily agenda).
func nearbyTimes(lines []string, i, year int) []dateparse.HM {
	for _, j := range []int{i + 1, i + 2, i + 3, i - 1, i - 2} {
		if j < 0 || j >= len(lines) || j == i || lines[j] == "" {
			continue
		}
		if dateparse.ParseDatePhrase(lines[j], year) != nil {
			continue // that line is itself dated; don't borrow its time
		}
		if hm := dateparse.ParseTimes(lines[j]); len(hm) > 0 && timeDominant(lines[j]) {
			return hm
		}
	}
	return nil
}

// Classify extracts the calendar items an email asks for.
func Classify(email string, defaultYear int) []schema.Event {
	if defaultYear == 0 {
		defaultYear = dateparse.DefaultYear
	}
	if referenceLike(email) {
		return nil // reference/handbook -> corpus & Q&A (Track 2 R2), not tasks
	}

	var lines []string
	var bullet []bool // whether the original line was a bulleted list item
	for _, ln := range strings.Split(email, "\n") {
		bullet = append(bullet, reBullet.MatchString(ln))
		lines = append(lines, strings.TrimSpace(reBullet.ReplaceAllString(ln, "")))
	}
	subject := ""
	for _, ln := range lines {
		if ln != "" {
			subject = ln
			break
		}
	}

	var out []schema.Event
	seen := map[string]bool{}
	add := func(ev schema.Event) {
		key := normTitle(ev.Title) + "|" + dateOf(ev)
		if strings.TrimSpace(ev.Title) == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ev)
	}

	// --- events pass (line-aware): holidays, meetings, drills, closures ---
	// Two layouts are handled: an event named on its own dated line, AND a daily-agenda
	// layout — a bare date line ("Thursday, October 8th") over bulleted events below. In
	// the agenda layout each bullet is an event ON that date (sectionDate), so the bullets
	// get the right day and the bare date line itself does not spawn a mis-titled event.
	header, sectionDate := "", ""
	eventDates := map[string]bool{}
	for i, ln := range lines {
		if ln == "" {
			continue // a blank line separates bullets; it does not end the agenda section
		}
		dt := dateparse.ExtractDatetime(ln, defaultYear)
		if dt == nil {
			// A bullet under an active section date is an event on that date (its own text
			// is the title). Actions/links/heads-ups stay with the asks pass (they have a
			// task/heads-up vocabulary), so only plain bullets become events here.
			if sectionDate != "" && bullet[i] && significant(ln) &&
				!reAction.MatchString(ln) && !reURL.MatchString(ln) && !reHeadsUp.MatchString(ln) {
				if title := Tidy(cleanSubject(ln)); title != "" && !isJunkTitle(title) {
					eventDates[sectionDate] = true
					add(schema.Event{Title: title, Start: sectionDate, AllDay: true, Notes: SourceNote(ln),
						Kind: schema.KindEvent, Confidence: 0.7})
				}
				continue
			}
			if !bullet[i] {
				sectionDate = "" // prose (not a bullet) ends the agenda list
			}
			if isHeader(ln) {
				header = ln
			}
			continue
		}
		// A bare all-day date line with bullets below is an agenda SECTION HEADER: it opens
		// a section (sectionDate) and takes a title only from its OWN text, never a stale
		// top-of-email header — otherwise a greeting/newsletter title would land on the date.
		var title string
		if dt.AllDay && nextBulletFollows(lines, bullet, i) {
			header = ""
			title = Tidy(eventTitleOrEmpty(ln))
		} else {
			title = Tidy(bestTitle(ln, header, subject))
		}
		if dt.AllDay {
			sectionDate = dt.Start[:10] // a bare date line opens an agenda section
		}
		// A dated ASK stays a task/heads-up (handled in the asks pass).
		if dt.AllDay && (reAction.MatchString(ln) || reHeadsUp.MatchString(ln)) {
			continue
		}
		start, end, allDay := dt.Start, dt.End, dt.AllDay
		if allDay {
			if hm := nearbyTimes(lines, i, defaultYear); len(hm) > 0 {
				start, allDay = combineDT(dt.Start, hm[0]), false
				if len(hm) > 1 {
					end = combineDT(dt.Start, hm[1])
				}
			}
		}
		if title == "" || isJunkTitle(title) {
			continue // a bare date, or a date/greeting/"nothing scheduled" line — not an event
		}
		// Source context (description): the event line plus the detail that follows it
		// (time/location/blurb), stopping at the next dated event or bullet. Falls back to
		// the section header when the dated line itself carries no words.
		note := SourceNote(eventContext(lines, bullet, i, defaultYear))
		if !significant(note) && significant(header) {
			note = SourceNote(header)
		}
		eventDates[start[:10]] = true
		add(schema.Event{Title: title, Start: start, End: end, AllDay: allDay, Notes: note,
			Kind: schema.KindEvent, Confidence: 0.75, Warnings: keepWarnings(dt.Warnings)})
	}

	// Propagate a date to date-less asks ONLY for a single-event email (so a
	// handbook/newsletter with many dates never stamps every ask with one date).
	primary := ""
	if len(eventDates) == 1 {
		for d := range eventDates {
			primary = d
		}
	}

	// --- asks pass (sentence-based): tasks, heads-ups, actions ---
	for _, s := range sentences(email) {
		dt := dateparse.ExtractDatetime(s, defaultYear)
		if dt != nil && !dt.AllDay {
			continue // a timed, dated sentence is a meeting — the events pass owns it
		}
		hasURL := reURL.MatchString(s)
		action := reAction.MatchString(s)
		headsUp := reHeadsUp.MatchString(s)
		if !action && !headsUp && !hasURL {
			continue
		}

		ev := schema.Event{Title: TidyItem(s), Notes: SourceNote(s), Confidence: 0.9, Warnings: []string{}, AllDay: true}
		switch {
		case hasURL:
			ev.Kind = schema.KindAction
			ev.URL = reURL.FindString(s)
		case action:
			ev.Kind = schema.KindTask
		default:
			ev.Kind = schema.KindHeadsUp
		}
		switch {
		case dt != nil:
			ev.AllDay = dt.AllDay
			ev.Warnings = keepWarnings(dt.Warnings)
			if ev.Kind == schema.KindHeadsUp {
				ev.Start = dt.Start
			} else {
				ev.Due = dt.Start
			}
		case primary != "":
			if ev.Kind == schema.KindHeadsUp {
				ev.Start = primary
			} else {
				ev.Due = primary
			}
			ev.Warnings = append(ev.Warnings, "date inferred from the email")
		case ev.Kind == schema.KindHeadsUp:
			continue // undated, un-anchored heads-up isn't a calendar item
		}
		add(ev)
	}
	return out
}

// bestTitle picks the cleanest title for a dated event line: a subject that
// clearly names it, else the line's own text, else the section header. Returns
// "" when none is a real name (a bare date line), so the event is dropped.
func bestTitle(line, header, subject string) string {
	if subject != "" && len(strings.Fields(subject)) <= 8 && sharesWord(subject, line) {
		if cs := cleanSubject(subject); len([]rune(cs)) >= 3 {
			return cs
		}
	}
	if t := eventTitleOrEmpty(line); t != "" {
		return t
	}
	if h := cleanSubject(header); significant(h) {
		return h
	}
	return ""
}

func sentences(email string) []string {
	var out []string
	for _, line := range strings.Split(email, "\n") {
		line = strings.TrimSpace(reBullet.ReplaceAllString(line, ""))
		if line == "" {
			continue
		}
		for _, s := range reSentence.Split(line, -1) {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, reSpace.ReplaceAllString(s, " "))
			}
		}
	}
	return out
}

func dateOf(e schema.Event) string {
	if e.Due != "" {
		return e.Due
	}
	return e.Start
}

// ItemExtractor is the WriteICS tool wrapping Classify. Its artifact is
// "items.ics" (distinct from the event extractor's), so both tools stay
// least-privilege and independent and the web app merges their outputs.
type ItemExtractor struct{}

func (ItemExtractor) Name() string                { return "item_extractor" }
func (ItemExtractor) Capability() tool.Capability { return tool.WriteICS }

func (ItemExtractor) Run(email string, ctx tool.Ctx) tool.Result {
	items := Classify(email, ctx.DefaultYear)
	for i := range items {
		items[i].SourceEmail = ctx.Source
	}
	res := tool.Result{Tool: "item_extractor", Capability: tool.WriteICS, Events: items}
	if len(items) > 0 {
		text, removed, err := ics.Write(items, "Email items")
		if err != nil {
			res.Warnings = append(res.Warnings, "items ics write failed: "+err.Error())
		} else {
			res.Artifacts = map[string]string{"items.ics": text}
			if removed > 0 {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%d link(s) sanitized", removed))
			}
		}
	}
	res.Warnings = append(res.Warnings, fmt.Sprintf("%d item(s)", len(items)))
	return res
}
