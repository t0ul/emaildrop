package items

import (
	"sort"
	"strings"
	"unicode"

	"github.com/t0ul/goflage"
)

// Deterministic, offline title hygiene for extracted items — the Tier-1 fix for the
// sentence-fragment titles the regex extractor produces. No LLM: this is the cheap,
// zero-injection-surface floor (clause-truncate + strip connectors + length cap +
// PII scrub). Dates and kind stay deterministic elsewhere (the M9 invariant); this
// only shapes the display string. All functions are idempotent — re-tidying a tidy
// title is a no-op — so they are safe to apply both at extraction and at projection.

const maxTitleWords = 10

// titleBound is a clause separator and the minimum word count a lead clause must have
// for a cut there to count. ":"/";"/dash are strong title separators (the lead is the
// name even at 2 words: "PTA Meeting: …" -> "PTA Meeting"); a comma is weaker, so it
// only cuts when a real lead clause precedes it ("…above, pay via Zelle" -> "…above").
type titleBound struct {
	sep      string
	minWords int
}

var titleBounds = []titleBound{
	{"; ", 2}, {": ", 2}, {" — ", 2}, {" – ", 2}, {" - ", 2}, {", ", 3},
}

// leadFillerWord: a single leading connective/filler word that adds no meaning to a
// title ("Plus, …", "Our …", "Please …"). Dropped from the front while a real phrase
// remains.
var leadFillerWord = map[string]bool{
	"plus": true, "and": true, "so": true, "also": true, "our": true, "the": true,
	"a": true, "an": true, "we": true, "you": true, "i": true, "please": true,
	"just": true, "now": true, "finally": true, "additionally": true, "as": true,
	"remember": true, "note": true, "fyi": true, "ps": true, "that": true,
	"there": true, "this": true, "it": true, "kindly": true, "reminder": true,
	"all": true, "but": true, "then": true,
}

// leadSubordinator introduces a leading DEPENDENT clause ("If you do not have time, we
// would appreciate a donation") — the condition, not the ask. When one leads and a comma
// follows, the clause up to the comma is dropped so the title centers on the main clause.
var leadSubordinator = map[string]bool{
	"if": true, "when": true, "since": true, "because": true, "although": true,
	"though": true, "while": true, "unless": true, "whenever": true, "after": true,
	"before": true, "plus": true, "also": true, "finally": true, "additionally": true,
	"however": true,
}

// leadFillerPair: a two-word opener that carries no title meaning ("You can donate …"
// -> "donate …"). Checked before the single-word drop.
var leadFillerPair = map[string]bool{
	"you can": true, "we are": true, "we will": true, "we ask": true,
	"we would": true, "we have": true, "there will": true, "there is": true,
	"this is": true, "it is": true,
	"please note": true, "as a": true, "in addition": true, "be sure": true,
	// NB: never strip a leading negation ("do not", "don't", "no") — dropping it inverts
	// the meaning ("We do not accept …" → "accept …"). Keep negations in the title.
}

// piiAnalyzer is the shared goflage scrubber (regex + checksum, zero deps). First
// live wiring of goflage into the app pipeline (was demo-only).
var piiAnalyzer = goflage.New()

// ScrubTitle removes PII spans (emails, Luhn cards, SSNs, secrets) from a title
// ENTIRELY — not a "<EMAIL>" placeholder, since a title is read by a person. A space
// replaces each removed span so neighbouring words don't fuse, then whitespace is
// collapsed. Deterministic and idempotent.
func ScrubTitle(s string) string {
	ms := piiAnalyzer.Analyze(s)
	if len(ms) == 0 {
		return s
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Start < ms[j].Start })
	var b strings.Builder
	last := 0
	for _, m := range ms {
		if m.Start < last {
			continue
		}
		b.WriteString(s[last:m.Start])
		b.WriteString(" ")
		last = m.End
	}
	b.WriteString(s[last:])
	return strings.TrimSpace(reSpace.ReplaceAllString(b.String(), " "))
}

// CleanTitle shapes a raw line into a short title: cut at the first clause boundary,
// drop leading connective filler, cap the length, trim trailing junk. It does NOT
// force capitalization — a title still lowercase after stripping is a mid-sentence
// fragment, the signal the event projection's dropFragments uses to cull non-events.
func CleanTitle(s string) string {
	s = reSpace.ReplaceAllString(strings.TrimSpace(s), " ")
	if s == "" {
		return ""
	}
	s = dropLeadSubordinate(s)
	s = cutAtBoundary(s)
	s = stripLeadFiller(s)
	s = capWords(s, maxTitleWords)
	s = trimEnds(strings.TrimSpace(strings.Trim(s, " ,.;:–—-@")))
	if s != "" && s == strings.ToUpper(s) && significant(s) { // de-SHOUT an all-caps title
		s = strings.Title(strings.ToLower(s))
	}
	return strings.TrimSpace(s)
}

// Tidy is the shared scrub-then-clean pipeline for an EVENT title (no capitalization,
// so a stripped-to-lowercase fragment still gets culled downstream).
func Tidy(s string) string { return CleanTitle(ScrubTitle(s)) }

// TidyItem is Tidy for a TASK/heads-up/action title, where an imperative fragment is
// legitimate ("donate at the link above") and there is no fragment cull — so the first
// letter is capitalized for display.
func TidyItem(s string) string { return capitalizeFirst(Tidy(s)) }

// SourceNote prepares an event's source line for display as a description — the actual
// email words the item was extracted from, so a reader can tell what a cryptic title
// ("In-Person!") actually is. It is untrusted email text, so it is PII-scrubbed here,
// whitespace-collapsed and length-capped; the UI HTML-escapes it and the .ics writer
// sanitizes it (strips exfil vectors) before it is shown or exported.
func SourceNote(s string) string {
	s = reSpace.ReplaceAllString(strings.TrimSpace(s), " ")
	s = ScrubTitle(s)
	if r := []rune(s); len(r) > 240 {
		s = strings.TrimSpace(string(r[:240])) + "…"
	}
	return s
}

func dropLeadSubordinate(s string) string {
	for {
		i := strings.Index(s, ", ")
		if i <= 0 {
			return s
		}
		w0 := strings.ToLower(strings.Trim(strings.Fields(s)[0], ",.;:!?"))
		if !leadSubordinator[w0] {
			return s
		}
		rest := strings.TrimSpace(s[i+2:])
		if len(strings.Fields(rest)) < 3 { // don't strip into nothing
			return s
		}
		s = rest
	}
}

func cutAtBoundary(s string) string {
	best := len(s)
	for _, b := range titleBounds {
		i := strings.Index(s, b.sep)
		if i <= 0 || i >= best {
			continue
		}
		if len(strings.Fields(s[:i])) < b.minWords {
			continue
		}
		best = i
	}
	return s[:best]
}

func stripLeadFiller(s string) string {
	for {
		words := strings.Fields(s)
		if len(words) < 4 { // keep at least three words
			break
		}
		w0 := strings.ToLower(strings.Trim(words[0], ",.;:!?"))
		w1 := strings.ToLower(strings.Trim(words[1], ",.;:!?"))
		pair := w0 + " " + w1
		if isNegation(w0) || isNegation(w1) {
			return strings.TrimSpace(s) // never strip a negation — dropping it inverts meaning
		}
		switch {
		case leadFillerPair[pair]:
			s = strings.Join(words[2:], " ")
		case leadFillerWord[w0]:
			s = strings.Join(words[1:], " ")
		default:
			return strings.TrimSpace(s)
		}
	}
	return strings.TrimSpace(s)
}

// isNegation reports whether a word negates — these must never be stripped as filler,
// since dropping one flips the meaning ("do not accept" → "accept").
func isNegation(w string) bool {
	switch w {
	case "no", "not", "never", "none", "cannot":
		return true
	}
	return strings.Contains(w, "n't") // don't, can't, won't, doesn't, isn't …
}

func capWords(s string, n int) string {
	words := strings.Fields(s)
	if len(words) <= n {
		return s
	}
	return strings.Join(words[:n], " ")
}

// CapitalizeFirst upper-cases the first letter of a title.
func CapitalizeFirst(s string) string { return capitalizeFirst(s) }

func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
