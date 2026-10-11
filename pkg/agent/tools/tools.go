// Package tools holds the read-only members of the agent's tool roster (the
// event→.ics writer lives in agent/extractor). Each is a drop-in behind the
// agent/tool plugin contract with a single declared capability, so the pipeline
// enforces least privilege: none of these may write an artifact, and the
// contacts tool is the only one scoped to surface PII.
package tools

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/t0ul/emaildrop/pkg/agent/dateparse"
	"github.com/t0ul/emaildrop/pkg/agent/extractor"
	"github.com/t0ul/emaildrop/pkg/agent/tool"
	"github.com/t0ul/goflage"
)

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// --- Tool 2: action items / deadlines ---

var reAction = regexp.MustCompile(`(?i)\b(please|due|deadline|rsvp|sign and return|return the|bring|submit|register|complete the|no later than|don't forget|reminder to|must)\b`)

// ActionItems extracts actionable asks and deadlines from an email.
type ActionItems struct{}

func (ActionItems) Name() string                { return "action_items" }
func (ActionItems) Capability() tool.Capability { return tool.ReadOnly }
func (ActionItems) Run(email string, _ tool.Ctx) tool.Result {
	var items []string
	for _, l := range nonEmptyLines(email) {
		if reAction.MatchString(l) {
			items = append(items, "- "+l)
		}
	}
	return tool.Result{
		Tool: "action_items", Capability: tool.ReadOnly,
		Text:     strings.Join(items, "\n"),
		Warnings: []string{fmt.Sprintf("%d action item(s)", len(items))},
	}
}

// --- Tool 3: digest / TL;DR ---

// Digest produces a short, deterministic summary: the subject line plus the
// dated lines a reader would calendar.
type Digest struct{}

func (Digest) Name() string                { return "digest" }
func (Digest) Capability() tool.Capability { return tool.ReadOnly }
func (Digest) Run(email string, _ tool.Ctx) tool.Result {
	lines := nonEmptyLines(email)
	subject := "(no subject)"
	if len(lines) > 0 {
		subject = lines[0]
	}
	var dated []string
	for _, l := range lines {
		if dateparse.MonthDayIndex(l) != nil {
			dated = append(dated, "- "+l)
			if len(dated) == 5 {
				break
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Subject: %s\n%d dated line(s):\n%s", subject, len(dated), strings.Join(dated, "\n"))
	return tool.Result{Tool: "digest", Capability: tool.ReadOnly, Text: b.String()}
}

// --- Tool 4: contacts (PII-scoped) ---

// Contacts surfaces the email/IP contact details in a message. It is the one
// roster tool permitted to output PII, so its result is flagged for the audit
// trail. It uses goflage's recognizers to find entities, returning their values
// (unlike the scrubber, which redacts them).
type Contacts struct{}

func (Contacts) Name() string                { return "contacts" }
func (Contacts) Capability() tool.Capability { return tool.ReadOnly }
func (Contacts) Run(email string, _ tool.Ctx) tool.Result {
	ms := goflage.New().Analyze(email)
	seen := map[string]bool{}
	var contacts []string
	entities := map[string]int{}
	for _, m := range ms {
		if m.Entity != "EMAIL_ADDRESS" {
			continue // contacts are addresses; secrets/IPs are not surfaced here
		}
		if !seen[m.Text] {
			seen[m.Text] = true
			contacts = append(contacts, m.Text)
		}
		entities[m.Entity]++
	}
	sort.Strings(contacts)
	return tool.Result{
		Tool: "contacts", Capability: tool.ReadOnly,
		Text:     strings.Join(contacts, "\n"),
		Warnings: []string{fmt.Sprintf("PII-scoped: surfaced %d contact(s)", len(contacts))},
	}
}

// --- Tool 5: change / conflict detector ---

var reConflictNorm = regexp.MustCompile(`[^a-z0-9]+`)

func normTitle(s string) string {
	return strings.TrimSpace(reConflictNorm.ReplaceAllString(strings.ToLower(s), " "))
}

// Conflicts flags the same event announced on more than one date across the
// email (a reschedule/cancel or a self-conflicting source — the M9 integrity
// surface). Read-only: it reports, it never writes a calendar entry.
type Conflicts struct{}

func (Conflicts) Name() string                { return "conflict_detector" }
func (Conflicts) Capability() tool.Capability { return tool.ReadOnly }
func (Conflicts) Run(email string, ctx tool.Ctx) tool.Result {
	year := ctx.DefaultYear
	if year == 0 {
		year = dateparse.DefaultYear
	}
	events := extractor.ExtractEvents(email, "", year)
	byTitle := map[string]map[string]bool{}
	for _, e := range events {
		k := normTitle(e.Title)
		if k == "" {
			continue
		}
		if byTitle[k] == nil {
			byTitle[k] = map[string]bool{}
		}
		byTitle[k][e.Start[:10]] = true
	}
	var warns []string
	for _, k := range sortedKeys(byTitle) {
		if len(byTitle[k]) > 1 {
			warns = append(warns, fmt.Sprintf("conflict: %q announced on %s", k, strings.Join(sortedKeys(byTitle[k]), ", ")))
		}
	}
	text := "no conflicts detected"
	if len(warns) > 0 {
		text = strings.Join(warns, "\n")
	}
	return tool.Result{Tool: "conflict_detector", Capability: tool.ReadOnly, Text: text, Warnings: warns}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
