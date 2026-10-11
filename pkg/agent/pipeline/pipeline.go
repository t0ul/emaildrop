// Package pipeline is the pure, testable core of the watched-folder agent.
//
// It reads one email, neutralizes indirect injection (guard, M4), runs the
// registered tools under one trace_id, enforces each tool's declared capability
// (least privilege, M6 — a read-only tool cannot write an artifact), writes
// inert artifacts to the outbox, and records every step to a tamper-evident,
// value-redacting audit log (gledger, replacing the Python telemetry spine).
// The watcher daemon is a thin wrapper that calls ProcessEmail per dropped file.
package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/t0ul/emaildrop/pkg/agent/guard"
	"github.com/t0ul/emaildrop/pkg/agent/items"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
	"github.com/t0ul/emaildrop/pkg/agent/tool"
	"github.com/t0ul/emaildrop/pkg/provenance"
	"github.com/t0ul/gledger"
	"github.com/t0ul/goflage"
)

// MaxBytes is the oversized-input DoS guard for the long-running agent (M10).
const MaxBytes = 256 * 1024

// Summary is the result of processing one email.
type Summary struct {
	TraceID   string   `json:"trace_id"`
	Source    string   `json:"source"`
	Events    int      `json:"events"`
	Artifacts []string `json:"artifacts"`
	Warnings  []string `json:"warnings"`
	Rejected  string   `json:"rejected,omitempty"`
	Bytes     int64    `json:"bytes,omitempty"`
}

// EmailSummary is the per-email derived sidecar the pipeline writes to the
// outbox as <stem>.summary.json. It is NOT a tool artifact — read-only tools may
// not write files (M6) — so the trusted pipeline persists their text plus the
// extracted items, letting the owner UI surface digest / contacts / action-items
// / tasks without re-running anything. Contacts are PII and already audited by
// the contacts tool's own capability.
type EmailSummary struct {
	Source      string            `json:"source"`
	TraceID     string            `json:"trace_id"`
	Tools       map[string]string `json:"tools"`                  // read-only tool name -> text
	Items       []schema.Event    `json:"items"`                  // events + tasks/heads-ups/actions (Kind-tagged)
	NeedsReview []schema.Event    `json:"needs_review,omitempty"` // low-confidence / warned items
	DocType     string            `json:"doc_type,omitempty"`     // "bulletin" | "reference" (R2 routing)
}

// Pipeline wires a tool registry to an audit log and an outbox.
type Pipeline struct {
	Registry    *tool.Registry
	Audit       *gledger.AuditLog
	OutboxDir   string
	ToolNames   []string // defaults to ["event_extractor"]
	DefaultYear int      // defaults to 2026
	// Index, if set, persists each email into the retrieval corpus (RAG) as
	// untrusted provenance. The raw file archived to processed/ stays the source
	// of truth; the index is rebuildable derived state. Indexing failures are
	// audited, never fatal.
	Index func(traceID, source, rawText string) error
	// Signer, if set, writes a provenance content credential (<artifact>.sig)
	// next to each emitted artifact, so a consumer can verify the agent produced
	// it unaltered (M20 output authenticity).
	Signer *provenance.Signer
	// Halted, when set and returning true, stops the pipeline before any work —
	// the operator kill switch (M18). Fail-closed: a halted drop is audited and
	// skipped (the raw file is still archived).
	Halted func() bool
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func normTitle(s string) string {
	return strings.Join(strings.Fields(nonAlnum.ReplaceAllString(strings.ToLower(s), " ")), " ")
}

func dateOf(e schema.Event) string {
	if e.Due != "" {
		return e.Due
	}
	return e.Start
}

// titlesMatch treats two same-date items as the same when one normalized title
// contains the other (the event extractor trims the date phrase, the item
// extractor keeps the whole line, so one is a prefix/substring of the other).
func titlesMatch(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return a == b || strings.Contains(a, b) || strings.Contains(b, a)
}

var firstWeekday = regexp.MustCompile(`(?i)^\s*(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b`)
var reAlphaWord = regexp.MustCompile(`[A-Za-z]{4,}`)
var dateWordSet = map[string]bool{
	"monday": true, "tuesday": true, "wednesday": true, "thursday": true, "friday": true, "saturday": true, "sunday": true,
	"january": true, "february": true, "march": true, "april": true, "june": true, "july": true,
	"august": true, "september": true, "october": true, "november": true, "december": true,
}

// isBareDateTitle reports whether a title is just a date phrase with no real
// event name ("Monday, September 28th") — the regex extractors sometimes emit
// these from stray dated lines; they are noise, not events.
func isBareDateTitle(title string) bool {
	for _, w := range reAlphaWord.FindAllString(strings.ToLower(title), -1) {
		if !dateWordSet[w] {
			return false
		}
	}
	return true
}

// looksLikeFragment reports whether an event title is a mid-sentence fragment
// ("went smoothly. See below…") rather than a name — a real event title starts
// with a capital letter or digit, not lowercase.
func looksLikeFragment(title string) bool {
	for _, r := range strings.TrimSpace(title) {
		return r >= 'a' && r <= 'z'
	}
	return false
}

func timedStart(e schema.Event) bool { return strings.Contains(e.Start, "T") }

// titleQuality scores a title: a raw date phrase ("Thursday, October 1st…") or a
// one-word title is low quality; a real name ("Evacuation Drills") is high.
func titleQuality(title string) int {
	if firstWeekday.MatchString(title) || len(strings.Fields(title)) < 2 {
		return 0
	}
	return 1
}

// kindRank prefers the more specific/actionable kind when two tools collide on
// the same item.
func kindRank(kind string) int {
	switch kind {
	case schema.KindAction:
		return 4
	case schema.KindTask:
		return 3
	case schema.KindHeadsUp:
		return 2
	default: // event
		return 1
	}
}

// ProcessEmail runs the full pipeline for one file.
func (p *Pipeline) ProcessEmail(path string) (Summary, error) {
	trace := gledger.NewTraceID()
	source := filepath.Base(path)
	if err := os.MkdirAll(p.OutboxDir, 0o755); err != nil {
		return Summary{}, err
	}
	p.Audit.Emit(trace, "request", "start", gledger.F{"source": source})

	if p.Halted != nil && p.Halted() {
		p.Audit.Emit(trace, "request", "killswitch_halt", gledger.F{"source": source})
		return Summary{TraceID: trace, Source: source, Rejected: "halted"}, nil
	}

	fi, err := os.Stat(path)
	if err != nil {
		return Summary{}, err
	}
	if fi.Size() > MaxBytes {
		p.Audit.Emit(trace, "ingest", "rejected", gledger.F{"reason": "oversized", "bytes": fi.Size(), "limit": MaxBytes})
		p.Audit.Emit(trace, "request", "end", gledger.F{"status": "rejected"})
		return Summary{TraceID: trace, Source: source, Rejected: "oversized", Bytes: fi.Size()}, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return Summary{}, err
	}
	text := string(raw)

	// Scrub secrets/PII BEFORE indexing into the retrieval corpus (M3): the corpus
	// is broadly queryable, so credentials/API keys/emails/IPs must not land in it
	// in the clear. The on-disk raw file (processed/) stays the backup; defense at
	// retrieval (rag.Assemble) still applies on top.
	if p.Index != nil {
		scrubbed, findings := goflage.New().Scrub(text)
		if len(findings) > 0 {
			p.Audit.Emit(trace, "pii", "scrubbed", gledger.F{"source": source, "entities": findings})
		}
		if err := p.Index(trace, source, scrubbed); err != nil {
			p.Audit.Emit(trace, "index", "error", gledger.F{"source": source, "error": err.Error()})
		} else {
			p.Audit.Emit(trace, "index", "stored", gledger.F{"source": source, "bytes": len(scrubbed)})
		}
	}

	// M4: neutralize indirect prompt injection in the untrusted body, and record
	// what was found — the audit trail is the detection surface.
	text, findings := guard.Sanitize(text)
	if len(findings) > 0 {
		p.Audit.Emit(trace, "injection_guard", "detected", gledger.F{"indicators": findings})
	}

	names := p.ToolNames
	if len(names) == 0 {
		names = []string{"event_extractor"}
	}
	year := p.DefaultYear
	if year == 0 {
		year = 2026
	}
	// Document-type routing (R2): classify the (sanitized) body once. A reference
	// doc (handbook/policy) feeds the Ask corpus but is extracted conservatively —
	// its prose dates are not shredded onto the calendar — while a bulletin gets
	// full extraction. The decision is recorded + audited and passed to every tool.
	docType := items.DocumentType(text)
	reference := docType == "reference"
	p.Audit.Emit(trace, "pipeline", "classified", gledger.F{"source": source, "doc_type": docType})

	stem := strings.TrimSuffix(source, filepath.Ext(source))
	summary := Summary{TraceID: trace, Source: source, Artifacts: []string{}, Warnings: []string{}}
	sidecar := EmailSummary{Source: source, TraceID: trace, Tools: map[string]string{}, DocType: docType}

	for _, name := range names {
		t, ok := p.Registry.Get(name)
		if !ok {
			continue
		}
		sp := p.Audit.Start(trace, name, gledger.F{"capability": string(t.Capability())})
		res := t.Run(text, tool.Ctx{Source: source, DefaultYear: year, Reference: reference})
		sp.End()

		// Capability enforcement (M6): only a WRITE_ICS tool may emit artifacts.
		artifacts := res.Artifacts
		if len(artifacts) > 0 && res.Capability != tool.WriteICS {
			keys := make([]string, 0, len(artifacts))
			for k := range artifacts {
				keys = append(keys, k)
			}
			p.Audit.Emit(trace, name, "capability_violation",
				gledger.F{"declared": string(res.Capability), "tried_to_write": keys})
			artifacts = nil
		}

		for fname, content := range artifacts {
			outPath := filepath.Join(p.OutboxDir, stem+"."+fname)
			if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil {
				p.Audit.Emit(trace, name, "artifact_error", gledger.F{"file": fname, "error": err.Error()})
				continue
			}
			// Provenance is fail-closed: when a signer is configured, an artifact that
			// cannot be signed is NOT shipped. Quarantine (remove) it instead of leaving
			// an unsigned .ics the UI would show with a false/absent signed badge — a
			// silent integrity downgrade. Only a successfully signed artifact is recorded.
			if p.Signer != nil {
				mark, merr := json.Marshal(p.Signer.Sign([]byte(content)))
				if merr == nil {
					merr = os.WriteFile(outPath+".sig", mark, 0o644)
				}
				if merr != nil {
					_ = os.Remove(outPath)
					p.Audit.Emit(trace, name, "artifact_sign_error", gledger.F{"file": fname, "error": merr.Error()})
					continue
				}
				p.Audit.Emit(trace, name, "artifact_signed", gledger.F{"file": filepath.Base(outPath) + ".sig"})
			}
			summary.Artifacts = append(summary.Artifacts, outPath)
			p.Audit.Emit(trace, name, "artifact_written",
				gledger.F{"file": filepath.Base(outPath), "bytes": len(content)})
		}

		// Collect items for the sidecar, deduped across tools: the event and the
		// item extractor can both emit the same dated line. Same title+date =
		// one item; keep the more specific kind (action > task > heads_up > event).
		for _, ev := range res.Events {
			// Drop noise: an "event" whose title is only a date phrase, or a
			// mid-sentence fragment, isn't a real event.
			if ev.ResolvedKind() == schema.KindEvent && (isBareDateTitle(ev.Title) || looksLikeFragment(ev.Title)) {
				continue
			}
			nt, d := normTitle(ev.Title), dateOf(ev)
			dup := -1
			for j := range sidecar.Items {
				ex := sidecar.Items[j]
				// Same item if titles match on the same date, OR two timed events
				// land on the exact same date+time (same meeting, different wording).
				if (dateOf(ex) == d && titlesMatch(nt, normTitle(ex.Title))) ||
					(timedStart(ev) && timedStart(ex) && ev.Start == ex.Start) {
					dup = j
					break
				}
			}
			if dup >= 0 {
				ex := sidecar.Items[dup]
				// Keep the better item: more specific kind, then the cleaner title
				// (a raw "Thursday, Oct 1st at 10:08 AM" loses to "Evacuation Drills").
				newRank, exRank := kindRank(ev.ResolvedKind()), kindRank(ex.ResolvedKind())
				if newRank > exRank || (newRank == exRank && titleQuality(ev.Title) > titleQuality(ex.Title)) {
					sidecar.Items[dup] = ev
				}
				continue
			}
			sidecar.Items = append(sidecar.Items, ev)
		}
		if res.Capability == tool.ReadOnly && strings.TrimSpace(res.Text) != "" {
			sidecar.Tools[name] = res.Text
		}

		summary.Events += len(res.Events)
		summary.Warnings = append(summary.Warnings, res.Warnings...)
		p.Audit.Emit(trace, name, "result", gledger.F{"events": len(res.Events), "warnings": res.Warnings})
	}

	// Review queue is computed from the deduped item set.
	for _, it := range sidecar.Items {
		if it.NeedsReview() {
			sidecar.NeedsReview = append(sidecar.NeedsReview, it)
		}
	}

	// Write the derived per-email sidecar (pipeline-owned, not a tool artifact).
	// Always written now that it carries the DocType classification (R2), so the
	// console can show how every email was routed — even a reference doc with no
	// extracted items.
	if sidecar.DocType != "" || len(sidecar.Tools) > 0 || len(sidecar.Items) > 0 {
		if b, err := json.MarshalIndent(sidecar, "", "  "); err == nil {
			sp := filepath.Join(p.OutboxDir, stem+".summary.json")
			// Not added to summary.Artifacts: that list is the user-acceptable .ics
			// outputs; the sidecar is derived state the UI reads, audited here.
			if err := os.WriteFile(sp, b, 0o644); err == nil {
				p.Audit.Emit(trace, "pipeline", "summary_written", gledger.F{
					"file": filepath.Base(sp), "tools": len(sidecar.Tools),
					"items": len(sidecar.Items), "needs_review": len(sidecar.NeedsReview)})
			}
		}
	}

	p.Audit.Emit(trace, "request", "end",
		gledger.F{"status": "ok", "events": summary.Events, "artifacts": len(summary.Artifacts)})
	return summary, nil
}
