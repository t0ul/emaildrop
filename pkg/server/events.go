package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/t0ul/emaildrop/pkg/agent/ics"
	"github.com/t0ul/emaildrop/pkg/agent/items"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

var reSafeName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// drop accepts an uploaded .txt (form field "email") or pasted text (field
// "text") and writes it into the watched inbox, where the watcher picks it up.
// The content is untrusted — the pipeline guards/sanitizes it on ingest; here we
// only harden the filename (basename, safe chars, .txt).
func (s *Server) drop(w http.ResponseWriter, r *http.Request) {
	if s.paused() {
		http.Error(w, "processing paused by the kill switch", http.StatusServiceUnavailable)
		return
	}
	var data []byte
	name := fmt.Sprintf("drop-%d.txt", time.Now().UnixNano())

	if file, hdr, err := r.FormFile("email"); err == nil {
		defer file.Close()
		data, _ = io.ReadAll(io.LimitReader(file, 256*1024))
		if hdr != nil && hdr.Filename != "" {
			name = safeName(hdr.Filename)
		}
	} else if text := r.FormValue("text"); strings.TrimSpace(text) != "" {
		data = []byte(text)
	} else {
		http.Error(w, "no email file or text provided", http.StatusBadRequest)
		return
	}

	dest := filepath.Join(s.InboxPath, name)
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "file": name})
}

func safeName(n string) string {
	n = reSafeName.ReplaceAllString(filepath.Base(n), "_")
	if !strings.HasSuffix(strings.ToLower(n), ".txt") {
		n += ".txt"
	}
	return n
}

// Event is a calendar item rendered in the owner view (meeting, task, heads-up,
// or action — see Kind).
type Event struct {
	Title       string `json:"title"`
	Start       string `json:"start"`
	End         string `json:"end"`
	Location    string `json:"location"`
	AllDay      bool   `json:"all_day"`
	HasReminder bool   `json:"has_reminder"`
	Signed      bool   `json:"signed"` // the .ics has a valid agent content credential (M20)
	File        string `json:"file"`
	Kind        string `json:"kind"`           // event|task|heads_up|action (from X-KIND)
	Due         string `json:"due,omitempty"`  // task/action due date
	URL         string `json:"url,omitempty"`  // action target
	Notes       string `json:"notes,omitempty"` // source-context description (from the .ics DESCRIPTION)
	Key         string `json:"key,omitempty"`  // content fingerprint, for delete
}

// eventKey is the content fingerprint for the delete overlay: day | normalized title.
// Stable across projection rebuilds (matches the dedup identity), so a deleted event
// stays deleted.
func eventKey(e Event) string { return dayOf(e) + "|" + normTitle(e.Title) }

// events reads the accepted .ics artifacts in OutboxDir and returns their events
// for the calendar view. The .ics is the source of truth the user accepts.
// allEvents returns the parsed outbox events, cached and keyed by the outbox
// directory's modification time so repeated requests (Calendar, Items, Summary,
// and now the chat's week schedule) don't re-read and re-parse every .ics each
// time. accept/reject and new drops add or remove files, which bumps the dir
// mtime and invalidates the cache. The returned slice is read-only — callers
// render it, they must not mutate it in place.
// EventStore is the DB-backed events projection the calendar view serves from. The
// signed .ics outbox stays the source of truth (it carries the M20 content
// credential); this projection is rebuilt from it whenever the outbox changes, and
// serves the deduped calendar without a per-request .ics scan.
type EventStore interface {
	ReplaceEvents(fingerprint string, events []Event) error
	LoadEvents() (fingerprint string, events []Event, err error)
}

// allEvents returns the deduped calendar events, served in three tiers: an in-memory
// cache, then the DB projection (persists across restarts), then a rebuild from the
// signed .ics (which re-verifies signatures and re-persists the projection). The
// outbox fingerprint keys all three — any .ics add/remove/edit invalidates them, so a
// tampered .ics re-verifies rather than serving a stale signed=true (a security
// invariant), and the DB is never served stale.
func (s *Server) allEvents() []Event {
	if s.OutboxDir == "" {
		return nil
	}
	fp := s.outboxFingerprint()
	s.evMu.Lock()
	if s.evCache != nil && fp == s.evFP {
		cached := s.evCache
		s.evMu.Unlock()
		return cached
	}
	s.evMu.Unlock()
	// DB projection: serve from it when it was built from the current outbox.
	if s.Events != nil && fp != "" {
		if dbFP, evs, err := s.Events.LoadEvents(); err == nil && dbFP == fp {
			s.evMu.Lock()
			s.evCache, s.evFP = evs, fp
			s.evMu.Unlock()
			return evs
		}
	}
	// Rebuild from the signed .ics (re-verifies), then persist the projection.
	out := s.readAllEvents()
	if s.Events != nil {
		_ = s.Events.ReplaceEvents(fp, out)
		log.Printf("events: rebuilt DB projection from signed .ics (%d events)", len(out))
	}
	s.evMu.Lock()
	s.evCache, s.evFP = out, fp
	s.evMu.Unlock()
	return out
}

// outboxFingerprint is a cheap key over the outbox's .ics/.sig entries: it stats
// (via ReadDir) but never reads or parses, so a cache hit skips all I/O + parse +
// signature verification. Any add/remove/edit changes it.
func (s *Server) outboxFingerprint() string {
	entries, err := os.ReadDir(s.OutboxDir)
	if err != nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(projectionVersion + "|") // bump to invalidate projections on a logic change
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if !strings.HasSuffix(n, ".ics") && !strings.HasSuffix(n, ".sig") {
			continue
		}
		if info, ierr := e.Info(); ierr == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", e.Name(), info.Size(), info.ModTime().UnixNano())
		}
	}
	return b.String()
}

// projectionVersion keys the events/items/summaries DB projections to the derivation
// logic (dedup, cleaning, filtering). Bump it when that logic changes so the stored
// projections rebuild from source instead of serving a stale result.
const projectionVersion = "v14"

// readAllEvents reads every .ics in the outbox into a sorted, de-duplicated event
// list. allEvents caches the result.
func (s *Server) readAllEvents() []Event {
	var out []Event
	if s.OutboxDir != "" {
		entries, _ := os.ReadDir(s.OutboxDir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".ics") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(s.OutboxDir, e.Name()))
			if err != nil {
				continue
			}
			signed := s.verifySig(e.Name(), raw)
			evs := parseICS(string(raw), e.Name())
			for i := range evs {
				evs[i].Signed = signed
				// Clean legacy/raw .ics titles at projection time so existing events
				// get short names without re-processing; dropFragments then culls any
				// that cleaned down to a lowercase mid-sentence fragment. Idempotent.
				evs[i].Title = items.Tidy(evs[i].Title)
			}
			out = append(out, evs...)
		}
	}
	out = dropFragments(out)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return dedupEvents(out)
}

// dropFragments removes events whose title is a sentence fragment the extractor
// grabbed rather than a real event name. A real title starts with a capital or a
// digit ("Back to School Night", "3-407 visits the library"); a fragment starts with
// a lowercase letter ("went smoothly. See below…", "meeting at 8:30 AM…"). High
// precision — a clean title never starts lowercase.
func dropFragments(in []Event) []Event {
	out := in[:0]
	for _, e := range in {
		t := strings.TrimSpace(e.Title)
		if t == "" || (t[0] >= 'a' && t[0] <= 'z') {
			continue // a sentence fragment (a clean title never starts lowercase)
		}
		if items.IsJunkTitle(t) {
			continue // a date, greeting or "nothing scheduled" line grabbed as a title
		}
		out = append(out, e)
	}
	return out
}

func (s *Server) events(w http.ResponseWriter, _ *http.Request) {
	all := s.allEvents()
	var hidden map[string]bool
	if s.HiddenEvents != nil {
		hidden, _ = s.HiddenEvents.LoadHiddenEvents()
	}
	out := make([]Event, 0, len(all))
	for _, e := range all {
		k := eventKey(e)
		if hidden[k] {
			continue // deleted via the overlay
		}
		e.Key = k
		out = append(out, e)
	}
	writeJSON(w, map[string]any{"events": out, "inbox": s.InboxPath})
}

// buildExport assembles the calendar for an .ics download: every extracted event and dated
// reminder (the deduped, non-hidden set shown in Calendar + Tasks). Reminders (tasks /
// heads-ups / actions) are written as all-day EVENTS prefixed "Reminder:" rather than VTODOs,
// because Google Calendar ignores VTODO on import — this way everything actually shows up.
// When onlyNew is set, events already recorded as exported are skipped (incremental export,
// so the household imports each event into their real calendar exactly once). It returns the
// schema events to write and their content fingerprints (for marking them exported).
func (s *Server) buildExport(onlyNew bool) ([]schema.Event, []string) {
	var hidden, exported map[string]bool
	if s.HiddenEvents != nil {
		hidden, _ = s.HiddenEvents.LoadHiddenEvents()
	}
	if onlyNew && s.Exported != nil {
		exported, _ = s.Exported.LoadExported()
	}
	// The server's display timestamps are "YYYY-MM-DD HH:MM" (space, no seconds); the .ics
	// writer wants RFC3339 "YYYY-MM-DDTHH:MM:SS". Bridge the two so a timed event exports.
	norm := func(s string) string {
		if len(s) >= 16 && s[10] == ' ' {
			s = s[:10] + "T" + s[11:]
		}
		if len(s) == 16 {
			s += ":00"
		}
		return s
	}
	var evs []schema.Event
	var keys []string
	for _, e := range s.allEvents() {
		k := eventKey(e)
		if hidden[k] || exported[k] {
			continue
		}
		notes := e.Notes
		if strings.EqualFold(strings.TrimSpace(notes), strings.TrimSpace(e.Title)) {
			notes = "" // the source line is just the title — a redundant description
		}
		se := schema.Event{Title: e.Title, Start: norm(e.Start), End: norm(e.End), AllDay: e.AllDay, Location: e.Location, Notes: notes, Kind: schema.KindEvent}
		if e.Kind != "" && e.Kind != "event" {
			day := e.Due
			if day == "" {
				day = e.Start
			}
			if len(day) >= 10 {
				day = day[:10]
			}
			if day == "" {
				continue // an undated reminder has no place on a calendar
			}
			se.AllDay, se.Start, se.End, se.Title = true, day, "", "Reminder: "+e.Title
		}
		evs = append(evs, se)
		keys = append(keys, k)
	}
	return evs, keys
}

// writeICS writes the events as a downloadable .ics attachment.
func (s *Server) writeICS(w http.ResponseWriter, evs []schema.Event) {
	body, _, err := ics.Write(evs, "Family calendar")
	if err != nil {
		http.Error(w, "export failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="family-calendar.ics"`)
	_, _ = io.WriteString(w, body)
}

// calendarExport serves the WHOLE calendar as one .ics (every event + reminder), no marking —
// the "export everything" path. Consumer-scoped (the user's own derived calendar).
func (s *Server) calendarExport(w http.ResponseWriter, _ *http.Request) {
	evs, _ := s.buildExport(false)
	s.writeICS(w, evs)
}

// calendarExportNew serves only events NOT yet exported, and marks them exported so the next
// download skips them (incremental export → no duplicates on the real calendar). The count of
// new events is returned in X-New-Count so the UI can say "nothing new" without downloading an
// empty file. CSRF + authz(write/calendar) — it mutates the exported overlay.
func (s *Server) calendarExportNew(w http.ResponseWriter, _ *http.Request) {
	evs, keys := s.buildExport(true)
	w.Header().Set("X-New-Count", strconv.Itoa(len(evs)))
	if len(keys) > 0 && s.Exported != nil {
		_ = s.Exported.MarkExported(keys)
	}
	s.writeICS(w, evs)
}

// calendarResetExported clears the exported overlay so a subsequent export includes everything
// again (e.g. switching to a new calendar). CSRF + authz(write/calendar).
func (s *Server) calendarResetExported(w http.ResponseWriter, _ *http.Request) {
	if s.Exported != nil {
		if err := s.Exported.ResetExported(); err != nil {
			http.Error(w, "reset failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, map[string]any{"ok": true})
}

// HiddenEventStore is the delete overlay for calendar events (hide by fingerprint,
// without mutating the source .ics). Nil = events cannot be deleted.
type HiddenEventStore interface {
	HideEvent(key string) error
	LoadHiddenEvents() (map[string]bool, error)
}

// ExportedStore records which calendar events have already been downloaded, so an
// incremental export skips them (the household imports each event once). Nil = every
// export includes everything (no incremental tracking).
type ExportedStore interface {
	MarkExported(keys []string) error
	LoadExported() (map[string]bool, error)
	ResetExported() error
}

// eventCreate writes a manually-entered calendar event to its own .ics (the household
// "add event" — a human touch not tied to any email). The operator's own input, so no
// HITL; still CSRF + authz(write/calendar) gated, and sanitized by the .ics writer.
func (s *Server) eventCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title    string `json:"title"`
		Start    string `json:"start"`
		End      string `json:"end"`
		Location string `json:"location"`
		AllDay   bool   `json:"all_day"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.Start) == "" {
		http.Error(w, "title and start are required", http.StatusBadRequest)
		return
	}
	if s.toolsBlocked() {
		http.Error(w, "blocked by the kill switch", http.StatusServiceUnavailable)
		return
	}
	ev := schema.Event{Title: req.Title, Start: req.Start, End: req.End, Location: req.Location, AllDay: req.AllDay, SourceEmail: "manual"}
	text, _, err := ics.Write([]schema.Event{ev}, "Manual")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	outName := fmt.Sprintf("manual-%d.events.ics", time.Now().UnixNano())
	if err := os.WriteFile(filepath.Join(s.OutboxDir, outName), []byte(text), 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// If the deleted overlay had the same fingerprint, clear it so re-adding re-shows.
	writeJSON(w, map[string]any{"ok": true, "file": outName})
}

// eventDelete hides a calendar event by its content fingerprint. The source .ics is left
// intact (tamper-evident record); the event is filtered from the calendar projection.
func (s *Server) eventDelete(w http.ResponseWriter, r *http.Request) {
	if s.HiddenEvents == nil {
		http.Error(w, "event delete not configured", http.StatusNotImplemented)
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || strings.TrimSpace(req.Key) == "" {
		http.Error(w, "key required", http.StatusBadRequest)
		return
	}
	if err := s.HiddenEvents.HideEvent(req.Key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "key": req.Key})
}

// parseICS extracts events from an .ics body (minimal VEVENT reader).
func parseICS(body, file string) []Event {
	var out []Event
	var cur *Event
	inAlarm := false // VALARM carries its own SUMMARY/DESCRIPTION; those are the alarm's, not the event's
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "BEGIN:VEVENT":
			cur, inAlarm = &Event{File: file, Kind: "event"}, false
		case line == "BEGIN:VTODO":
			cur, inAlarm = &Event{File: file, Kind: "task"}, false
		case line == "END:VEVENT", line == "END:VTODO":
			if cur != nil {
				out = append(out, *cur)
				cur = nil
			}
		case cur == nil:
			continue
		case line == "BEGIN:VALARM":
			cur.HasReminder = true
			inAlarm = true
		case line == "END:VALARM":
			inAlarm = false
		case inAlarm:
			continue // skip the alarm's own fields (its DESCRIPTION is not the event's)
		case strings.HasPrefix(line, "X-KIND:"):
			cur.Kind = strings.TrimPrefix(line, "X-KIND:")
		case strings.HasPrefix(line, "SUMMARY:"):
			cur.Title = unescapeICS(strings.TrimPrefix(line, "SUMMARY:"))
		case strings.HasPrefix(line, "LOCATION:"):
			cur.Location = unescapeICS(strings.TrimPrefix(line, "LOCATION:"))
		case strings.HasPrefix(line, "DESCRIPTION:"):
			cur.Notes = unescapeICS(strings.TrimPrefix(line, "DESCRIPTION:"))
		case strings.HasPrefix(line, "URL:"):
			cur.URL = unescapeICS(strings.TrimPrefix(line, "URL:"))
		case strings.HasPrefix(line, "DTSTART;VALUE=DATE:"):
			cur.Start = fmtDate(strings.TrimPrefix(line, "DTSTART;VALUE=DATE:"))
			cur.AllDay = true
		case strings.HasPrefix(line, "DTSTART:"):
			cur.Start = fmtDateTime(strings.TrimPrefix(line, "DTSTART:"))
		case strings.HasPrefix(line, "DTEND:"):
			cur.End = fmtDateTime(strings.TrimPrefix(line, "DTEND:"))
		case strings.HasPrefix(line, "DUE;VALUE=DATE:"):
			cur.Due = fmtDate(strings.TrimPrefix(line, "DUE;VALUE=DATE:"))
			cur.Start = cur.Due // VTODO has no DTSTART; use Due for sort/display
			cur.AllDay = true
		case strings.HasPrefix(line, "DUE:"):
			cur.Due = fmtDateTime(strings.TrimPrefix(line, "DUE:"))
			cur.Start = cur.Due
		}
	}
	return out
}

func fmtDate(s string) string { // 20260924 -> 2026-09-24
	if len(s) >= 8 {
		return s[0:4] + "-" + s[4:6] + "-" + s[6:8]
	}
	return s
}

func fmtDateTime(s string) string { // 20260924T083000 -> 2026-09-24 08:30
	if len(s) >= 15 {
		return fmtDate(s[:8]) + " " + s[9:11] + ":" + s[11:13]
	}
	return fmtDate(s)
}

func unescapeICS(s string) string {
	r := strings.NewReplacer(`\,`, ",", `\;`, ";", `\n`, " ", `\\`, `\`)
	return r.Replace(s)
}
