package server

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Progress is what the watcher is doing right now and what it did lately, for
// the Add Data progress screen: a bulk drop of forty emails used to look like
// nothing was happening. The watcher's hooks feed it; the handler adds how many
// files are still waiting in the inbox.
type Progress struct {
	mu      sync.Mutex
	current string
	since   time.Time
	done    int
	failed  int
	recent  []ProgressItem
	started time.Time
}

// ProgressItem is one finished file.
type ProgressItem struct {
	File       string `json:"file"`
	MovedTo    string `json:"moved_to,omitempty"`
	Sidecar    string `json:"sidecar,omitempty"` // <stem>.summary.json, for the result view
	Events     int    `json:"events"`
	Artifacts  int    `json:"artifacts"`
	Error      string `json:"error,omitempty"`
	Seconds    int    `json:"seconds"`
	FinishedAt string `json:"finished_at"`
}

const progressKeep = 25

// NewProgress returns an empty tracker.
func NewProgress() *Progress { return &Progress{started: time.Now()} }

// Begin records that the watcher picked up name.
func (p *Progress) Begin(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current, p.since = name, time.Now()
}

// End records name's outcome and clears it as the current file.
func (p *Progress) End(name, movedTo string, events, artifacts int, errText string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	secs := 0
	if p.current == name && !p.since.IsZero() {
		secs = int(time.Since(p.since).Seconds())
	}
	it := ProgressItem{File: name, MovedTo: movedTo, Events: events, Artifacts: artifacts, Error: errText,
		Seconds: secs, FinishedAt: time.Now().Format(time.RFC3339)}
	if errText == "" {
		p.done++
		it.Sidecar = strings.TrimSuffix(name, ".txt") + ".summary.json"
	} else {
		p.failed++
	}
	p.recent = append([]ProgressItem{it}, p.recent...)
	if len(p.recent) > progressKeep {
		p.recent = p.recent[:progressKeep]
	}
	p.current, p.since = "", time.Time{}
}

// snapshot is the JSON shape the UI polls, with pending counted from the inbox.
func (p *Progress) snapshot(pending int) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	var cur any
	if p.current != "" {
		cur = map[string]any{"file": p.current, "seconds": int(time.Since(p.since).Seconds())}
	}
	recent := append([]ProgressItem{}, p.recent...)
	return map[string]any{
		"pending": pending, "current": cur, "done": p.done, "failed": p.failed,
		"active": pending > 0 || p.current != "", "recent": recent,
		"since": p.started.Format(time.RFC3339),
	}
}

// pendingInInbox counts the .txt files still waiting in the inbox.
func (s *Server) pendingInInbox() int {
	if s.InboxPath == "" {
		return 0
	}
	entries, err := os.ReadDir(s.InboxPath)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".txt") && !strings.HasPrefix(e.Name(), ".") {
			n++
		}
	}
	return n
}

// progress serves the watcher's state for the Add Data progress screen.
func (s *Server) progress(w http.ResponseWriter, _ *http.Request) {
	if s.Progress == nil {
		writeJSON(w, map[string]any{"pending": s.pendingInInbox(), "current": nil, "done": 0, "failed": 0, "active": s.pendingInInbox() > 0, "recent": []ProgressItem{}})
		return
	}
	writeJSON(w, s.Progress.snapshot(s.pendingInInbox()))
}
