package watcher_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/pkg/agent/extractor"
	"github.com/t0ul/emaildrop/pkg/agent/pipeline"
	"github.com/t0ul/emaildrop/pkg/agent/tool"
	"github.com/t0ul/emaildrop/pkg/agent/watcher"
	"github.com/t0ul/gledger"
)

const email = `PS 123 Newsletter

Back to School Night: Thursday, September 29th at 6:00 PM in the auditorium

Days Off / No School:
Monday, October 12th - Italian Heritage Day
`

func newWatcher(t *testing.T) (*watcher.Watcher, string, func() (bool, int)) {
	t.Helper()
	dir := t.TempDir()
	cfg := watcher.NewConfig(dir)
	cfg.SettleSeconds = 0
	logPath := filepath.Join(cfg.Logs, "audit.jsonl")
	a, err := gledger.Open(logPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	reg := tool.NewRegistry()
	reg.Register(extractor.New())
	pipe := &pipeline.Pipeline{Registry: reg, Audit: a, OutboxDir: cfg.Outbox, DefaultYear: 2026}
	w := &watcher.Watcher{Pipe: pipe, Cfg: cfg}
	if err := w.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	return w, dir, func() (bool, int) { return gledger.VerifyFile(logPath) }
}

func drop(t *testing.T, w *watcher.Watcher, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(w.Cfg.Inbox, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunOnceProcessesMovesAndAudits(t *testing.T) {
	t.Setenv("EXTRACT_MODE", "regex") // no model needed
	w, _, verify := newWatcher(t)
	drop(t, w, "3.txt", email)

	handled := w.RunOnce()
	if len(handled) != 1 {
		t.Fatalf("expected 1 handled file, got %d", len(handled))
	}
	h := handled[0]
	if h.Error != "" {
		t.Fatalf("unexpected error: %s", h.Error)
	}
	if h.Events < 2 {
		t.Fatalf("expected >=2 events, got %d", h.Events)
	}
	if len(h.Artifacts) != 1 || !strings.HasSuffix(h.Artifacts[0], "3.events.ics") {
		t.Fatalf("expected outbox artifact 3.events.ics, got %v", h.Artifacts)
	}

	// input gone from inbox, present in processed/ under its stamped name
	if ents, _ := os.ReadDir(w.Cfg.Inbox); len(ents) != 0 {
		t.Errorf("inbox not drained: %v", ents)
	}
	if !strings.HasSuffix(h.MovedTo, "3.txt") {
		t.Errorf("unexpected processed name: %q", h.MovedTo)
	}
	if _, err := os.Stat(filepath.Join(w.Cfg.Processed, h.MovedTo)); err != nil {
		t.Errorf("processed file missing: %v", err)
	}
	if ok, n := verify(); !ok || n == 0 {
		t.Fatalf("audit chain failed to verify: ok=%v n=%d", ok, n)
	}
}

func TestSettleSkipsUnsettledFile(t *testing.T) {
	w, _, _ := newWatcher(t)
	w.Cfg.SettleSeconds = time.Hour // nothing is old enough
	drop(t, w, "fresh.txt", email)

	if h := w.RunOnce(); len(h) != 0 {
		t.Fatalf("unsettled file should be skipped, got %d", len(h))
	}
	if ents, _ := os.ReadDir(w.Cfg.Inbox); len(ents) != 1 {
		t.Errorf("unsettled file should remain in inbox, got %v", ents)
	}
}

func TestMaxPerCycleCaps(t *testing.T) {
	t.Setenv("EXTRACT_MODE", "regex")
	w, _, _ := newWatcher(t)
	w.Cfg.MaxPerCycle = 2
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		drop(t, w, n, email)
	}
	if h := w.RunOnce(); len(h) != 2 {
		t.Fatalf("expected cap of 2 per cycle, got %d", len(h))
	}
	if ents, _ := os.ReadDir(w.Cfg.Inbox); len(ents) != 1 {
		t.Errorf("expected 1 file left after capped cycle, got %v", ents)
	}
}

// The progress hooks see every file: picked up, then finished with its outcome.
func TestHooksReportEachFile(t *testing.T) {
	t.Setenv("EXTRACT_MODE", "regex")
	w, _, _ := newWatcher(t)
	var started []string
	var done []watcher.Handled
	w.OnStart = func(name string) { started = append(started, name) }
	w.OnDone = func(h watcher.Handled) { done = append(done, h) }
	drop(t, w, "a.txt", email)
	drop(t, w, "b.txt", email)
	w.RunOnce()
	if len(started) != 2 || started[0] != "a.txt" || started[1] != "b.txt" {
		t.Fatalf("OnStart must see each file in order, got %v", started)
	}
	if len(done) != 2 || done[0].Source != "a.txt" || done[1].MovedTo == "" || done[1].Events < 2 {
		t.Fatalf("OnDone must carry each file's outcome, got %+v", done)
	}
}
