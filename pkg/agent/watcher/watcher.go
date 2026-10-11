// Package watcher is the long-running email-to-calendar daemon.
//
// It watches an inbox for new .txt files and hands each to the pipeline under
// its own trace_id. Outputs land in outbox/, the input is moved to processed/,
// and every step is recorded to the audit log. The daemon never takes an
// irreversible action (it only writes inert files the user later accepts), and
// the watched folder is an untrusted ingestion boundary, so it enforces:
//   - a settle delay (never read a half-written file),
//   - a per-cycle rate cap (DoS, M10),
//
// alongside the size cap the pipeline already applies. This is the
// long-running-agent threat surface: indirect injection (M4), DoS (M10),
// goal drift (ASI06).
//
// Stdlib-only poll loop, so it runs anywhere, including inside the MicroVM.
package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/t0ul/emaildrop/pkg/agent/pipeline"
	"github.com/t0ul/gledger"
)

// Config holds the watched-folder layout and the ingestion limits.
type Config struct {
	Drop          string
	Inbox         string
	Outbox        string
	Processed     string
	Logs          string
	PollSeconds   time.Duration
	SettleSeconds time.Duration
	MaxPerCycle   int
}

// NewConfig derives the folder layout under drop and applies the defaults.
func NewConfig(drop string) Config {
	return Config{
		Drop:          drop,
		Inbox:         filepath.Join(drop, "inbox"),
		Outbox:        filepath.Join(drop, "outbox"),
		Processed:     filepath.Join(drop, "processed"),
		Logs:          filepath.Join(drop, "logs"),
		PollSeconds:   2 * time.Second,
		SettleSeconds: 1 * time.Second,
		MaxPerCycle:   20,
	}
}

// Watcher drives one pipeline over a watched folder.
type Watcher struct {
	Pipe *pipeline.Pipeline
	Cfg  Config
}

// Handled is the per-file outcome of one scan pass.
type Handled struct {
	pipeline.Summary
	MovedTo string `json:"moved_to,omitempty"`
	Error   string `json:"error,omitempty"`
}

// EnsureDirs creates the inbox, outbox, processed, and logs folders.
func (w *Watcher) EnsureDirs() error {
	for _, d := range []string{w.Cfg.Inbox, w.Cfg.Outbox, w.Cfg.Processed, w.Cfg.Logs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// readyFiles returns inbox .txt files idle at least SettleSeconds, sorted by
// name. A file still being written is skipped until it settles.
func (w *Watcher) readyFiles() []string {
	entries, err := os.ReadDir(w.Cfg.Inbox)
	if err != nil {
		return nil
	}
	now := time.Now()
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".txt") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) >= w.Cfg.SettleSeconds {
			out = append(out, filepath.Join(w.Cfg.Inbox, name))
		}
	}
	sort.Strings(out)
	return out
}

// moveToProcessed moves path into processed/ under a timestamped, collision-free
// name, so the inbox is never re-processed and the original is preserved.
func (w *Watcher) moveToProcessed(path string) (string, error) {
	stamp := time.Now().Format("20060102-150405")
	base := filepath.Base(path)
	dest := filepath.Join(w.Cfg.Processed, stamp+"."+base)
	for i := 1; ; i++ {
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			break
		}
		dest = filepath.Join(w.Cfg.Processed, fmt.Sprintf("%s-%d.%s", stamp, i, base))
	}
	return dest, os.Rename(path, dest)
}

// RunOnce performs one scan+process pass and returns a summary per file. One bad
// file never kills the daemon: its error is audited and the file is still moved.
func (w *Watcher) RunOnce() []Handled {
	files := w.readyFiles()
	if len(files) > w.Cfg.MaxPerCycle {
		files = files[:w.Cfg.MaxPerCycle]
	}
	out := make([]Handled, 0, len(files))
	for _, path := range files {
		name := filepath.Base(path)
		sum, err := w.Pipe.ProcessEmail(path)
		if err != nil {
			w.Pipe.Audit.Emit(gledger.NewTraceID(), "watcher", "process_error",
				gledger.F{"source": name, "error": err.Error()})
			dest, mverr := w.moveToProcessed(path)
			h := Handled{Summary: pipeline.Summary{Source: name}, Error: err.Error()}
			if mverr == nil {
				h.MovedTo = filepath.Base(dest)
			}
			out = append(out, h)
			continue
		}
		dest, mverr := w.moveToProcessed(path)
		h := Handled{Summary: sum}
		if mverr != nil {
			h.Error = mverr.Error()
			w.Pipe.Audit.Emit(sum.TraceID, "watcher", "move_error",
				gledger.F{"source": name, "error": mverr.Error()})
		} else {
			h.MovedTo = filepath.Base(dest)
		}
		trace := sum.TraceID
		if trace == "" {
			trace = gledger.NewTraceID()
		}
		w.Pipe.Audit.Emit(trace, "watcher", "handled", gledger.F{
			"source":    name,
			"moved_to":  h.MovedTo,
			"events":    sum.Events,
			"artifacts": len(sum.Artifacts),
			"rejected":  sum.Rejected,
		})
		out = append(out, h)
	}
	return out
}

// Watch runs the poll loop until ctx is cancelled. log, if non-nil, receives one
// human-readable line per handled file plus boot/stop notices.
func (w *Watcher) Watch(ctx context.Context, log func(string)) error {
	if err := w.EnsureDirs(); err != nil {
		return err
	}
	boot := gledger.NewTraceID()
	w.Pipe.Audit.Emit(boot, "watcher", "start",
		gledger.F{"inbox": w.Cfg.Inbox, "poll_s": w.Cfg.PollSeconds.Seconds()})
	if log != nil {
		log(fmt.Sprintf("watching %s", w.Cfg.Inbox))
		log(fmt.Sprintf("drop a .txt to process; outputs -> %s; Ctrl-C to stop", w.Cfg.Outbox))
	}
	ticker := time.NewTicker(w.Cfg.PollSeconds)
	defer ticker.Stop()
	for {
		for _, h := range w.RunOnce() {
			if log != nil {
				log(formatHandled(h))
			}
		}
		select {
		case <-ctx.Done():
			w.Pipe.Audit.Emit(boot, "watcher", "stop", gledger.F{})
			if log != nil {
				log("watcher stopped.")
			}
			return nil
		case <-ticker.C:
		}
	}
}

func formatHandled(h Handled) string {
	switch {
	case h.Error != "":
		return fmt.Sprintf("  !! %s: %s", h.Source, h.Error)
	case h.Rejected != "":
		return fmt.Sprintf("  xx %s: rejected (%s)", h.Source, h.Rejected)
	default:
		return fmt.Sprintf("  ok %s -> processed/%s  events=%d artifacts=%d",
			h.Source, h.MovedTo, h.Events, len(h.Artifacts))
	}
}
