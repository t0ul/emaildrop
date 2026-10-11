// Command emaildrop is the entry point for the watched-folder agent.
//
// It wires the event_extractor tool into a pipeline backed by a hash-chained
// audit log, then runs the watcher daemon over DROP_DIR. Drop a .txt into
// inbox/; its .ics (and any text artifacts) land in outbox/ and the input is
// moved to processed/. Every step is recorded to logs/audit.jsonl.
//
//	emaildrop            run the daemon (Ctrl-C to stop)
//	emaildrop --once     one scan pass, print JSON, exit (for testing)
//
// Config via env: DROP_DIR, AUDIT_LOG, POLL_SECONDS, SETTLE_SECONDS,
// MAX_PER_CYCLE, EXTRACT_MODE.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/t0ul/emaildrop/pkg/agent/pipeline"
	"github.com/t0ul/emaildrop/pkg/agent/roster"
	"github.com/t0ul/emaildrop/pkg/agent/tool"
	"github.com/t0ul/emaildrop/pkg/agent/watcher"
	"github.com/t0ul/emaildrop/pkg/rag"
	"github.com/t0ul/gledger"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "emaildrop:", err)
		os.Exit(1)
	}
}

func run() error {
	drop := envOr("DROP_DIR", mustCwd())
	cfg := watcher.NewConfig(drop)
	applyEnvDurations(&cfg)

	once := false
	for _, a := range os.Args[1:] {
		if a == "--once" {
			once = true
		}
	}
	if once {
		cfg.SettleSeconds = 0 // tests drop then scan immediately
	}

	reg := tool.NewRegistry()
	roster.Register(reg)

	auditPath := envOr("AUDIT_LOG", filepath.Join(cfg.Logs, "audit.jsonl"))
	audit, err := gledger.Open(auditPath, "watcher")
	if err != nil {
		return err
	}
	pipe := &pipeline.Pipeline{Registry: reg, Audit: audit, OutboxDir: cfg.Outbox, DefaultYear: time.Now().Year(), ToolNames: roster.Names()}

	// Index processed emails into the SQLite RAG corpus (queryable, persistent).
	// The raw file archived to processed/ stays the source of truth; this index
	// is rebuildable from it. DROP_DIR/corpus.db.
	if corpus, cerr := rag.Open(envOr("CORPUS_DB", filepath.Join(cfg.Drop, "corpus.db"))); cerr == nil {
		defer corpus.Close()
		pipe.Index = func(traceID, source, rawText string) error {
			return corpus.Add(rag.Doc{ID: traceID, Tenant: "", Text: rawText, Prov: rag.Untrusted})
		}
	} else {
		fmt.Fprintln(os.Stderr, "emaildrop: corpus index unavailable (emails still processed + archived):", cerr)
	}

	w := &watcher.Watcher{Pipe: pipe, Cfg: cfg}

	if once {
		if err := w.EnsureDirs(); err != nil {
			return err
		}
		out := w.RunOnce()
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return w.Watch(ctx, func(s string) { fmt.Println(s) })
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func applyEnvDurations(cfg *watcher.Config) {
	if v := os.Getenv("POLL_SECONDS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.PollSeconds = time.Duration(f * float64(time.Second))
		}
	}
	if v := os.Getenv("SETTLE_SECONDS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.SettleSeconds = time.Duration(f * float64(time.Second))
		}
	}
	if v := os.Getenv("MAX_PER_CYCLE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxPerCycle = n
		}
	}
}

func mustCwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}
