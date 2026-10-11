// Command modeld brings up the local dual-SLM runtime with one command: the
// Llama-3.2-3B planner and the Qwen-1.5B coder, each served by llama.cpp. It
// replaces the two hand-run `llama serve ...` shells — it launches both, waits
// for their /health endpoints, streams prefixed logs, and shuts both down
// cleanly on Ctrl-C.
//
//	modeld                      # defaults: planner :11435, coder :11436
//	modeld -bin /path/to/llama -dir set-up/vm-assets
//
// gouncer routes the logical "planner"/"coder" models to these ports; keep the
// bind host at 127.0.0.1 (least exposure) unless a gateway on another host needs
// them.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/emaildrop/internal/modelserve"
	"github.com/t0ul/emaildrop/pkg/datastore"
)

func main() {
	defaultBin := filepath.Join(homeDir(), ".llama-app", "llama")

	bin := flag.String("bin", defaultBin, "llama.cpp server binary")
	dir := flag.String("dir", "set-up/vm-assets", "directory holding the .gguf models")
	host := flag.String("host", "127.0.0.1", "bind host for the model servers (infra override)")
	db := flag.String("db", "", "inventory.db holding the model catalog (empty = built-in bootstrap seed)")
	ready := flag.Duration("ready", 120*time.Second, "per-server readiness timeout")
	flag.Parse()

	// The served models (name/file/port/ctx) come from the catalog — the single
	// source of truth — not per-model flags. -db reads the operator-editable catalog;
	// empty uses the fail-closed bootstrap seed.
	catalog := resolveCatalog(*db)
	var servers []modelserve.Server
	for _, m := range catalog {
		servers = append(servers, modelserve.LlamaServer(m.Name, *bin, *host, filepath.Join(*dir, m.File), m.Port, m.Ctx))
	}
	sup := &modelserve.Supervisor{Servers: servers}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println("modeld: starting dual-SLM runtime (Ctrl-C to stop)...")
	if err := sup.Run(ctx, *ready); err != nil {
		log.Fatalf("modeld: %v", err)
	}
	fmt.Println("modeld: stopped.")
}

// resolveCatalog returns the model catalog from the inventory DB (seeded on first
// use) when a -db is given, else the built-in fail-closed bootstrap seed. The model
// list is never hardcoded in this command.
func resolveCatalog(dbPath string) []modelcatalog.Entry {
	if dbPath == "" {
		return modelcatalog.DefaultSeed()
	}
	inv, err := datastore.Open(dbPath)
	if err != nil {
		log.Fatalf("modeld: open catalog db: %v", err)
	}
	defer inv.Close()
	cat, err := inv.SeedModelCatalogIfEmpty(modelcatalog.DefaultSeed())
	if err != nil {
		log.Fatalf("modeld: load catalog: %v", err)
	}
	return cat
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}
