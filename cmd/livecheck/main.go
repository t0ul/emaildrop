// Command livecheck runs the whole LLM-path gate with one command: it starts
// both llama.cpp model servers (ready-gated), runs the gouncer gateway
// in-process on :4000, then scores the extractor's LLM path against the labeled
// emails and checks the F1 gates. No separate terminals, no gouncer binary, no
// codesign, no MicroVM — the eval path needs only models + gateway.
//
//	go run ./cmd/livecheck              # defaults: planner :11435, coder :11436
//	go run ./cmd/livecheck -bin /path/to/llama
//
// Exit 0 iff every gate passes. (The MicroVM/controlplane demo is separate; see
// docs/RUNBOOK.md.)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/t0ul/emaildrop/internal/modelserve"
	"github.com/t0ul/emaildrop/pkg/agent/eval"
	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/gouncer"
)

const (
	host        = "127.0.0.1"
	plannerPort = 11435
	coderPort   = 11436
	gatewayAddr = ":4000"
)

type gate struct {
	label string
	min   float64
}

func main() {
	bin := flag.String("bin", filepath.Join(home(), ".llama-app", "llama"), "llama.cpp server binary")
	dir := flag.String("dir", "set-up/vm-assets", "directory holding the .gguf models")
	ready := flag.Duration("ready", 180*time.Second, "per-model readiness timeout")
	reclaim := flag.Bool("reclaim", true, "kill any process already listening on the model/gateway ports before starting")
	flag.Parse()

	// This harness owns these ports for the length of a run; clear leftovers from
	// a crashed or still-running previous attempt so it is re-runnable.
	if *reclaim {
		for _, p := range []int{plannerPort, coderPort, 4000} {
			modelserve.ReclaimPort(p, os.Stdout)
		}
	}

	gates := []gate{
		{"testdata/emaildrop/labels/3.json", 1.00},
		{"testdata/emaildrop/labels/1.json", 0.87},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 1. Model servers.
	sup := &modelserve.Supervisor{
		Servers: []modelserve.Server{
			modelserve.LlamaServer("planner", *bin, host, filepath.Join(*dir, "llama-3.2-3b.gguf"), plannerPort, 8192),
			modelserve.LlamaServer("coder", *bin, host, filepath.Join(*dir, "qwen1.5b.gguf"), coderPort, 4096),
		},
	}
	if err := sup.Start(ctx); err != nil {
		log.Fatalf("livecheck: %v", err)
	}
	defer sup.Shutdown()
	fmt.Println("livecheck: waiting for models to load...")
	if err := sup.WaitHealthy(ctx, *ready); err != nil {
		log.Fatalf("livecheck: %v", err)
	}

	// 2. gouncer gateway, in-process.
	gw, err := gouncer.New(gouncer.Config{
		Routes: map[string]gouncer.Route{
			"planner": {Upstream: fmt.Sprintf("http://%s:%d", host, plannerPort)},
			"coder":   {Upstream: fmt.Sprintf("http://%s:%d", host, coderPort)},
		},
		UpstreamTimeout: 120 * time.Second,
	})
	if err != nil {
		log.Fatalf("livecheck: gateway: %v", err)
	}
	srv := &http.Server{Addr: gatewayAddr, Handler: gw, ReadHeaderTimeout: 10 * time.Second}
	go srv.ListenAndServe()
	defer srv.Close()
	if err := waitListening(ctx, "127.0.0.1"+gatewayAddr, 5*time.Second); err != nil {
		log.Fatalf("livecheck: gateway did not come up: %v", err)
	}
	fmt.Printf("livecheck: gateway up on %s; running eval gates...\n\n", gatewayAddr)

	// 3. Eval gates through the LLM path (extractor -> gouncer -> planner); mode
	// is passed explicitly via eval.ScoreWithMode, not a global env.

	// Persist F1 to the inventory so the promotion gate can read a real score.
	var inv *datastore.Store
	if db, derr := datastore.Open(filepath.Join("controlplane", "logs", "inventory.db")); derr == nil {
		inv = db
		defer inv.Close()
	}

	allPass := true
	for _, g := range gates {
		rep, err := eval.ScoreWithMode(g.label, true, "llm")
		if err != nil {
			fmt.Printf("ERROR %-40s %v\n", g.label, err)
			allPass = false
			continue
		}
		if inv != nil {
			_ = inv.RecordEval(rep.Source, rep.F1)
		}
		pass := rep.F1 >= g.min-1e-9
		if !pass {
			allPass = false
		}
		fmt.Printf("%-4s %-40s f1=%.2f (gate >=%.2f)  P=%.2f R=%.2f  matched=%d/%d\n",
			passLabel(pass), rep.Source, rep.F1, g.min, rep.Precision, rep.Recall, rep.Matched, rep.Gold)
	}

	fmt.Println()
	if !allPass {
		fmt.Println("livecheck: FAILED")
		os.Exit(1)
	}
	fmt.Println("livecheck: PASSED")
}

func passLabel(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// waitListening blocks until addr accepts a TCP connection or the timeout passes.
func waitListening(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %s", timeout)
}

func home() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}
