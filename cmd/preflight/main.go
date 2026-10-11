// Command preflight reports whether the LIVE-model path is ready, and makes the
// live-vs-offline split explicit so "tests pass" is never mistaken for "beaten
// against a live model."
//
//	go run ./cmd/preflight
//
// OFFLINE (no model, always runnable): go test ./... — unit tests, and the ADD
// red-team scorecard (cmd/scorecard). ADD cases are white-box, in-process
// undefended/defended pairs: they prove the CONTROLS deterministically and never
// call llama/qwen. LIVE (needs the models serving): the eval F1 gate
// (cmd/livecheck) and the LLM extractor/ensemble, which call the gouncer gateway.
//
// This checks the GGUF model files are downloaded and whether the ports answer,
// and tells you exactly what to run if not. Exits non-zero only when the model
// files are missing (the live path cannot run at all).
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/t0ul/emaildrop/internal/assets"
)

func main() {
	dir := flag.String("dir", "set-up/vm-assets", "directory holding the .gguf models")
	planner := flag.String("planner-model", "llama-3.2-3b.gguf", "planner GGUF filename")
	coder := flag.String("coder-model", "qwen1.5b.gguf", "coder GGUF filename")
	flag.Parse()

	fmt.Println("AI-Security preflight — live-model path readiness")
	fmt.Println("  OFFLINE (always runnable, no model): go test ./...  +  go run ./cmd/scorecard (ADD)")
	fmt.Println("  NOTE: ADD/scorecard are white-box in-process attack/defense pairs — they prove the")
	fmt.Println("        controls deterministically and do NOT call a live model.")
	fmt.Println("  LIVE (needs models serving): go run ./cmd/livecheck (F1 gate) + the LLM extractor.")
	fmt.Println()

	missing := false
	for label, name := range map[string]string{"planner (llama)": *planner, "coder (qwen)": *coder} {
		p := filepath.Join(*dir, name)
		info, err := os.Stat(p)
		switch {
		case err != nil:
			fmt.Printf("  ✗ %-16s %s — NOT DOWNLOADED\n", label, p)
			missing = true
		case assets.VerifyGGUFHeader(p) != nil:
			fmt.Printf("  ✗ %-16s %s — present but not a valid GGUF\n", label, p)
			missing = true
		default:
			fmt.Printf("  ✓ %-16s %s (%d MB)\n", label, p, info.Size()>>20)
		}
	}

	fmt.Println()
	for label, addr := range map[string]string{"gateway (gouncer)": "127.0.0.1:4000", "planner port": "127.0.0.1:11435", "coder port": "127.0.0.1:11436"} {
		if reachable(addr) {
			fmt.Printf("  ✓ %-18s %s answering\n", label, addr)
		} else {
			fmt.Printf("  ·  %-18s %s not serving\n", label, addr)
		}
	}

	fmt.Println()
	if missing {
		fmt.Println("Models missing. Download + verify them, then serve:")
		fmt.Println("  go run ./cmd/prepareassets   # verified GGUF download into", *dir)
		fmt.Println("  go run ./cmd/modeld          # serve planner :11435 + coder :11436 (gouncer :4000)")
		fmt.Println("The offline suite still runs without them: go test ./...")
		os.Exit(1)
	}
	fmt.Println("Models present. For the LIVE path: go run ./cmd/modeld, then go run ./cmd/livecheck.")
}

func reachable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
