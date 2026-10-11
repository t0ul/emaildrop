// Command replay reconstructs an incident from the audit log: given a trace_id,
// it prints the ordered timeline of every recorded step and verifies the
// hash-chain so the evidence is known-untampered. With no -trace it lists the
// traces present. This is the forensic replay (M12/M18).
//
//	replay -log controlplane/logs/audit.jsonl -trace <id>
//	replay -log controlplane/logs/audit.jsonl            # list traces
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/t0ul/emaildrop/pkg/ir"
	"github.com/t0ul/gledger"
)

func main() {
	log := flag.String("log", "controlplane/logs/audit.jsonl", "audit log path")
	trace := flag.String("trace", "", "trace_id to replay (empty: list traces)")
	flag.Parse()

	events, err := ir.Load(*log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "replay:", err)
		os.Exit(1)
	}

	ok, n := gledger.VerifyFile(*log)
	fmt.Printf("log: %s  records=%d  chain_ok=%t\n\n", *log, n, ok)
	if !ok {
		fmt.Println("WARNING: audit chain does not verify — evidence may be tampered.")
	}

	if *trace == "" {
		fmt.Println("traces (newest first):")
		for _, id := range ir.Traces(events) {
			fmt.Printf("  %s  (%d events)\n", id, len(ir.Timeline(events, id)))
		}
		return
	}

	tl := ir.Timeline(events, *trace)
	if len(tl) == 0 {
		fmt.Printf("no events for trace %s\n", *trace)
		return
	}
	fmt.Printf("== incident replay: %s ==\n", *trace)
	fmt.Print(ir.Format(tl))
}
