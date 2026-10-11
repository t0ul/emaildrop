// Command eval scores the event extractor against a hand-labeled ground-truth
// file and prints precision/recall/F1 plus field accuracy. It exits 0 only when
// F1 == 1.00, so it doubles as a CI regression gate.
//
//	eval [labels/3.json]     score one label file (default: the 3.json gate)
//	eval --tool labels/1.json run the registered tool path (honors EXTRACT_MODE)
//
// The LLM path needs llama.cpp + the gouncer gateway up; set EXTRACT_MODE=regex
// to score the deterministic path without a model.
package main

import (
	"fmt"
	"os"

	"github.com/t0ul/emaildrop/pkg/agent/eval"
)

// defaultLabel is the 3.txt gate. The sample emails and labels live in the
// Go-owned testdata tree (migrated out of the deleted Python module-3).
const defaultLabel = "testdata/emaildrop/labels/3.json"

func main() {
	labelPath := defaultLabel
	useTool := false
	for _, a := range os.Args[1:] {
		switch a {
		case "--tool":
			useTool = true
		default:
			labelPath = a
		}
	}

	rep, err := eval.Score(labelPath, useTool)
	if err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		os.Exit(2)
	}
	fmt.Println(rep.String())
	if rep.F1 == 1.0 {
		os.Exit(0)
	}
	os.Exit(1)
}
