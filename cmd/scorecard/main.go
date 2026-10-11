// Command scorecard is the M12 full-chain security gate, now powered by the ADD
// framework (github.com/t0ul/ADD). It evaluates every red-team technique's ADD
// invariant — the attack breaches the undefended baseline and the control blocks
// it — printing the attack-success-rate before and after each defense, plus the
// OWASP coverage grid. It exits non-zero if any invariant is violated, so it
// doubles as a CI security-regression gate: a real incident becomes a permanent
// check that cannot silently recur.
package main

import (
	"fmt"
	"os"

	"github.com/t0ul/ADD"
	"github.com/t0ul/emaildrop/pkg/redteam"
)

func main() {
	fmt.Println("== security scorecard (ADD: ASR before -> after) ==")
	fmt.Printf("%-24s %-8s %8s %8s\n", "technique", "risk", "before", "after")

	techniques := redteam.Techniques()
	outs := make([]add.Outcome, 0, len(techniques))
	failed := 0
	for _, tech := range techniques {
		out, violations := add.Evaluate(tech)
		outs = append(outs, out)
		flag := "ok"
		if len(violations) > 0 {
			flag = "FAIL"
			failed++
		}
		fmt.Printf("%-24s %-8s %7.0f%% %7.0f%%  %s\n",
			out.Name, out.Risk, out.UndefendedASR*100, out.DefendedASR*100, flag)
		for _, v := range violations {
			fmt.Printf("    ! %s\n", v)
		}
	}

	fmt.Println()
	for _, line := range add.Grid(outs) {
		fmt.Println(line)
	}

	fmt.Printf("\n%d technique(s); %d regressed\n", len(techniques), failed)
	if failed > 0 {
		os.Exit(1)
	}
	fmt.Println("all defenses hold: ASR 0% across the chain.")
}
