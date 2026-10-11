// Command console demonstrates the Track II governed control plane: an operator
// changes the agent's config only through RBAC + four-eyes approval, with
// versioned rollback and a fail-closed kill switch, every decision recorded to
// the gledger audit log. It is the CLI stand-in for the operator console (the
// Wails GUI, gridge, is the Capstone II deliverable).
//
//	console            run the governed-lifecycle demo
//
// Env: AUDIT_LOG (default controlplane/logs/governance.jsonl).
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/gledger"
	"github.com/t0ul/goverlord"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "console:", err)
		os.Exit(1)
	}
}

func run() error {
	auditPath := envOr("AUDIT_LOG", filepath.Join("controlplane", "logs", "governance.jsonl"))
	audit, err := gledger.Open(auditPath, "console")
	if err != nil {
		return err
	}

	gov := controlplane.NewGovernance(audit,
		map[string]any{"planner_model": "planner", "coder_model": "coder", "extract_mode": "llm"},
		goverlord.Operator{ID: "alice", Roles: []string{controlplane.RoleOperator}},
		goverlord.Operator{ID: "bob", Roles: []string{controlplane.RoleApprover}},
		goverlord.Operator{ID: "carol", Roles: []string{controlplane.RoleSRE}},
	)

	fmt.Println("== governed control plane ==")
	fmt.Printf("v%d config: %v\n\n", gov.Version(), gov.Config())

	// 1. Operator proposes a config change — pending under dual control.
	step("alice (operator) proposes planner_model=planner-v2")
	id, applied, err := gov.ProposeConfig("alice", "upgrade planner", map[string]any{"planner_model": "planner-v2"})
	if err != nil {
		return err
	}
	fmt.Printf("   proposal=%s applied=%v (awaits a second approver)\n\n", id, applied)

	// 2. Four-eyes: the proposer cannot approve their own change.
	step("alice tries to approve her own proposal")
	if _, err := gov.Approve("alice", id); err != nil {
		fmt.Printf("   refused: %v\n\n", err)
	}

	// 3. A different, authorized approver commits it.
	step("bob (approver) approves")
	if _, err := gov.Approve("bob", id); err != nil {
		return err
	}
	fmt.Printf("   committed -> v%d config: %v\n\n", gov.Version(), gov.Config())

	// 4. A bad change is proposed and rejected.
	step("alice proposes a risky change; bob rejects it")
	badID, _, err := gov.ProposeConfig("alice", "disable guard", map[string]any{"extract_mode": "raw"})
	if err != nil {
		return err
	}
	if err := gov.Reject("bob", badID); err != nil {
		return err
	}
	fmt.Printf("   rejected; config unchanged at v%d\n\n", gov.Version())

	// 5. Roll back to genesis.
	step("bob rolls back to v0")
	if err := gov.Rollback("bob", 0); err != nil {
		return err
	}
	fmt.Printf("   rolled back -> v%d config: %v\n\n", gov.Version(), gov.Config())

	// 6. Kill switch: fail-closed, refuses mutations.
	step("carol (sre) engages the kill switch")
	if err := gov.SetKillSwitch("carol", true); err != nil {
		return err
	}
	fmt.Printf("   killed=%v\n", gov.Killed())
	if _, _, err := gov.ProposeConfig("alice", "sneak change", map[string]any{"x": 1}); err != nil {
		fmt.Printf("   mutation refused while killed: %v\n\n", err)
	}
	step("carol disengages the kill switch")
	if err := gov.SetKillSwitch("carol", false); err != nil {
		return err
	}
	fmt.Printf("   killed=%v\n\n", gov.Killed())

	// History + audit integrity.
	fmt.Println("version history:")
	for _, v := range gov.History() {
		fmt.Printf("   v%d by %-6s %s\n", v.N, v.By, v.Note)
	}
	ok, n := audit.Verify()
	fmt.Printf("\naudit: %s  chain_ok=%t  records=%d\n", auditPath, ok, n)
	return nil
}

func step(s string) { fmt.Printf("-> %s\n", s) }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
