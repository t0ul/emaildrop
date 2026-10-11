package controlplane

import (
	"context"
	"errors"
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/goverlord"
)

func newGov(t *testing.T) (*Governance, func() (bool, int)) {
	t.Helper()
	audit, verify := tempAudit(t)
	g := NewGovernance(audit,
		map[string]any{"planner_model": "planner", "extract_mode": "llm"},
		goverlord.Operator{ID: "alice", Roles: []string{RoleOperator}},
		goverlord.Operator{ID: "bob", Roles: []string{RoleApprover}},
		goverlord.Operator{ID: "carol", Roles: []string{RoleSRE}},
	)
	return g, verify
}

func TestGovernanceFourEyesApproval(t *testing.T) {
	g, verify := newGov(t)
	id, applied, err := g.ProposeConfig("alice", "tune planner", map[string]any{"planner_model": "planner-v2"})
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Fatal("config.write is under dual control; must not apply on propose")
	}
	if _, err := g.Approve("alice", id); !errors.Is(err, goverlord.ErrSameOperator) {
		t.Fatalf("four-eyes: expected ErrSameOperator, got %v", err)
	}
	ok, err := g.Approve("bob", id)
	if err != nil || !ok {
		t.Fatalf("approve by bob failed: ok=%v err=%v", ok, err)
	}
	if g.String("planner_model", "") != "planner-v2" {
		t.Fatalf("config not updated: %v", g.Config())
	}
	if g.Version() != 1 {
		t.Fatalf("expected version 1 after one change, got %d", g.Version())
	}
	if ok, _ := verify(); !ok {
		t.Error("audit chain should verify")
	}
}

func TestApprovalRecordedToInventory(t *testing.T) {
	inv, err := datastore.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	g, _ := newGov(t)
	g.Inventory = inv

	id, _, err := g.ProposeConfig("alice", "upgrade", map[string]any{"planner_model": "v2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Approve("bob", id); err != nil {
		t.Fatal(err)
	}
	rows, err := inv.ListApprovals(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected 1 persisted approval, got %v err=%v", rows, err)
	}
	if rows[0].Proposer != "alice" || rows[0].Approver != "bob" {
		t.Fatalf("approval not recorded correctly: %+v", rows[0])
	}
}

func TestGovernanceRBACDeniesRollback(t *testing.T) {
	g, _ := newGov(t)
	if err := g.Rollback("alice", 0); !errors.Is(err, goverlord.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for operator rollback, got %v", err)
	}
}

func TestGovernanceRollbackRestoresConfig(t *testing.T) {
	g, _ := newGov(t)
	id, _, _ := g.ProposeConfig("alice", "change", map[string]any{"planner_model": "planner-v2"})
	g.Approve("bob", id)
	if err := g.Rollback("bob", 0); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := g.String("planner_model", ""); got != "planner" {
		t.Fatalf("rollback did not restore genesis config, got %q", got)
	}
}

func TestGovernanceKillSwitchBlocksMutation(t *testing.T) {
	g, _ := newGov(t)
	if err := g.SetKillSwitch("carol", true); err != nil {
		t.Fatal(err)
	}
	if !g.Killed() {
		t.Fatal("kill switch should report engaged")
	}
	if _, _, err := g.ProposeConfig("alice", "x", map[string]any{"k": "v"}); !errors.Is(err, goverlord.ErrKilled) {
		t.Fatalf("mutations must be refused while killed, got %v", err)
	}
}

func TestOrchestratorKillSwitchHalts(t *testing.T) {
	audit, _ := tempAudit(t)
	// No LLM/Interp wired: Run must halt before touching them.
	o := &Orchestrator{Audit: audit, Killed: func() bool { return true }}
	final, err := o.Run(context.Background(), "t", "history")
	if err != nil {
		t.Fatal(err)
	}
	if final.FinalMarkdown == "" || final.ToolCommand != "" {
		t.Fatalf("kill switch should halt before execution: %+v", final)
	}
}
