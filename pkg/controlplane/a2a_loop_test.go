package controlplane

import (
	"context"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/a2a"
)

func TestSignedPlanDetonates(t *testing.T) {
	audit, _ := tempAudit(t)
	gw := fakeGateway(t, map[string]string{
		"planner": "- a\n- b\n- c\nCOMMAND: ls -la",
		"coder":   "# ok",
	})
	defer gw.Close()
	vm := fakeMicroVM(t, "total 0\n")
	defer vm.Close()

	key := []byte("planner-key")
	o := &Orchestrator{
		LLM:      &LLMClient{BaseURL: gw.URL, HTTP: gw.Client()},
		Interp:   &Interpreter{MicroVMURL: vm.URL, Audit: audit, HTTP: vm.Client()},
		Audit:    audit,
		Approve:  func(State) bool { return true },
		Signer:   a2a.NewSigner("planner", key),
		Verifier: a2a.NewVerifier().Trust("planner", key),
	}
	final, err := o.Run(context.Background(), "t", "history")
	if err != nil {
		t.Fatal(err)
	}
	if final.ToolOutput != "total 0\n" {
		t.Fatalf("signed plan should detonate, got ToolOutput=%q", final.ToolOutput)
	}
}

func TestUnsignedPlanRejected(t *testing.T) {
	audit, _ := tempAudit(t)
	gw := fakeGateway(t, map[string]string{"planner": "- a\nCOMMAND: whoami", "coder": "# ok"})
	defer gw.Close()
	// Verifier set but NO signer: the plan arrives unauthenticated. Interp is nil
	// on purpose — the executor must not detonate.
	o := &Orchestrator{
		LLM:      &LLMClient{BaseURL: gw.URL, HTTP: gw.Client()},
		Audit:    audit,
		Approve:  func(State) bool { return true },
		Verifier: a2a.NewVerifier().Trust("planner", []byte("planner-key")),
	}
	final, err := o.Run(context.Background(), "t", "history")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(final.ToolOutput, "failed inter-agent authentication") {
		t.Fatalf("unsigned plan must be rejected, got %q", final.ToolOutput)
	}
}
