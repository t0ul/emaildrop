package controlplane

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

func TestGovernedPromptsPersist(t *testing.T) {
	inv, _ := datastore.Open(":memory:")
	defer inv.Close()
	p := GovernedPrompts(map[string]string{"planner": "D"}, inv, nil)
	p.Activate("planner", "GOVERNED-V1")
	rows, err := inv.ListPrompts(10)
	if err != nil || len(rows) != 1 || rows[0].Name != "planner" || rows[0].Version != "v1" {
		t.Fatalf("activation not persisted via OnActivate: %+v (%v)", rows, err)
	}
}

func TestPromptsFallsBackToDefault(t *testing.T) {
	p := NewPrompts(map[string]string{"planner": "DEFAULT-PLANNER"})
	v := p.Get("planner")
	if v.Version != 0 || v.Text != "DEFAULT-PLANNER" {
		t.Fatalf("expected default version 0, got %+v", v)
	}
	if v.Hash != HashPrompt("DEFAULT-PLANNER") {
		t.Fatalf("default hash wrong: %s", v.Hash)
	}
}

func TestPromptsActivateVersionsAndPins(t *testing.T) {
	p := NewPrompts(map[string]string{"coder": "DEFAULT"})
	a := p.Activate("coder", "GOVERNED-V1")
	if a.Version != 1 || a.Text != "GOVERNED-V1" {
		t.Fatalf("activate wrong: %+v", a)
	}
	if got := p.Get("coder"); got.Text != "GOVERNED-V1" || got.Version != 1 {
		t.Fatalf("Get after activate wrong: %+v", got)
	}
	if !p.Verify("coder", a.Hash) {
		t.Fatal("pin verify should match the active hash")
	}
	if p.Verify("coder", "deadbeef") {
		t.Fatal("pin verify must reject a wrong hash")
	}
	if b := p.Activate("coder", "GOVERNED-V2"); b.Version != 2 {
		t.Fatalf("version should increment, got %d", b.Version)
	}
}

func TestPromptsActivateHookFires(t *testing.T) {
	var got PromptVersion
	p := NewPrompts(map[string]string{"planner": "D"})
	p.OnActivate = func(pv PromptVersion) { got = pv } // stands in for datastore.RecordPrompt + audit
	p.Activate("planner", "V1")
	if got.Name != "planner" || got.Version != 1 || got.Hash != HashPrompt("V1") {
		t.Fatalf("persistence hook did not receive the activation: %+v", got)
	}
}

func TestOrchestratorResolvesGovernedPrompt(t *testing.T) {
	// nil resolver -> shipped const defaults.
	o := &Orchestrator{}
	if o.plannerPrompt() != PlannerSystemPrompt || o.coderPrompt() != CoderSystemPrompt {
		t.Fatal("nil Prompts should fall back to the const prompts")
	}
	// governed activation -> the orchestrator uses it, no redeploy.
	o.Prompts = NewPrompts(map[string]string{"planner": PlannerSystemPrompt, "coder": CoderSystemPrompt})
	o.Prompts.Activate("planner", "GOVERNED-PLANNER-PROMPT")
	if o.plannerPrompt() != "GOVERNED-PLANNER-PROMPT" {
		t.Fatalf("orchestrator did not use the governed planner prompt: %q", o.plannerPrompt())
	}
	if o.coderPrompt() != CoderSystemPrompt {
		t.Fatal("coder should still resolve to its default until activated")
	}
}

func TestPromptsListAndReset(t *testing.T) {
	p := NewPrompts(map[string]string{"planner": "P-default", "coder": "C-default"})
	// List shows every known name at its default (version 0).
	if got := p.List(); len(got) != 2 || got[0].Name != "coder" || got[1].Name != "planner" {
		t.Fatalf("List should return both names sorted, got %+v", got)
	}
	// Activate a new planner version, then confirm List reflects it.
	pv := p.Activate("planner", "P-v1")
	if pv.Version != 1 {
		t.Fatalf("first activation should be version 1, got %d", pv.Version)
	}
	for _, v := range p.List() {
		if v.Name == "planner" && (v.Version != 1 || v.Text != "P-v1") {
			t.Fatalf("List should show the active planner v1, got %+v", v)
		}
	}
	// Reset rolls back to the shipped default (version 0).
	if got := p.Reset("planner"); got.Version != 0 || got.Text != "P-default" {
		t.Fatalf("Reset should restore the default, got %+v", got)
	}
	if p.Text("planner") != "P-default" {
		t.Fatal("after Reset, Text should be the default")
	}
}
