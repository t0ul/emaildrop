package controlplane

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

func TestPoliciesListActivateReset(t *testing.T) {
	p := NewPolicies(map[string][]string{
		"egress": {"schools.nyc.gov", "nyc.gov"},
		"exec":   {"uname", "whoami"},
	})
	// List shows both at default version 0.
	got := p.List()
	if len(got) != 2 || got[0].Name != "egress" || got[0].Version != 0 {
		t.Fatalf("List should return both policies sorted at v0, got %+v", got)
	}
	// Activate a widened egress allowlist.
	pv := p.Activate("egress", []string{"schools.nyc.gov", "nyc.gov", "ps51eliashowe.org"})
	if pv.Version != 1 || len(pv.Items) != 3 {
		t.Fatalf("activation should be v1 with 3 items, got %+v", pv)
	}
	if len(p.Items("egress")) != 3 {
		t.Fatal("resolver should return the active (widened) egress allowlist")
	}
	// Hash is order-independent (pin stability).
	if HashPolicy([]string{"a", "b"}) != HashPolicy([]string{"b", "a"}) {
		t.Fatal("HashPolicy must be order-independent")
	}
	// Reset rolls back to the shipped default (v0, 2 items).
	if r := p.Reset("egress"); r.Version != 0 || len(r.Items) != 2 {
		t.Fatalf("Reset should restore the default, got %+v", r)
	}
}

func TestGovernedPoliciesPersist(t *testing.T) {
	inv, _ := datastore.Open(":memory:")
	defer inv.Close()
	p := GovernedPolicies(map[string][]string{"egress": {"nyc.gov"}}, inv, nil)
	p.Activate("egress", []string{"nyc.gov", "example.org"})
	rows, err := inv.ListPolicies(10)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(rows) == 0 || rows[0].Name != "egress" {
		t.Fatalf("activation should persist a policy row, got %+v", rows)
	}
}
