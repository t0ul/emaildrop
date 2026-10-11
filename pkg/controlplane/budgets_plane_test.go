package controlplane

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

func TestBudgetsListActivateReset(t *testing.T) {
	p := NewBudgets(map[string]BudgetConfig{"api": {RatePerMin: 0}})
	if got := p.List(); len(got) != 1 || got[0].Version != 0 {
		t.Fatalf("default should list at v0, got %+v", got)
	}
	pv := p.Activate("api", BudgetConfig{RatePerMin: 60, KeyRef: "GATEWAY_KEY"})
	if pv.Version != 1 || p.Config("api").RatePerMin != 60 {
		t.Fatalf("activation should set rate 60 at v1, got %+v", pv)
	}
	// KeyRef is a pointer, stored as given (the value is never in config).
	if p.Config("api").KeyRef != "GATEWAY_KEY" {
		t.Fatal("key pointer should be stored")
	}
	if r := p.Reset("api"); r.Version != 0 || r.Config.RatePerMin != 0 {
		t.Fatalf("reset should restore the default, got %+v", r)
	}
}

func TestGovernedBudgetsPersist(t *testing.T) {
	inv, _ := datastore.Open(":memory:")
	defer inv.Close()
	p := GovernedBudgets(map[string]BudgetConfig{"api": {}}, inv, nil)
	p.Activate("api", BudgetConfig{RatePerMin: 30})
	cfg, ok, err := inv.LatestBudget("api")
	if err != nil || !ok || cfg == "" {
		t.Fatalf("activation should persist a budget row, ok=%v err=%v", ok, err)
	}
}
