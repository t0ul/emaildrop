package server

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/controlplane"
)

// TestConcurrencyBudgetEnforced locks F1: the governed MaxConcurrency budget is actually
// enforced by the console (not display-only). Real Server + real Budgets plane.
func TestConcurrencyBudgetEnforced(t *testing.T) {
	budgets := controlplane.NewBudgets(map[string]controlplane.BudgetConfig{"api": {MaxConcurrency: 2}})
	s := New(Config{Budgets: budgets})

	r1, ok1 := s.apiSlot()
	r2, ok2 := s.apiSlot()
	if !ok1 || !ok2 {
		t.Fatalf("first two slots must be granted (limit 2): ok1=%v ok2=%v", ok1, ok2)
	}
	if _, ok3 := s.apiSlot(); ok3 {
		t.Fatal("a third concurrent request must be refused at limit 2")
	}
	r1() // release one
	r3, ok := s.apiSlot()
	if !ok {
		t.Fatal("a slot must free up after a release")
	}
	r2()
	r3()

	// Unlimited when the knob is 0 (default): never refuses.
	open := New(Config{Budgets: controlplane.NewBudgets(map[string]controlplane.BudgetConfig{"api": {}})})
	for i := 0; i < 100; i++ {
		if _, ok := open.apiSlot(); !ok {
			t.Fatalf("MaxConcurrency=0 must be unlimited, refused at %d", i)
		}
	}
	// No Budgets plane at all → unlimited, never panics.
	if _, ok := New(Config{}).apiSlot(); !ok {
		t.Fatal("no Budgets plane must be unlimited")
	}
}
