package controlplane

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/registry"
)

func TestPromoteWithLatestEval(t *testing.T) {
	inv, err := datastore.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	reg := registry.New(0.87)
	reg.Register(registry.Model{Name: "planner", Version: "v2", Stage: registry.Staging, Signed: true})

	// A passing persisted score promotes to prod.
	inv.RecordEval("1.txt", 1.00)
	if err := PromoteWithLatestEval(reg, inv, "planner", "v2", "1.txt"); err != nil {
		t.Fatalf("promotion with passing score should succeed: %v", err)
	}
	if st, _ := reg.Stage("planner", "v2"); st != registry.Prod {
		t.Fatalf("expected prod, got %s", st)
	}

	// A failing score is gated out.
	reg.Register(registry.Model{Name: "coder", Version: "v1", Stage: registry.Staging, Signed: true})
	inv.RecordEval("3.txt", 0.40)
	if err := PromoteWithLatestEval(reg, inv, "coder", "v1", "3.txt"); err == nil {
		t.Fatal("low persisted score must block prod promotion")
	}
}
