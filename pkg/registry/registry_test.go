package registry_test

import (
	"errors"
	"testing"

	"github.com/t0ul/emaildrop/pkg/registry"
)

func TestGatedPromotionToProd(t *testing.T) {
	r := registry.New(0.87)
	r.Register(registry.Model{Name: "planner", Version: "v2", Signed: true, EvalF1: 0.95})
	// dev -> staging -> prod
	if err := r.Promote("planner", "v2"); err != nil {
		t.Fatal(err)
	}
	if err := r.Promote("planner", "v2"); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.Stage("planner", "v2"); st != registry.Prod {
		t.Fatalf("expected prod, got %s", st)
	}
}

func TestUnsignedBlocked(t *testing.T) {
	r := registry.New(0.87)
	r.Register(registry.Model{Name: "x", Version: "v1", Signed: false, EvalF1: 0.99})
	if err := r.Promote("x", "v1"); !errors.Is(err, registry.ErrUnsigned) {
		t.Fatalf("unsigned must not advance, got %v", err)
	}
}

func TestEvalGateBlocksProd(t *testing.T) {
	r := registry.New(0.87)
	r.Register(registry.Model{Name: "x", Version: "v1", Stage: registry.Staging, Signed: true, EvalF1: 0.50})
	if err := r.Promote("x", "v1"); !errors.Is(err, registry.ErrEvalGate) {
		t.Fatalf("below-gate model must not reach prod, got %v", err)
	}
}
