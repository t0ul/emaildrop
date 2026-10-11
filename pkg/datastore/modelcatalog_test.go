package datastore_test

import (
	"testing"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
)

// TestModelCatalogSeedIsIdempotent: the seed populates an empty table once, and a
// second boot must NOT clobber operator edits.
func TestModelCatalogSeedIsIdempotent(t *testing.T) {
	s := open(t)
	seed := modelcatalog.DefaultSeed()
	got, err := s.SeedModelCatalogIfEmpty(seed)
	if err != nil || len(got) != len(seed) {
		t.Fatalf("first seed: got %d err %v, want %d", len(got), err, len(seed))
	}
	// Operator edits a row (changes the URL for "planner").
	e, ok, _ := s.GetModelCatalog("planner")
	if !ok {
		t.Fatal("planner should be seeded")
	}
	e.URL = "https://example.test/pinned.gguf"
	e.SHA256 = "deadbeef"
	if err := s.UpsertModelCatalog(e); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Second boot: seed must be a no-op, edit preserved.
	again, err := s.SeedModelCatalogIfEmpty(seed)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if len(again) != len(seed) {
		t.Fatalf("catalog size changed: got %d want %d", len(again), len(seed))
	}
	edited, _, _ := s.GetModelCatalog("planner")
	if edited.URL != "https://example.test/pinned.gguf" || edited.SHA256 != "deadbeef" {
		t.Fatalf("seed clobbered an operator edit: %+v", edited)
	}
}

// TestModelCatalogCRUD: upsert adds, list sorts, delete removes.
func TestModelCatalogCRUD(t *testing.T) {
	s := open(t)
	if err := s.UpsertModelCatalog(modelcatalog.Entry{Name: "zeta", URL: "u", File: "z.gguf", Port: 1, Ctx: 2, Host: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertModelCatalog(modelcatalog.Entry{Name: "alpha", URL: "u2", File: "a.gguf", Port: 3, Ctx: 4, Host: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListModelCatalog()
	if err != nil || len(list) != 2 || list[0].Name != "alpha" {
		t.Fatalf("list should be sorted [alpha,zeta], got %+v err %v", list, err)
	}
	// Upsert replaces, does not duplicate.
	if err := s.UpsertModelCatalog(modelcatalog.Entry{Name: "zeta", URL: "u-new", File: "z.gguf", Port: 9, Ctx: 2, Host: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	z, ok, _ := s.GetModelCatalog("zeta")
	if !ok || z.URL != "u-new" || z.Port != 9 {
		t.Fatalf("upsert should replace in place, got %+v ok=%v", z, ok)
	}
	if err := s.DeleteModelCatalog("zeta"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetModelCatalog("zeta"); ok {
		t.Fatal("zeta should be deleted")
	}
}
