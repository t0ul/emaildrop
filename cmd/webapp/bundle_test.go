package main

import (
	"path/filepath"
	"testing"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/rag"
	"github.com/t0ul/emaildrop/pkg/server"
	"github.com/t0ul/gledger"
)

// TestBundleRoundTripsRAGAndCatalog locks B6: the known-good snapshot captures and
// restores the DB-backed RAG lab config AND the model catalog, not just the governed
// planes. Real datastore + real ragLab + real gledger — no mocks.
func TestBundleRoundTripsRAGAndCatalog(t *testing.T) {
	dir := t.TempDir()
	inv, err := datastore.Open(filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	audit, err := gledger.Open(filepath.Join(dir, "audit.jsonl"), "test")
	if err != nil {
		t.Fatal(err)
	}

	// Seed a catalog of two models.
	for _, e := range []modelcatalog.Entry{
		{Name: "planner", File: "planner.gguf", Port: 11001, Ctx: 8192, Host: "127.0.0.1"},
		{Name: "coder", File: "coder.gguf", Port: 11002, Ctx: 8192, Host: "127.0.0.1"},
	} {
		if err := inv.UpsertModelCatalog(e); err != nil {
			t.Fatal(err)
		}
	}

	corpus, err := rag.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer corpus.Close()
	lab := newRAGLab(inv, corpus, t.TempDir(), t.TempDir(), []string{"none"}, nil)
	if _, err := lab.Save(server.RAGConfig{Mode: "fts", Chunker: "paragraph", ChunkSize: 800}); err != nil {
		t.Fatal(err)
	}

	bs := bundleStore{inv: inv, audit: audit, rag: lab}

	// Snapshot the safe point.
	if err := bs.Save("safe"); err != nil {
		t.Fatal(err)
	}

	// Drift away from it: change the chunker, drop a model, add a bogus one.
	if _, err := lab.Save(server.RAGConfig{Mode: "fts", Chunker: "fixed", ChunkSize: 200, ChunkOverlap: 40}); err != nil {
		t.Fatal(err)
	}
	if err := inv.DeleteModelCatalog("coder"); err != nil {
		t.Fatal(err)
	}
	if err := inv.UpsertModelCatalog(modelcatalog.Entry{Name: "rogue", File: "x.gguf", Port: 9999}); err != nil {
		t.Fatal(err)
	}

	// Roll back.
	if err := bs.Apply("safe"); err != nil {
		t.Fatal(err)
	}

	// RAG config restored.
	if got := lab.Config(); got.Chunker != "paragraph" || got.ChunkSize != 800 {
		t.Errorf("RAG config not restored: got %+v", got)
	}
	// Catalog restored EXACTLY: planner+coder back, rogue gone.
	cat, _ := inv.ListModelCatalog()
	names := map[string]bool{}
	for _, e := range cat {
		names[e.Name] = true
	}
	if !names["planner"] || !names["coder"] {
		t.Errorf("catalog missing restored models: %v", names)
	}
	if names["rogue"] {
		t.Error("rollback must remove an entry the snapshot did not have (rogue)")
	}
}

// TestBundleApplyOldPlaneOnlyFormat: a bundle saved before B6 (governed planes only,
// no rag_lab/model_catalog) must still apply cleanly — the extra fields are absent.
func TestBundleApplyOldPlaneOnlyFormat(t *testing.T) {
	dir := t.TempDir()
	inv, err := datastore.Open(filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	audit, _ := gledger.Open(filepath.Join(dir, "audit.jsonl"), "test")
	if err := inv.SaveBundle("legacy", `{"label":"legacy","prompts":{},"sampling":{}}`); err != nil {
		t.Fatal(err)
	}
	bs := bundleStore{inv: inv, audit: audit}
	if err := bs.Apply("legacy"); err != nil {
		t.Fatalf("legacy plane-only bundle must still apply: %v", err)
	}
}
