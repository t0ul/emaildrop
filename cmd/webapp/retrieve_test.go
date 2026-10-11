package main

import (
	"context"
	"errors"
	"testing"

	"github.com/t0ul/emaildrop/pkg/rag"
)

// TestRetrieveDegradesLoudly locks G2: when semantic retrieval is requested but the
// embedder is down, retrieval falls back to lexical FTS and REPORTS it — it never
// silently claims to be semantic. Real in-memory rag.Store, a real failing embedder.
func TestRetrieveDegradesLoudly(t *testing.T) {
	store, err := rag.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Add(rag.Doc{ID: "d1", Tenant: "public", Text: "picture day is friday", Prov: "seed"}); err != nil {
		t.Fatal(err)
	}

	// Lexical: no embedder wanted → "keyword", and it finds the doc.
	chunks, mode, err := retrieve(store, false, "public", "picture day", 5)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "keyword" {
		t.Errorf("lexical mode: got %q, want keyword", mode)
	}
	if len(chunks) == 0 {
		t.Error("lexical retrieval found nothing")
	}

	// Semantic requested but embedder errors → degrade to FTS, flagged, still answers.
	store.Embed = func(context.Context, string) ([]float32, error) {
		return nil, errors.New("embed server down")
	}
	chunks, mode, err = retrieve(store, true, "public", "picture day", 5)
	if err != nil {
		t.Fatalf("degraded retrieval must still answer, got err: %v", err)
	}
	if mode != "keyword (semantic unavailable)" {
		t.Errorf("degraded mode must be surfaced, got %q", mode)
	}
	if len(chunks) == 0 {
		t.Error("degraded retrieval returned nothing — the FTS fallback did not run")
	}

	// Semantic with a working embedder → reports "semantic" (never mislabels).
	store.Embed = func(context.Context, string) ([]float32, error) {
		return []float32{0.1, 0.2, 0.3}, nil
	}
	if _, mode, err = retrieve(store, true, "public", "picture day", 5); err != nil {
		t.Fatal(err)
	}
	if mode != "semantic" {
		t.Errorf("semantic mode: got %q, want semantic", mode)
	}
}
