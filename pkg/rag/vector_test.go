package rag_test

import (
	"context"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/rag"
)

// fakeEmbed is a deterministic bag-of-words embedder over a tiny vocab, so
// cosine similarity tracks shared keywords without a model.
func fakeEmbed(_ context.Context, text string) ([]float32, error) {
	vocab := []string{"october", "drill", "salary", "meeting"}
	v := make([]float32, len(vocab))
	low := strings.ToLower(text)
	for i, w := range vocab {
		if strings.Contains(low, w) {
			v[i] = 1
		}
	}
	return v, nil
}

func newVecStore(t *testing.T) *rag.Store {
	t.Helper()
	s, err := rag.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	s.Embed = fakeEmbed
	t.Cleanup(func() { s.Close() })
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.Add(rag.Doc{ID: "meet", Text: "october meeting agenda", Prov: rag.Trusted}))
	must(s.Add(rag.Doc{ID: "drill", Text: "monthly fire drill drill procedure", Prov: rag.Trusted}))
	must(s.Add(rag.Doc{ID: "sal", Tenant: "hr", Text: "salary roster", Prov: rag.Trusted}))
	return s
}

func TestSemanticRankByEmbedding(t *testing.T) {
	s := newVecStore(t)
	hits, err := s.SemanticQuery(context.Background(), "public", "fire drill schedule", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 || hits[0].DocID != "drill" {
		t.Fatalf("semantic top hit should be the drill doc, got %+v", hits)
	}
}

func TestSemanticRespectsTenantACL(t *testing.T) {
	s := newVecStore(t)
	// A non-hr tenant must never get the hr salary doc, even by vector similarity.
	hits, err := s.SemanticQuery(context.Background(), "public", "salary", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range hits {
		if c.DocID == "sal" {
			t.Fatal("cross-tenant semantic leak: got hr salary doc")
		}
	}
}
