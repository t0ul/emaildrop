package rag_test

import (
	"path/filepath"
	"testing"

	"github.com/t0ul/emaildrop/pkg/rag"
)

// TestOpenReadOnlyCannotWrite proves C4d: a read-only retrieval handle can query
// the corpus but the engine refuses any write, so the search path cannot mutate
// or poison the index regardless of app-layer bugs.
func TestOpenReadOnlyCannotWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.db")

	w, err := rag.Open(path)
	if err != nil {
		t.Fatalf("open writable: %v", err)
	}
	if err := w.Add(rag.Doc{ID: "a", Tenant: "public", Text: "october book fair", Prov: rag.Untrusted}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	ro, err := rag.OpenReadOnly(path)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	defer ro.Close()

	hits, err := ro.Query("public", "october", 5)
	if err != nil {
		t.Fatalf("read-only query: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("read-only handle should still read seeded docs")
	}
	if err := ro.Add(rag.Doc{ID: "b", Tenant: "public", Text: "injected", Prov: rag.Untrusted}); err == nil {
		t.Fatal("read-only store must refuse writes (engine-enforced)")
	}
}
