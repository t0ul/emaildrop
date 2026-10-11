package datastore_test

import (
	"path/filepath"
	"testing"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/emaildrop/pkg/datastore"
)

// TestModelCatalogKindRoundTrip locks B4 persistence: a catalog entry's Kind (chat vs
// trained embedding model) survives a store round-trip, so the chat stack and the
// embeddings server can tell them apart. Real SQLite.
func TestModelCatalogKindRoundTrip(t *testing.T) {
	inv, err := datastore.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()

	if err := inv.UpsertModelCatalog(modelcatalog.Entry{Name: "planner", File: "p.gguf", Port: 1}); err != nil {
		t.Fatal(err)
	}
	if err := inv.UpsertModelCatalog(modelcatalog.Entry{Name: "nomic-embed-text", File: "n.gguf", Port: 2, Kind: "embedding"}); err != nil {
		t.Fatal(err)
	}

	got, err := inv.ListModelCatalog()
	if err != nil {
		t.Fatal(err)
	}
	kind := map[string]string{}
	for _, e := range got {
		kind[e.Name] = e.Kind
	}
	if kind["planner"] != "" {
		t.Errorf("chat model must have empty kind, got %q", kind["planner"])
	}
	if kind["nomic-embed-text"] != "embedding" {
		t.Errorf("embedding model kind not persisted, got %q", kind["nomic-embed-text"])
	}

	e, ok, err := inv.GetModelCatalog("nomic-embed-text")
	if err != nil || !ok || !e.IsEmbedding() {
		t.Errorf("GetModelCatalog must report the embedding kind: ok=%v e=%+v err=%v", ok, e, err)
	}
}
