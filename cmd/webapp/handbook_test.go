package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/rag"
)

// TestIngestHandbooks locks D1: a *handbook*.txt in the seed dir is auto-ingested into
// the corpus (retrievable by Ask), PII-scrubbed on the way in, while a non-handbook file
// is left alone. Real in-memory corpus, no mocks.
func TestIngestHandbooks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "family-handbook.txt"),
		[]byte("Pickup is at 3pm. Contact the office at nurse@school.test for early dismissal."), 0o644); err != nil {
		t.Fatal(err)
	}
	// A regular email in the same dir must NOT be ingested as a handbook.
	if err := os.WriteFile(filepath.Join(dir, "newsletter.txt"), []byte("Back to School Night"), 0o644); err != nil {
		t.Fatal(err)
	}

	corpus, err := rag.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer corpus.Close()

	ids := ingestHandbooks(corpus, dir)
	if len(ids) != 1 || ids[0] != "handbook:family-handbook.txt" {
		t.Fatalf("expected exactly the handbook ingested, got %v", ids)
	}

	// Retrievable by Ask.
	hits, err := corpus.Query("public", "pickup", 5)
	if err != nil || len(hits) == 0 {
		t.Fatalf("handbook not retrievable: %v hits=%d", err, len(hits))
	}
	// PII-scrubbed on ingest: the email address must not survive verbatim.
	for _, h := range hits {
		if containsEmail(h.Text) {
			t.Errorf("handbook was not PII-scrubbed on ingest: %q", h.Text)
		}
	}

	// Idempotent: a second ingest replaces, not duplicates.
	ingestHandbooks(corpus, dir)
	if docs, _ := corpus.Stats(); docs != 1 {
		t.Errorf("re-ingest must be idempotent, got %d docs", docs)
	}
}

// TestHandbookChunksIntoPassages locks the real fix: with the default (paragraph)
// chunker set on the corpus, a long handbook is indexed as MANY passages, not one whole
// chunk — so retrieval returns the relevant passage and never a window-overflowing blob.
func TestHandbookChunksIntoPassages(t *testing.T) {
	if defaultRAGConfig().Chunker != "paragraph" {
		t.Fatalf("default chunker must be paragraph, got %q", defaultRAGConfig().Chunker)
	}
	dir := t.TempDir()
	// A multi-paragraph handbook well over one chunk's MaxChars.
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("Paragraph ")
		b.WriteString(strings.Repeat("word ", 40))
		b.WriteString("\n\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "family-handbook.txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	corpus, err := rag.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer corpus.Close()
	corpus.Chunker = chunkerFor(loadRAGConfig(nil)) // same as the boot path (nil inv → default)

	if ids := ingestHandbooks(corpus, dir); len(ids) != 1 {
		t.Fatalf("expected the handbook ingested, got %v", ids)
	}
	docs, chunks := corpus.Stats()
	if docs != 1 {
		t.Fatalf("expected 1 doc, got %d", docs)
	}
	if chunks < 3 {
		t.Fatalf("the handbook must split into multiple passages, got %d chunks", chunks)
	}
}

func containsEmail(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '@' {
			return true
		}
	}
	return false
}
