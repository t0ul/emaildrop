package main

import (
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/rag"
)

// TestBudgetChunksBoundsContext locks the chat-context cap: a large doc is trimmed so the
// combined retrieved context fits the model window (no fallback), while every source still
// contributes something.
func TestBudgetChunksBoundsContext(t *testing.T) {
	chunks := []rag.Chunk{
		{DocID: "handbook", Text: strings.Repeat("x", 40000)}, // one giant doc
		{DocID: "email1", Text: "picture day is friday"},
		{DocID: "email2", Text: "half day on tuesday"},
	}
	const budget = 6000
	out := budgetChunks(chunks, budget)

	if len(out) != 3 {
		t.Fatalf("every source must be kept, got %d", len(out))
	}
	total := 0
	for _, ch := range out {
		total += len([]rune(ch.Text))
	}
	// Per-chunk share is budget/3 = 2000; plus the "…(truncated)" marker per trimmed
	// chunk. Total must be bounded near the budget, nowhere near the original 40k.
	if total > budget+200 {
		t.Errorf("context not bounded: %d runes (budget %d)", total, budget)
	}
	if !strings.Contains(out[0].Text, "truncated") {
		t.Error("the oversized chunk should be marked truncated")
	}
	// Small chunks are untouched.
	if out[1].Text != "picture day is friday" {
		t.Errorf("small chunk should be intact, got %q", out[1].Text)
	}

	// Empty / zero budget are safe no-ops.
	if got := budgetChunks(nil, 100); got != nil {
		t.Error("nil chunks must pass through")
	}
}
