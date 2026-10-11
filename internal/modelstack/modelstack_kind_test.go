package modelstack

import (
	"testing"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
)

// TestChatModelsExcludesEmbedding locks the B4 split: a trained embedding model is NOT
// booted into the chat stack (it is served by the dedicated embeddings server), so the
// chat gateway never routes to it and Available doesn't require it as a chat model.
func TestChatModelsExcludesEmbedding(t *testing.T) {
	catalog := []modelcatalog.Entry{
		{Name: "planner", File: "planner.gguf"},
		{Name: "nomic-embed-text", File: "nomic.gguf", Kind: "embedding"},
		{Name: "coder", File: "coder.gguf"},
	}
	chat := chatModels(catalog)
	if len(chat) != 2 {
		t.Fatalf("chat stack must exclude embedding models, got %d of 3", len(chat))
	}
	for _, e := range chat {
		if e.IsEmbedding() {
			t.Errorf("embedding model %q leaked into the chat stack", e.Name)
		}
	}
	// A catalog of only embedding models has no chat stack to start.
	if ok, reason := Available(t.TempDir(), []modelcatalog.Entry{{Name: "e", File: "e.gguf", Kind: "embedding"}}); ok {
		t.Error("an embedding-only catalog must not be chat-stack Available")
	} else if reason == "" {
		t.Error("expected a reason why the chat stack is unavailable")
	}
}
