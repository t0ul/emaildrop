package server

import (
	"net/http"
	"strings"

	"github.com/t0ul/emaildrop/pkg/domain"
)

// ask answers a free-text question by lexical retrieval over the corpus. The
// query is FTS5-escaped by the store (no operator injection); results are
// snippets to read, not an LLM answer (offline, no model).
func (s *Server) ask(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if s.Search == nil || q == "" {
		writeJSON(w, map[string]any{"hits": []domain.SearchHit{}})
		return
	}
	hits, err := s.Search(q, 8)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"hits": hits})
}

// snippet trims recalled text to a readable preview.
func Snippet(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 240 {
		return text[:240] + "…"
	}
	return text
}
