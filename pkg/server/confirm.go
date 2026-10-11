package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/t0ul/emaildrop/pkg/agent/pipeline"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
	"github.com/t0ul/emaildrop/pkg/hitl"
)

// pending is an issued HITL approval bound to an action (ASI09).
type pending struct {
	kind  string // "accept" | "action"
	file  string
	index int
	req   hitl.Request
}

func (s *Server) storePending(nonce string, p pending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pend[nonce] = p // initialized by New
}

func (s *Server) takePending(nonce string) (pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pend[nonce]
	if ok {
		delete(s.pend, nonce) // single-use
	}
	return p, ok
}

// loadItem reads item index from a sidecar file.
func (s *Server) loadItem(file string, index int) (schema.Event, bool) {
	raw, err := os.ReadFile(filepath.Join(s.OutboxDir, file))
	if err != nil {
		return schema.Event{}, false
	}
	var es pipeline.EmailSummary
	if json.Unmarshal(raw, &es) != nil || index < 0 || index >= len(es.Items) {
		return schema.Event{}, false
	}
	return es.Items[index], true
}

func itemWhen(e schema.Event) string {
	if e.Due != "" {
		return e.Due
	}
	if e.Start != "" {
		return e.Start
	}
	return "no date"
}

// hitlGate runs the two-phase HITL approval. With no nonce it issues a challenge
// (evidence + single-use nonce) and returns false — the caller must stop. With a
// nonce it verifies the echo matches the exact issued action and returns true to
// proceed. A blind/forged POST cannot produce the nonce (it never saw the
// challenge), and the confirm is evidence-first and single-use.
func (s *Server) hitlGate(w http.ResponseWriter, kind, file string, index int, nonce string, confirm bool, summary string, evidence ...string) bool {
	if nonce == "" {
		h := hitl.NewRequest(summary, evidence...)
		s.storePending(h.Nonce(), pending{kind: kind, file: file, index: index, req: h})
		writeJSON(w, map[string]any{
			"confirm_required": true, "nonce": h.Nonce(), "summary": h.Summary, "evidence": h.Evidence,
		})
		return false
	}
	p, ok := s.takePending(nonce)
	if !ok || p.kind != kind || p.file != file || p.index != index {
		http.Error(w, "unknown or expired approval", http.StatusForbidden)
		return false
	}
	if okc, err := p.req.Confirm(nonce, confirm); !okc {
		msg := "approval refused"
		if err != nil {
			msg = err.Error()
		}
		http.Error(w, msg, http.StatusForbidden)
		return false
	}
	return true
}
