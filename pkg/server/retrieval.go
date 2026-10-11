package server

import (
	"encoding/json"
	"net/http"

	"github.com/t0ul/emaildrop/pkg/controlplane"
)

// RetrievalRow is one entry of the retrieval governance tab: a corpus's governed
// retrieval config (top-k, …) with its version and content hash.
type RetrievalRow struct {
	Name    string                       `json:"name"`
	Version int                          `json:"version"`
	Hash    string                       `json:"hash"`
	Config  controlplane.RetrievalConfig `json:"config"`
}

func (s *Server) retrievalList(w http.ResponseWriter, _ *http.Request) {
	var out []RetrievalRow
	for _, v := range s.Retrieval.List() {
		out = append(out, RetrievalRow{Name: v.Name, Version: v.Version, Hash: short12(v.Hash), Config: v.Config})
	}
	writeJSON(w, map[string]any{"retrieval": out})
}

// retrievalActivate records a new governed retrieval version for a corpus.
// CSRF + authz(write/retrieval) guard this route.
func (s *Server) retrievalActivate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string                       `json:"name"`
		Config controlplane.RetrievalConfig `json:"config"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		http.Error(w, "name and config required", http.StatusBadRequest)
		return
	}
	v := s.Retrieval.Activate(req.Name, req.Config)
	writeJSON(w, map[string]any{"ok": true, "name": v.Name, "version": v.Version, "hash": short12(v.Hash)})
}

// retrievalReset rolls a corpus's retrieval back to its shipped default.
func (s *Server) retrievalReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	v := s.Retrieval.Reset(req.Name)
	writeJSON(w, map[string]any{"ok": true, "name": v.Name, "version": v.Version})
}
