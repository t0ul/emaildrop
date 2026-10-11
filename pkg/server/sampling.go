package server

import (
	"encoding/json"
	"net/http"

	"github.com/t0ul/emaildrop/pkg/controlplane"
)

// SamplingRow is one entry of the sampling governance tab (C5): a model's governed
// decoding config with its version and content hash.
type SamplingRow struct {
	Name    string                      `json:"name"`
	Version int                         `json:"version"`
	Hash    string                      `json:"hash"`
	Config  controlplane.SamplingConfig `json:"config"`
}

func (s *Server) samplingList(w http.ResponseWriter, _ *http.Request) {
	var out []SamplingRow
	for _, v := range s.Sampling.List() {
		out = append(out, SamplingRow{Name: v.Name, Version: v.Version, Hash: short12(v.Hash), Config: v.Config})
	}
	writeJSON(w, map[string]any{"sampling": out})
}

// samplingActivate records a new governed sampling version for a model (versioned,
// hashed, audited, persisted). CSRF + authz(write/sampling) guard this route.
func (s *Server) samplingActivate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string                      `json:"name"`
		Config controlplane.SamplingConfig `json:"config"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		http.Error(w, "name and config required", http.StatusBadRequest)
		return
	}
	v := s.Sampling.Activate(req.Name, req.Config)
	writeJSON(w, map[string]any{"ok": true, "name": v.Name, "version": v.Version, "hash": short12(v.Hash)})
}

// samplingReset rolls a model's sampling back to its shipped default.
func (s *Server) samplingReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	v := s.Sampling.Reset(req.Name)
	writeJSON(w, map[string]any{"ok": true, "name": v.Name, "version": v.Version})
}
