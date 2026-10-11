package server

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/t0ul/emaildrop/pkg/controlplane"
)

// BudgetRow is one entry of the budgets tab (C9): a governed resource envelope.
// KeySet reports whether the env var named by the config's KeyRef is populated —
// so the console shows the key POINTER and whether it resolves, never the value.
type BudgetRow struct {
	Name    string                    `json:"name"`
	Version int                       `json:"version"`
	Hash    string                    `json:"hash"`
	Config  controlplane.BudgetConfig `json:"config"`
	KeySet  bool                      `json:"key_set"`
}

func (s *Server) budgetsList(w http.ResponseWriter, _ *http.Request) {
	var out []BudgetRow
	for _, v := range s.Budgets.List() {
		keySet := v.Config.KeyRef != "" && os.Getenv(v.Config.KeyRef) != ""
		out = append(out, BudgetRow{Name: v.Name, Version: v.Version, Hash: short12(v.Hash), Config: v.Config, KeySet: keySet})
	}
	writeJSON(w, map[string]any{"budgets": out})
}

func (s *Server) budgetsActivate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string                    `json:"name"`
		Config controlplane.BudgetConfig `json:"config"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		http.Error(w, "name and config required", http.StatusBadRequest)
		return
	}
	v := s.Budgets.Activate(req.Name, req.Config)
	writeJSON(w, map[string]any{"ok": true, "name": v.Name, "version": v.Version, "hash": short12(v.Hash)})
}

func (s *Server) budgetsReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	v := s.Budgets.Reset(req.Name)
	writeJSON(w, map[string]any{"ok": true, "name": v.Name, "version": v.Version})
}

// overBudget enforces the governed per-minute request rate for the console API (a
// fixed-window limiter). RatePerMin <= 0 (or no Budgets) means unlimited. Rate and
// max-concurrency (apiSlot) are the two budgets the app enforces itself; per-model
// token and spend caps are enforced gateway-side by gouncer (and are labeled as such
// in the Budgets tab, so the console never claims to enforce what it does not).
func (s *Server) overBudget() bool {
	if s.Budgets == nil {
		return false
	}
	limit := s.Budgets.Config("api").RatePerMin
	if limit <= 0 {
		return false
	}
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	now := time.Now()
	if now.Sub(s.rlWindow) >= time.Minute {
		s.rlWindow = now
		s.rlCount = 0
	}
	s.rlCount++
	return s.rlCount > limit
}

// apiSlot enforces the governed max-concurrency budget for the console API. It takes an
// in-flight slot and returns a release func, or ok=false when the limit is already
// reached (the caller refuses with 429). MaxConcurrency <= 0 (or no Budgets) = unlimited.
func (s *Server) apiSlot() (release func(), ok bool) {
	limit := 0
	if s.Budgets != nil {
		limit = s.Budgets.Config("api").MaxConcurrency
	}
	n := s.inflight.Add(1)
	if limit > 0 && int(n) > limit {
		s.inflight.Add(-1)
		return func() {}, false
	}
	return func() { s.inflight.Add(-1) }, true
}
