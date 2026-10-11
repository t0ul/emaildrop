package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/t0ul/emaildrop/internal/assets"
	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/gledger"
)

// ModelCatalogStore reads and writes the DB-backed model catalog (the single source
// of truth for which models exist: verified download URL/SHA, file, serve port/ctx).
// *datastore.Store satisfies it.
type ModelCatalogStore interface {
	ListModelCatalog() ([]modelcatalog.Entry, error)
	GetModelCatalog(name string) (modelcatalog.Entry, bool, error)
	UpsertModelCatalog(e modelcatalog.Entry) error
	DeleteModelCatalog(name string) error
}

// ModelCatalogRow is one catalog entry for the Studio Models tab. SHA is shown as
// set/unset (a pin is integrity, and the full hash is long); the URL is shown so the
// operator can see provenance.
type ModelCatalogRow struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Pinned bool   `json:"pinned"` // whether a SHA-256 pin is recorded
	File   string `json:"file"`
	Port   int    `json:"port"`
	Ctx    int    `json:"ctx"`
	Host   string `json:"host"`
	Kind   string `json:"kind,omitempty"` // "" = chat, "embedding" = trained embedding model
}

func (s *Server) modelCatalogList(w http.ResponseWriter, _ *http.Request) {
	entries, err := s.ModelCatalog.ListModelCatalog()
	if err != nil {
		http.Error(w, "catalog read failed", http.StatusInternalServerError)
		return
	}
	out := make([]ModelCatalogRow, 0, len(entries))
	for _, e := range entries {
		out = append(out, ModelCatalogRow{
			Name: e.Name, URL: e.URL, SHA256: e.SHA256, Pinned: e.SHA256 != "",
			File: e.File, Port: e.Port, Ctx: e.Ctx, Host: e.Host, Kind: e.Kind,
		})
	}
	writeJSON(w, map[string]any{"catalog": out})
}

// modelCatalogUpsert adds or edits a catalog entry (swap a model in/out). CSRF +
// authz(write/model). Requires name, url, and file; host defaults to loopback.
func (s *Server) modelCatalogUpsert(w http.ResponseWriter, r *http.Request) {
	var e modelcatalog.Entry
	if json.NewDecoder(r.Body).Decode(&e) != nil || e.Name == "" || e.URL == "" || e.File == "" {
		http.Error(w, "name, url and file are required", http.StatusBadRequest)
		return
	}
	if e.Host == "" {
		e.Host = "127.0.0.1" // least-exposure default
	}
	if err := s.ModelCatalog.UpsertModelCatalog(e); err != nil {
		http.Error(w, "catalog write failed", http.StatusInternalServerError)
		return
	}
	s.auditModel("catalog-upsert", e.Name)
	writeJSON(w, map[string]any{"ok": true, "name": e.Name})
}

// modelCatalogDelete removes a catalog entry. Refuses if a role is still bound to it
// (don't leave a dangling binding pointing at a model that no longer exists).
func (s *Server) modelCatalogDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	if role := s.roleBoundTo(req.Name); role != "" {
		http.Error(w, "refused: role \""+role+"\" is bound to this model — rebind it first", http.StatusConflict)
		return
	}
	if err := s.ModelCatalog.DeleteModelCatalog(req.Name); err != nil {
		http.Error(w, "catalog delete failed", http.StatusInternalServerError)
		return
	}
	s.auditModel("catalog-delete", req.Name)
	writeJSON(w, map[string]any{"ok": true, "name": req.Name})
}

// modelCatalogDownload fetches a catalog entry's GGUF to the asset dir and verifies it
// (SHA-256 pin + GGUF magic) in-console (B5), so "swap a model in" no longer requires an
// out-of-band `prepareassets` run. A hash mismatch removes the partial file (the download
// helper fails closed). CSRF + authz(write/model).
func (s *Server) modelCatalogDownload(w http.ResponseWriter, r *http.Request) {
	if s.AssetsDir == "" {
		http.Error(w, "asset dir not configured", http.StatusNotImplemented)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	e, ok, err := s.ModelCatalog.GetModelCatalog(req.Name)
	if err != nil || !ok {
		http.Error(w, "no such catalog entry", http.StatusBadRequest)
		return
	}
	if e.URL == "" || e.File == "" {
		http.Error(w, "entry has no url/file to download", http.StatusBadRequest)
		return
	}
	dest := filepath.Join(s.AssetsDir, e.File)
	if derr := assets.DownloadAndVerify(e.URL, dest, e.SHA256); derr != nil {
		s.auditModel("catalog-download-failed", e.Name)
		writeJSON(w, map[string]any{"ok": false, "name": e.Name, "error": derr.Error()})
		return
	}
	s.auditModel("catalog-download", e.Name)
	writeJSON(w, map[string]any{"ok": true, "name": e.Name, "file": e.File, "verified": true, "pinned": e.SHA256 != ""})
}

// roleBoundTo returns a role currently bound to the given logical model name, or ""
// if none. Used to guard catalog deletes against dangling bindings.
func (s *Server) roleBoundTo(name string) string {
	if s.Models == nil {
		return ""
	}
	for _, v := range s.Models.List() {
		if v.Model == name {
			return v.Name
		}
	}
	return ""
}

func (s *Server) auditModel(action, name string) {
	if s.Audit != nil {
		s.Audit.Emit(gledger.NewTraceID(), "model-catalog", action, gledger.F{"name": name})
	}
}
