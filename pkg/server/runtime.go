package server

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/t0ul/emaildrop/internal/assets"
)

// RuntimeControl is the in-console start/stop of the local model stack (C3). Models
// auto-start on boot and stop on shutdown; this adds an operator button for the rest of
// the time. Nil = health panel only (no start/stop). The same controller owns the stack,
// so start/stop never orphans a process or double-starts.
type RuntimeControl interface {
	StartModels() error
	StopModels() error
	ModelsRunning() bool
}

func (s *Server) runtimeStart(w http.ResponseWriter, _ *http.Request) {
	if s.Runtime == nil {
		http.Error(w, "runtime control not available", http.StatusNotImplemented)
		return
	}
	if err := s.Runtime.StartModels(); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "running": true})
}

func (s *Server) runtimeStop(w http.ResponseWriter, _ *http.Request) {
	if s.Runtime == nil {
		http.Error(w, "runtime control not available", http.StatusNotImplemented)
		return
	}
	if err := s.Runtime.StopModels(); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "running": false})
}

// ModelRuntimeRow is the live readiness of one catalog model: is its GGUF file
// present and valid on disk, and is its serve port answering. This is the in-console
// equivalent of `cmd/preflight`, so "why is chat dead" has an answer in the UI.
type ModelRuntimeRow struct {
	Name      string `json:"name"`
	File      string `json:"file"`
	Present   bool   `json:"present"`
	ValidGGUF bool   `json:"valid_gguf"`
	Port      int    `json:"port"`
	PortOpen  bool   `json:"port_open"`
}

// runtimeStatus reports the live model runtime: gateway health, asset directory, and
// per-model file/port readiness. Read-only.
func (s *Server) runtimeStatus(w http.ResponseWriter, _ *http.Request) {
	var rows []ModelRuntimeRow
	if s.ModelCatalog != nil {
		entries, _ := s.ModelCatalog.ListModelCatalog()
		for _, e := range entries {
			r := ModelRuntimeRow{Name: e.Name, File: e.File, Port: e.Port}
			path := filepath.Join(s.AssetsDir, e.File)
			if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
				r.Present = true
				r.ValidGGUF = assets.VerifyGGUFHeader(path) == nil
			}
			host := e.Host
			if host == "" {
				host = "127.0.0.1"
			}
			r.PortOpen = dialable(net.JoinHostPort(host, strconv.Itoa(e.Port)))
			rows = append(rows, r)
		}
	}
	gwUp := s.GatewayUp != nil && s.GatewayUp()
	out := map[string]any{
		"gateway":    map[string]any{"url": s.GatewayURL, "up": gwUp},
		"assets_dir": s.AssetsDir,
		"models":     rows,
		"identity":   map[string]any{"ephemeral": s.IdentityEphemeral},
	}
	if s.VMURL != "" {
		out["sandbox"] = map[string]any{"url": s.VMURL, "up": s.VMUp != nil && s.VMUp()}
	}
	if s.Runtime != nil {
		// "running" reflects whether the models are actually reachable, which is true
		// both when THIS instance started the stack (managed) and when it reused an
		// already-running gateway — otherwise the panel misreports "stopped" on the
		// reuse path even though chat works. "managed" distinguishes the two: Stop only
		// affects a stack this instance owns.
		managed := s.Runtime.ModelsRunning()
		out["control"] = map[string]any{"available": true, "running": managed || gwUp, "managed": managed}
	}
	writeJSON(w, out)
}

// dialable reports whether a TCP address answers within a short timeout.
func dialable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
