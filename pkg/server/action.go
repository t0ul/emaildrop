package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

// Fetcher performs an egress fetch for an action link. In production it is
// controlplane.SandboxFetchTool — the fetch executes inside the egress-denied
// MicroVM and reaches the net only through the host netpolicy broker, so
// untrusted bytes are parsed off the host. It returns the fetched text (or a
// human-readable failure string); it does not return a Go error for a refused
// or failed fetch — the content carries the message.
type Fetcher func(ctx context.Context, url string) (string, error)

// action performs an action item's link. Anti-SSRF by construction: the URL is
// taken from the stored, vetted item (by file+index), NEVER from the request
// body, so a caller cannot redirect the fetch. The URL is cleared by the egress
// allowlist (netpolicy: deny-by-default + no loopback/private/IMDS) before the
// sandbox fetch runs. The link text came from an UNTRUSTED document, so this
// endpoint is the only place it may be reached, and only on an explicit click.
func (s *Server) action(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File    string `json:"file"`
		Index   int    `json:"index"`
		Nonce   string `json:"nonce"`
		Confirm bool   `json:"confirm"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || !safeSidecar(req.File) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.toolsBlocked() {
		http.Error(w, "blocked by the kill switch", http.StatusServiceUnavailable)
		return
	}
	item, ok := s.loadItem(req.File, req.Index)
	if !ok {
		http.Error(w, "no such item", http.StatusBadRequest)
		return
	}
	if item.ResolvedKind() != schema.KindAction || item.URL == "" {
		http.Error(w, "not an action link", http.StatusBadRequest)
		return
	}
	// HITL (ASI09): a link from an UNTRUSTED email opens only on an evidence-first,
	// single-use confirm — then still netpolicy-gated + fetched in the sandbox.
	if !s.hitlGate(w, "action", req.File, req.Index, req.Nonce, req.Confirm,
		"Open a link from an email", "url: "+item.URL, "from: "+item.Title) {
		return
	}

	// Egress allowlist (deny-by-default): the link from the untrusted doc must
	// resolve to an allow-listed, non-internal host or it is refused here. The
	// allowlist resolves live from the governed Policies (C8).
	if err := s.egressPolicy().Check(item.URL); err != nil {
		writeJSON(w, map[string]any{"ok": false, "url": item.URL, "refused": err.Error()})
		return
	}
	if s.Fetch == nil {
		writeJSON(w, map[string]any{"ok": false, "url": item.URL, "refused": "sandbox fetch not configured"})
		return
	}
	// Multi-party sign-off (A4/A5): a threshold of distinct trusted agents must each
	// have attested THIS exact URL before egress; a single rogue component cannot
	// authorize the fetch alone.
	if s.Quorum != nil {
		if err := s.Quorum("fetch:" + item.URL); err != nil {
			writeJSON(w, map[string]any{"ok": false, "url": item.URL, "refused": "quorum: " + err.Error()})
			return
		}
	}
	out, ferr := s.Fetch(r.Context(), item.URL)
	if ferr != nil {
		writeJSON(w, map[string]any{"ok": false, "url": item.URL, "refused": "sandbox fetch failed: " + ferr.Error()})
		return
	}
	if len(out) > 4000 {
		out = out[:4000] + "\n…(truncated)"
	}
	writeJSON(w, map[string]any{"ok": true, "url": item.URL, "result": out})
}
