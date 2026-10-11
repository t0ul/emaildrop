package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/t0ul/emaildrop/pkg/ir"
)

// commands renders the raw tool-call stream — the operator twin of the consumer Activity
// feed (M2 observability / ASI10 agent-action visibility). Each row is one command the agent
// actually ran: the exec argv or the fetch URL, its allow/block decision, and the sandbox
// outcome, correlated by trace (a `policy/gate` paired with its `vsock/detonate`). Output
// text is NEVER logged — only its length — so the stream shows WHAT ran and whether it
// succeeded, never the fetched content. Newest first, bounded.
func (s *Server) commands(w http.ResponseWriter, _ *http.Request) {
	events, _ := ir.Load(s.AuditPath)
	type cmd struct {
		TS       string `json:"ts"`
		Trace    string `json:"trace"`
		Kind     string `json:"kind"`              // exec | fetch
		Command  string `json:"command"`           // argv joined, or the URL
		Decision string `json:"decision"`          // allow | block
		Reason   string `json:"reason,omitempty"`  // on a block
		Outcome  string `json:"outcome,omitempty"` // ok (N bytes) | status 403 | error: … | blocked
	}
	var rows []*cmd
	pending := map[string]*cmd{} // the most recent unresolved allow-gate per trace, awaiting its detonate
	for _, e := range events {
		switch e.Span + "/" + e.Event {
		case "policy/gate":
			c := &cmd{TS: e.TS, Trace: e.TraceID, Decision: fv(e.Fields, "decision"), Reason: fv(e.Fields, "reason")}
			if _, ok := e.Fields["argv"]; ok {
				c.Kind, c.Command = "exec", argvString(e.Fields["argv"])
			} else {
				c.Kind, c.Command = "fetch", fv(e.Fields, "url")
			}
			if c.Decision == "block" {
				c.Outcome = "blocked"
			} else {
				pending[e.TraceID] = c
			}
			rows = append(rows, c)
		case "vsock/detonate":
			c := pending[e.TraceID]
			if c == nil {
				continue
			}
			switch {
			case fv(e.Fields, "ok") == "true":
				c.Outcome = "ok (" + fv(e.Fields, "out_len") + " bytes)"
			case fv(e.Fields, "status") != "":
				c.Outcome = "status " + fv(e.Fields, "status")
			default:
				c.Outcome = "error: " + fv(e.Fields, "error")
			}
			delete(pending, e.TraceID)
		}
	}
	out := make([]*cmd, 0, 100)
	for i := len(rows) - 1; i >= 0 && len(out) < 100; i-- {
		out = append(out, rows[i])
	}
	writeJSON(w, map[string]any{"commands": out})
}

// argvString renders a logged argv (a JSON array) as a single command line.
func argvString(v any) string {
	switch a := v.(type) {
	case []any:
		parts := make([]string, 0, len(a))
		for _, x := range a {
			parts = append(parts, fmt.Sprintf("%v", x))
		}
		return strings.Join(parts, " ")
	case []string:
		return strings.Join(a, " ")
	}
	return fmt.Sprintf("%v", v)
}
