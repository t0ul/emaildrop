package server

import (
	"fmt"
	"net/http"

	"github.com/t0ul/emaildrop/pkg/ir"
)

// activity renders the audit log as a plain-language feed of what the agent did
// — the same tamper-evident records the Incidents view reads, shown in the
// owner's words (M2 observability / ASI10 agent-action visibility). Newest
// first, bounded.
func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	events, _ := ir.Load(s.AuditPath)
	type row struct {
		TS    string `json:"ts"`
		Trace string `json:"trace"`
		Text  string `json:"text"`
	}
	var out []row
	for i := len(events) - 1; i >= 0 && len(out) < 100; i-- {
		e := events[i]
		if t := phrase(e); t != "" {
			out = append(out, row{TS: e.TS, Trace: e.TraceID, Text: t})
		}
	}
	writeJSON(w, map[string]any{"activity": out})
}

func fv(f map[string]any, k string) string {
	if v, ok := f[k]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// phrase turns one audit record into a sentence a non-engineer can read. An
// empty string drops noisy/duplicate spans from the feed.
func phrase(e ir.Event) string {
	switch e.Span + "/" + e.Event {
	case "request/start":
		return "📨 Started processing " + fv(e.Fields, "source")
	case "injection_guard/detected":
		return "🛡️ Neutralized injected instructions hidden in an email"
	case "ingest/rejected":
		return "🚫 Rejected an oversized email (" + fv(e.Fields, "reason") + ")"
	case "index/stored":
		return "📚 Added the email to the searchable corpus"
	case "policy/gate":
		if fv(e.Fields, "decision") == "block" {
			return "⛔ Blocked a command — " + fv(e.Fields, "reason")
		}
		return "✓ Allowed a vetted command"
	case "vsock/detonate":
		if fv(e.Fields, "ok") == "true" {
			return "🧪 Ran a command inside the sandbox"
		}
		return "🧪 Sandbox command did not complete"
	case "pipeline/summary_written":
		return "📝 Summarized an email — " + fv(e.Fields, "items") + " item(s), " + fv(e.Fields, "needs_review") + " need review"
	case "coder/sanitize":
		return "🧹 Stripped exfiltration vectors from generated output"
	case "killswitch/engaged", "request/killswitch_halt":
		return "🔴 Halted: kill switch engaged"
	case "request/safety_halt":
		return "🟠 Halted by the safety level"
	}
	// Broker egress + artifact events carry their own shape.
	switch e.Event {
	case "egress":
		if fv(e.Fields, "decision") == "deny" || fv(e.Fields, "allowed") == "false" {
			return "⛔ Blocked network egress to " + fv(e.Fields, "target")
		}
		return "🌐 Fetched an allow-listed URL through the sandbox"
	case "artifact_written":
		return "📅 Wrote a calendar file: " + fv(e.Fields, "file")
	case "artifact_signed":
		return "🔏 Signed an artifact for authenticity"
	}
	return ""
}
