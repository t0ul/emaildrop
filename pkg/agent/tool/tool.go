// Package tool is the plugin contract: one narrow, scoped capability per tool.
// The planner chooses which tool(s) to run; the pipeline enforces each tool's
// declared capability and routes its output. Adding a tool means implementing
// this interface and registering it — never editing the core loop.
package tool

import "github.com/t0ul/emaildrop/pkg/agent/schema"

// Capability is the single privilege a tool declares (least privilege, M6).
type Capability string

const (
	ReadOnly Capability = "read_only" // may only produce text (digest, action-items, contacts)
	WriteICS Capability = "write_ics" // may emit an inert .ics artifact for the user to accept
)

// Ctx is the per-request context passed to a tool.
type Ctx struct {
	Source      string
	DefaultYear int
	Mode        string // "", "auto", "llm", or "regex"
	Reference   bool   // the source is a reference/handbook doc (R2): extract conservatively, feed the corpus
}

// Result is a tool's typed output.
type Result struct {
	Tool       string
	Capability Capability
	Events     []schema.Event
	Text       string            // for read-only text tools
	Artifacts  map[string]string // filename -> content (write tools only)
	Warnings   []string
}

// Tool is one scoped capability. Implementations must be safe to reuse.
type Tool interface {
	Name() string
	Capability() Capability
	Run(emailText string, ctx Ctx) Result
}

// Registry holds the available tools by name.
type Registry struct{ m map[string]Tool }

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{m: map[string]Tool{}} }

// Register adds (or replaces) a tool by its name.
func (r *Registry) Register(t Tool) { r.m[t.Name()] = t }

// Get returns a tool by name.
func (r *Registry) Get(name string) (Tool, bool) { t, ok := r.m[name]; return t, ok }

// All returns a copy of the registry map.
func (r *Registry) All() map[string]Tool {
	out := make(map[string]Tool, len(r.m))
	for k, v := range r.m {
		out[k] = v
	}
	return out
}
