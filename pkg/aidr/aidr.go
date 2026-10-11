// Package aidr is runtime AI detection & response: it watches the audit trace
// stream (gledger events, decoded by ir) and, when a rule matches a dangerous
// signal, auto-escalates the layered kill switch (controlplane.Safety). This
// closes the loop — detection (a policy block, a capability violation, a tripped
// breaker, an MCP rug-pull) becomes automatic containment, not just a log line a
// human might read later.
package aidr

import (
	"strings"

	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/ir"
)

// Rule maps a trace signal to the kill level it should trigger.
type Rule struct {
	Name  string
	Level controlplane.KillLevel
	Match func(ir.Event) bool
}

// Engine evaluates rules against observed events and invokes a response.
type Engine struct {
	rules   []Rule
	respond func(level controlplane.KillLevel, reason string)
}

// New builds an engine. respond is called (if non-nil) when any rule fires, with
// the highest triggered level and the matched rule names. Empty rules use the
// defaults.
func New(respond func(controlplane.KillLevel, string), rules ...Rule) *Engine {
	if len(rules) == 0 {
		rules = DefaultRules()
	}
	return &Engine{rules: rules, respond: respond}
}

// Observe evaluates one event, invoking the response with the highest level
// among matched rules. It returns that level and whether anything fired.
func (e *Engine) Observe(ev ir.Event) (controlplane.KillLevel, bool) {
	best := controlplane.LevelNone
	var names []string
	for _, r := range e.rules {
		if r.Match(ev) {
			names = append(names, r.Name)
			if r.Level > best {
				best = r.Level
			}
		}
	}
	if len(names) > 0 {
		if e.respond != nil {
			e.respond(best, strings.Join(names, ","))
		}
		return best, true
	}
	return controlplane.LevelNone, false
}

// Scan observes a batch and returns the highest level any event triggered.
func (e *Engine) Scan(events []ir.Event) controlplane.KillLevel {
	max := controlplane.LevelNone
	for _, ev := range events {
		if lvl, fired := e.Observe(ev); fired && lvl > max {
			max = lvl
		}
	}
	return max
}

// DefaultRules are the baseline detection signals.
func DefaultRules() []Rule {
	return []Rule{
		{"policy-block", controlplane.LevelBlockTools, func(ev ir.Event) bool {
			return ev.Span == "policy" && ev.Event == "gate" && asString(ev.Fields["decision"]) == "block"
		}},
		{"capability-violation", controlplane.LevelBlockTools, func(ev ir.Event) bool {
			return ev.Event == "capability_violation"
		}},
		{"mcp-rug-pull", controlplane.LevelBlockTools, func(ev ir.Event) bool {
			return ev.Span == "gustoms" && ev.Event == "deny" && asString(ev.Fields["reason"]) == "pin_mismatch"
		}},
		{"circuit-breaker", controlplane.LevelHalt, func(ev ir.Event) bool {
			return ev.Event == "circuit_breaker_tripped"
		}},
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
