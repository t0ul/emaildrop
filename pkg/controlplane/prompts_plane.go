package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/gledger"
)

// PromptVersion is a resolved, content-hashed system prompt. Version 0 is the
// shipped default const; >0 is a governed activation.
type PromptVersion struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Hash    string `json:"hash"`
	Text    string `json:"text"`
}

// HashPrompt is the content pin for a prompt (sha256 hex).
func HashPrompt(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// Prompts is the runtime prompt resolver — the prompts management plane. It
// returns the governed-active prompt for a logical name (planner / coder /
// extractor), falling back to the shipped default const when none is activated.
// Activations are versioned and content-hashed so a caller can pin-verify the
// prompt before use and a change can be rolled back. The governed lifecycle
// (propose → dual-control approve → eval+ADD gate) wraps Activate; this type is
// the apply + resolve step, deliberately dependency-free so it is offline-testable.
type Prompts struct {
	mu       sync.RWMutex
	defaults map[string]string
	active   map[string]PromptVersion
	// OnActivate, when set, persists/audits each activation (e.g.
	// datastore.RecordPrompt + a gledger admin record). Kept as a hook so the
	// resolver stays dependency-free and offline-testable.
	OnActivate func(PromptVersion)
}

// NewPrompts seeds the resolver with the shipped default prompts by logical name.
func NewPrompts(defaults map[string]string) *Prompts {
	cp := make(map[string]string, len(defaults))
	for k, v := range defaults {
		cp[k] = v
	}
	return &Prompts{defaults: cp, active: map[string]PromptVersion{}}
}

// Get returns the active prompt for name, or the default (version 0) when none
// is activated.
func (p *Prompts) Get(name string) PromptVersion {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if v, ok := p.active[name]; ok {
		return v
	}
	text := p.defaults[name]
	return PromptVersion{Name: name, Version: 0, Hash: HashPrompt(text), Text: text}
}

// Text is the active (or default) prompt text for name.
func (p *Prompts) Text(name string) string { return p.Get(name).Text }

// Activate records a new active version (next version number, content-hashed) and
// returns it. Callers gate this behind governance + eval/ADD; Activate only applies.
func (p *Prompts) Activate(name, text string) PromptVersion {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := 1
	if v, ok := p.active[name]; ok {
		next = v.Version + 1
	}
	pv := PromptVersion{Name: name, Version: next, Hash: HashPrompt(text), Text: text}
	p.active[name] = pv
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Verify reports whether the active prompt for name still matches wantHash (the
// pin check). On a mismatch the caller fails closed to the default.
func (p *Prompts) Verify(name, wantHash string) bool {
	return p.Get(name).Hash == wantHash
}

// List returns the current (active or default) prompt for every known logical
// name, sorted — the console's prompt inventory.
func (p *Prompts) List() []PromptVersion {
	p.mu.RLock()
	names := map[string]struct{}{}
	for n := range p.defaults {
		names[n] = struct{}{}
	}
	for n := range p.active {
		names[n] = struct{}{}
	}
	p.mu.RUnlock()
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)
	out := make([]PromptVersion, 0, len(ordered))
	for _, n := range ordered {
		out = append(out, p.Get(n))
	}
	return out
}

// Rehydrate restores a persisted active prompt loaded from the governed store on
// boot. Unlike Activate it does NOT fire OnActivate (it is a reload of what was
// already persisted, not a new activation), so it never writes a duplicate row.
func (p *Prompts) Rehydrate(name, text string) {
	p.mu.Lock()
	p.active[name] = PromptVersion{Name: name, Version: 1, Hash: HashPrompt(text), Text: text}
	p.mu.Unlock()
}

// Reset reverts name to the shipped default (version 0) — rollback to the
// guaranteed known-good when an activated prompt misbehaves. The reset is
// recorded through OnActivate for the audit trail. Returns the default version.
func (p *Prompts) Reset(name string) PromptVersion {
	p.mu.Lock()
	delete(p.active, name)
	p.mu.Unlock()
	pv := p.Get(name)
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// GovernedPrompts is a resolver whose activations are durably persisted
// (datastore.RecordPrompt — a versioned, hashed artifact) and audited to gledger,
// so a prompt change survives restarts and is attributable (M14/M15).
func GovernedPrompts(defaults map[string]string, inv *datastore.Store, audit *gledger.AuditLog) *Prompts {
	p := NewPrompts(defaults)
	p.OnActivate = func(pv PromptVersion) {
		if inv != nil {
			_ = inv.RecordPrompt(pv.Name, fmt.Sprintf("v%d", pv.Version), pv.Hash, pv.Text)
		}
		if audit != nil {
			audit.Emit(gledger.NewTraceID(), "prompt", "activated",
				gledger.F{"name": pv.Name, "version": pv.Version, "hash": pv.Hash[:12]})
		}
	}
	return p
}
