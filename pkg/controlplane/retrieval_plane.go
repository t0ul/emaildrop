package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"sync"

	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/gledger"
)

// RetrievalConfig is a corpus's retrieval knobs — how much context the RAG read
// path pulls per query. Today K (top-k) is the live one; it was a hardcoded
// literal in the chat/search path and is now a governed, versioned artifact.
type RetrievalConfig struct {
	K int `json:"k"`
	// ContextTokens caps the retrieved context handed to the chat model, so a large
	// corpus can't overflow the window and force a fallback. 0 = a sane default derived
	// from the model's context size. A governed, versioned, bundle-referenced knob.
	ContextTokens int `json:"context_tokens,omitempty"`
}

// RetrievalVersion is a resolved, content-hashed retrieval config. Version 0 is
// the shipped default; >0 is a governed activation.
type RetrievalVersion struct {
	Name    string          `json:"name"`
	Version int             `json:"version"`
	Hash    string          `json:"hash"`
	Config  RetrievalConfig `json:"config"`
}

// HashRetrieval is the content pin for a retrieval config (sha256 over its JSON).
func HashRetrieval(c RetrievalConfig) string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Retrieval is the runtime resolver for per-corpus retrieval knobs — the twin of
// the prompts/sampling/policies/budgets planes. A hardcoded k becomes a governed,
// versioned, rollback-able artifact; an un-set corpus resolves to the shipped
// default (fail-closed to what the binary trusts).
type Retrieval struct {
	mu         sync.RWMutex
	defaults   map[string]RetrievalConfig
	active     map[string]RetrievalVersion
	OnActivate func(RetrievalVersion)
}

// NewRetrieval seeds the resolver with the shipped default configs by corpus name.
func NewRetrieval(defaults map[string]RetrievalConfig) *Retrieval {
	cp := make(map[string]RetrievalConfig, len(defaults))
	for k, v := range defaults {
		cp[k] = v
	}
	return &Retrieval{defaults: cp, active: map[string]RetrievalVersion{}}
}

// Get returns the active retrieval for name, or its default (version 0).
func (p *Retrieval) Get(name string) RetrievalVersion {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if v, ok := p.active[name]; ok {
		return v
	}
	c := p.defaults[name]
	return RetrievalVersion{Name: name, Version: 0, Hash: HashRetrieval(c), Config: c}
}

// Config is the active (or default) retrieval config for name.
func (p *Retrieval) Config(name string) RetrievalConfig { return p.Get(name).Config }

// List returns the current retrieval for every known corpus, sorted.
func (p *Retrieval) List() []RetrievalVersion {
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
	out := make([]RetrievalVersion, 0, len(ordered))
	for _, n := range ordered {
		out = append(out, p.Get(n))
	}
	return out
}

// Activate records a new active retrieval version and returns it.
func (p *Retrieval) Activate(name string, c RetrievalConfig) RetrievalVersion {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := 1
	if v, ok := p.active[name]; ok {
		next = v.Version + 1
	}
	pv := RetrievalVersion{Name: name, Version: next, Hash: HashRetrieval(c), Config: c}
	p.active[name] = pv
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Rehydrate restores a persisted active config on boot without firing OnActivate.
func (p *Retrieval) Rehydrate(name string, c RetrievalConfig) {
	p.mu.Lock()
	p.active[name] = RetrievalVersion{Name: name, Version: 1, Hash: HashRetrieval(c), Config: c}
	p.mu.Unlock()
}

// Reset drops the active version so name resolves to its shipped default.
func (p *Retrieval) Reset(name string) RetrievalVersion {
	p.mu.Lock()
	delete(p.active, name)
	p.mu.Unlock()
	return p.Get(name)
}

// Verify reports whether name's active (or default) config matches wantHash.
func (p *Retrieval) Verify(name, wantHash string) bool {
	return p.Get(name).Hash == wantHash
}

// GovernedRetrieval wires persistence + audit into the resolver: each activation
// is recorded to the datastore (so it rehydrates on boot) and audited to gledger.
func GovernedRetrieval(defaults map[string]RetrievalConfig, inv *datastore.Store, audit *gledger.AuditLog) *Retrieval {
	p := NewRetrieval(defaults)
	p.OnActivate = func(pv RetrievalVersion) {
		if inv != nil {
			b, _ := json.Marshal(pv.Config)
			_ = inv.RecordRetrieval(pv.Name, "v"+strconv.Itoa(pv.Version), pv.Hash, string(b))
		}
		if audit != nil {
			audit.Emit(gledger.NewTraceID(), "retrieval", "activated",
				gledger.F{"name": pv.Name, "version": pv.Version, "hash": pv.Hash[:12], "k": pv.Config.K})
		}
	}
	return p
}
