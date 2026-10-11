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

// GrammarVersion is a resolved, content-hashed output grammar (the GBNF/JSON-schema
// the model's decoding is constrained to). Version 0 is the shipped default; >0 is
// a governed activation. A swapped grammar silently changes the output contract, so
// it is a hash-pinned, versioned, rollback-able artifact like a prompt.
type GrammarVersion struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Hash    string `json:"hash"`
	Text    string `json:"text"`
}

// HashGrammar is the content pin for a grammar (sha256 over its text).
func HashGrammar(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// Grammars is the runtime resolver for per-extractor output grammars — the twin of
// the prompts plane, for the output-schema dimension. A hardcoded GBNF const becomes
// a governed, versioned, rollback-able artifact; an un-set name resolves to the
// shipped default.
type Grammars struct {
	mu         sync.RWMutex
	defaults   map[string]string
	active     map[string]GrammarVersion
	OnActivate func(GrammarVersion)
}

// NewGrammars seeds the resolver with the shipped default grammars by name.
func NewGrammars(defaults map[string]string) *Grammars {
	cp := make(map[string]string, len(defaults))
	for k, v := range defaults {
		cp[k] = v
	}
	return &Grammars{defaults: cp, active: map[string]GrammarVersion{}}
}

// Get returns the active grammar for name, or its default (version 0).
func (p *Grammars) Get(name string) GrammarVersion {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if v, ok := p.active[name]; ok {
		return v
	}
	t := p.defaults[name]
	return GrammarVersion{Name: name, Version: 0, Hash: HashGrammar(t), Text: t}
}

// Text is the active (or default) grammar text for name.
func (p *Grammars) Text(name string) string { return p.Get(name).Text }

// List returns the current grammar for every known name, sorted.
func (p *Grammars) List() []GrammarVersion {
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
	out := make([]GrammarVersion, 0, len(ordered))
	for _, n := range ordered {
		out = append(out, p.Get(n))
	}
	return out
}

// Activate records a new active grammar version and returns it.
func (p *Grammars) Activate(name, text string) GrammarVersion {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := 1
	if v, ok := p.active[name]; ok {
		next = v.Version + 1
	}
	pv := GrammarVersion{Name: name, Version: next, Hash: HashGrammar(text), Text: text}
	p.active[name] = pv
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Rehydrate restores a persisted active grammar on boot without firing OnActivate.
func (p *Grammars) Rehydrate(name, text string) {
	p.mu.Lock()
	p.active[name] = GrammarVersion{Name: name, Version: 1, Hash: HashGrammar(text), Text: text}
	p.mu.Unlock()
}

// Reset drops the active version so name resolves to its shipped default.
func (p *Grammars) Reset(name string) GrammarVersion {
	p.mu.Lock()
	delete(p.active, name)
	p.mu.Unlock()
	return p.Get(name)
}

// Verify reports whether name's active (or default) grammar matches wantHash.
func (p *Grammars) Verify(name, wantHash string) bool {
	return p.Get(name).Hash == wantHash
}

// GovernedGrammars wires persistence + audit: each activation is recorded to the
// datastore (rehydrates on boot) and audited to gledger.
func GovernedGrammars(defaults map[string]string, inv *datastore.Store, audit *gledger.AuditLog) *Grammars {
	p := NewGrammars(defaults)
	p.OnActivate = func(pv GrammarVersion) {
		if inv != nil {
			_ = inv.RecordGrammar(pv.Name, fmt.Sprintf("v%d", pv.Version), pv.Hash, pv.Text)
		}
		if audit != nil {
			audit.Emit(gledger.NewTraceID(), "grammar", "activated",
				gledger.F{"name": pv.Name, "version": pv.Version, "hash": pv.Hash[:12]})
		}
	}
	return p
}
