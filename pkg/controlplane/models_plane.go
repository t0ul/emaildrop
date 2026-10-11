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

// ModelVersion is a resolved, content-hashed model binding: the logical model name
// a role (extractor, chat, …) routes to, which the gateway maps to a physical
// model. Version 0 is the shipped default; >0 is a governed activation. Swapping a
// model is a governed, versioned, rollback-able change, not a code edit — and a
// local→frontier swap is exactly where the data-residency rule bites.
type ModelVersion struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Hash    string `json:"hash"`
	Model   string `json:"model"`
}

// HashModel is the content pin for a model binding.
func HashModel(model string) string {
	sum := sha256.Sum256([]byte(model))
	return hex.EncodeToString(sum[:])
}

// Models is the runtime resolver for per-role model bindings — the twin of the
// prompts plane, for the model dimension. Hardcoded/config-key model names become
// governed, versioned, rollback-able artifacts; an un-set role resolves to the
// shipped default.
type Models struct {
	mu         sync.RWMutex
	defaults   map[string]string
	active     map[string]ModelVersion
	OnActivate func(ModelVersion)
}

// NewModels seeds the resolver with the shipped default bindings by role.
func NewModels(defaults map[string]string) *Models {
	cp := make(map[string]string, len(defaults))
	for k, v := range defaults {
		cp[k] = v
	}
	return &Models{defaults: cp, active: map[string]ModelVersion{}}
}

// Get returns the active binding for name, or its default (version 0).
func (p *Models) Get(name string) ModelVersion {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if v, ok := p.active[name]; ok {
		return v
	}
	m := p.defaults[name]
	return ModelVersion{Name: name, Version: 0, Hash: HashModel(m), Model: m}
}

// Bound is the active (or default) model name for a role.
func (p *Models) Bound(name string) string { return p.Get(name).Model }

// List returns the current binding for every known role, sorted.
func (p *Models) List() []ModelVersion {
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
	out := make([]ModelVersion, 0, len(ordered))
	for _, n := range ordered {
		out = append(out, p.Get(n))
	}
	return out
}

// Activate records a new active binding and returns it.
func (p *Models) Activate(name, model string) ModelVersion {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := 1
	if v, ok := p.active[name]; ok {
		next = v.Version + 1
	}
	pv := ModelVersion{Name: name, Version: next, Hash: HashModel(model), Model: model}
	p.active[name] = pv
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Rehydrate restores a persisted active binding on boot without firing OnActivate.
func (p *Models) Rehydrate(name, model string) {
	p.mu.Lock()
	p.active[name] = ModelVersion{Name: name, Version: 1, Hash: HashModel(model), Model: model}
	p.mu.Unlock()
}

// Reset drops the active version so name resolves to its shipped default.
func (p *Models) Reset(name string) ModelVersion {
	p.mu.Lock()
	delete(p.active, name)
	p.mu.Unlock()
	return p.Get(name)
}

// Verify reports whether name's active (or default) binding matches wantHash.
func (p *Models) Verify(name, wantHash string) bool {
	return p.Get(name).Hash == wantHash
}

// GovernedModels wires persistence + audit: each activation is recorded to the
// datastore (rehydrates on boot) and audited to gledger.
func GovernedModels(defaults map[string]string, inv *datastore.Store, audit *gledger.AuditLog) *Models {
	p := NewModels(defaults)
	p.OnActivate = func(pv ModelVersion) {
		if inv != nil {
			_ = inv.RecordModel(pv.Name, fmt.Sprintf("v%d", pv.Version), pv.Hash, pv.Model)
		}
		if audit != nil {
			audit.Emit(gledger.NewTraceID(), "model", "activated",
				gledger.F{"name": pv.Name, "version": pv.Version, "hash": pv.Hash[:12], "model": pv.Model})
		}
	}
	return p
}
