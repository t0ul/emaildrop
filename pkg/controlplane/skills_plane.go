package controlplane

import (
	"fmt"
	"sort"
	"sync"

	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/gledger"
)

// SkillApproval is a governed skill pin: the operator-approved content hash for a
// skill name. Version 0 means UNAPPROVED — there is no safe default skill, so an
// un-activated name has an empty pin and the loader fails closed (a skill is
// runtime-loaded instructions; nothing loads until an operator approves that exact
// content). Approving a skill IS pinning its content hash, so Hash is that pin.
type SkillApproval struct {
	Name    string `json:"name"`
	Version int    `json:"version"` // governance version: 0 = unapproved, >0 = approved
	Hash    string `json:"hash"`    // the approved skill content hash (the pin), empty when unapproved
}

// Skills is the runtime resolver for governed skill approvals — the pin side of the
// skills supply-chain control. Unlike the other planes there is no shipped default
// value: an unknown or un-activated skill resolves to an empty pin, so skills.Library
// refuses it (fail-closed). Only an explicit Approve makes a skill loadable.
type Skills struct {
	mu         sync.RWMutex
	known      map[string]bool // names the operator is aware of (for listing), seeded + on approve
	active     map[string]SkillApproval
	OnActivate func(SkillApproval)
}

// NewSkills seeds the resolver with the names of skills the operator knows about
// (all initially UNAPPROVED — listing them, not trusting them).
func NewSkills(known []string) *Skills {
	k := make(map[string]bool, len(known))
	for _, n := range known {
		k[n] = true
	}
	return &Skills{known: k, active: map[string]SkillApproval{}}
}

// Get returns the active approval for name, or an unapproved (version 0, empty pin)
// record if the operator has not approved it.
func (p *Skills) Get(name string) SkillApproval {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if v, ok := p.active[name]; ok {
		return v
	}
	return SkillApproval{Name: name, Version: 0, Hash: ""}
}

// Pins returns the approved {name -> content hash} map the skills.Library consumes
// as its pin set. Unapproved skills are absent, so they fail closed.
func (p *Skills) Pins() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]string, len(p.active))
	for n, v := range p.active {
		if v.Hash != "" {
			out[n] = v.Hash
		}
	}
	return out
}

// List returns the current approval for every known name, sorted.
func (p *Skills) List() []SkillApproval {
	p.mu.RLock()
	names := map[string]struct{}{}
	for n := range p.known {
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
	out := make([]SkillApproval, 0, len(ordered))
	for _, n := range ordered {
		out = append(out, p.Get(n))
	}
	return out
}

// Approve pins a skill's content hash as operator-approved and returns the new
// approval. Re-approving a different hash is a new governance version (re-approval
// after a rug-pull).
func (p *Skills) Approve(name, contentHash string) SkillApproval {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := 1
	if v, ok := p.active[name]; ok {
		next = v.Version + 1
	}
	a := SkillApproval{Name: name, Version: next, Hash: contentHash}
	p.active[name] = a
	p.known[name] = true
	if p.OnActivate != nil {
		p.OnActivate(a)
	}
	return a
}

// Activate is an alias for Approve, for parity with the other planes' API.
func (p *Skills) Activate(name, contentHash string) SkillApproval { return p.Approve(name, contentHash) }

// Rehydrate restores a persisted approval on boot without firing OnActivate.
func (p *Skills) Rehydrate(name, contentHash string) {
	p.mu.Lock()
	p.active[name] = SkillApproval{Name: name, Version: 1, Hash: contentHash}
	p.known[name] = true
	p.mu.Unlock()
}

// Reset revokes the approval so name becomes unapproved again (fail-closed).
func (p *Skills) Reset(name string) SkillApproval {
	p.mu.Lock()
	delete(p.active, name)
	p.mu.Unlock()
	return p.Get(name)
}

// Verify reports whether name is approved for exactly wantHash.
func (p *Skills) Verify(name, wantHash string) bool {
	g := p.Get(name)
	return g.Version > 0 && g.Hash == wantHash
}

// GovernedSkills wires persistence + audit: each approval is recorded to the
// datastore (rehydrates on boot) and audited to gledger.
func GovernedSkills(known []string, inv *datastore.Store, audit *gledger.AuditLog) *Skills {
	p := NewSkills(known)
	p.OnActivate = func(a SkillApproval) {
		if inv != nil {
			_ = inv.RecordSkillPin(a.Name, fmt.Sprintf("v%d", a.Version), a.Hash)
		}
		if audit != nil {
			short := a.Hash
			if len(short) > 12 {
				short = short[:12]
			}
			audit.Emit(gledger.NewTraceID(), "skill", "approved",
				gledger.F{"name": a.Name, "version": a.Version, "hash": short})
		}
	}
	return p
}
