package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/gledger"
)

// Policies is the runtime resolver for the agent's security policy allowlists —
// the C8 twin of the prompts plane (C1/C2). Each policy is a named allowlist
// (egress hosts, exec argv[0]s, guardrail topics, ...) resolved at runtime from a
// governed store, versioned and content-hashed so a change can be pinned,
// audited, and rolled back. An un-set policy resolves to the shipped default
// (fail-closed to what the binary trusts). Widening a policy is a governed,
// attributable, reversible act — not a code edit. The deny-by-default enforcement
// (netpolicy private/IMDS block, argcheck) is independent of the allowlist, so a
// governed widening still cannot reach link-local/RFC1918 (covered by the SSRF /
// AllowlistBypass ADD cases).
type Policies struct {
	mu       sync.RWMutex
	defaults map[string][]string
	active   map[string]PolicyVersion
	// OnActivate persists/audits each activation (datastore.RecordPolicy + gledger).
	OnActivate func(PolicyVersion)
}

// PolicyVersion is a resolved, content-hashed allowlist. Version 0 is the shipped
// default; >0 is a governed activation.
type PolicyVersion struct {
	Name    string   `json:"name"`
	Version int      `json:"version"`
	Hash    string   `json:"hash"`
	Items   []string `json:"items"`
}

// HashPolicy is the content pin for an allowlist (order-independent: sorted,
// newline-joined, sha256 hex).
func HashPolicy(items []string) string {
	c := append([]string(nil), items...)
	sort.Strings(c)
	sum := sha256.Sum256([]byte(strings.Join(c, "\n")))
	return hex.EncodeToString(sum[:])
}

// NewPolicies seeds the resolver with the shipped default allowlists by name.
func NewPolicies(defaults map[string][]string) *Policies {
	cp := make(map[string][]string, len(defaults))
	for k, v := range defaults {
		cp[k] = append([]string(nil), v...)
	}
	return &Policies{defaults: cp, active: map[string]PolicyVersion{}}
}

// Get returns the active policy for name, or its default (version 0).
func (p *Policies) Get(name string) PolicyVersion {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if v, ok := p.active[name]; ok {
		return v
	}
	items := append([]string(nil), p.defaults[name]...)
	return PolicyVersion{Name: name, Version: 0, Hash: HashPolicy(items), Items: items}
}

// Items is the active (or default) allowlist for name.
func (p *Policies) Items(name string) []string { return p.Get(name).Items }

// List returns the current policy for every known name, sorted.
func (p *Policies) List() []PolicyVersion {
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
	out := make([]PolicyVersion, 0, len(ordered))
	for _, n := range ordered {
		out = append(out, p.Get(n))
	}
	return out
}

// Activate records a new active version of name's allowlist and returns it.
func (p *Policies) Activate(name string, items []string) PolicyVersion {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := 1
	if v, ok := p.active[name]; ok {
		next = v.Version + 1
	}
	cp := append([]string(nil), items...)
	pv := PolicyVersion{Name: name, Version: next, Hash: HashPolicy(cp), Items: cp}
	p.active[name] = pv
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Rehydrate restores a persisted active allowlist loaded from the governed store
// on boot, without firing OnActivate (a reload, not a new activation).
func (p *Policies) Rehydrate(name string, items []string) {
	cp := append([]string(nil), items...)
	p.mu.Lock()
	p.active[name] = PolicyVersion{Name: name, Version: 1, Hash: HashPolicy(cp), Items: cp}
	p.mu.Unlock()
}

// Reset reverts name to the shipped default (version 0) — rollback to known-good.
func (p *Policies) Reset(name string) PolicyVersion {
	p.mu.Lock()
	delete(p.active, name)
	p.mu.Unlock()
	pv := p.Get(name)
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Verify reports whether the active policy for name still matches wantHash.
func (p *Policies) Verify(name, wantHash string) bool {
	return p.Get(name).Hash == wantHash
}

// GovernedPolicies is a resolver whose activations are durably persisted
// (datastore.RecordPolicy) and audited to gledger (M14/M15), so a policy change
// survives restarts and is attributable.
func GovernedPolicies(defaults map[string][]string, inv *datastore.Store, audit *gledger.AuditLog) *Policies {
	p := NewPolicies(defaults)
	p.OnActivate = func(pv PolicyVersion) {
		if inv != nil {
			_ = inv.RecordPolicy(pv.Name, "v"+strconv.Itoa(pv.Version), pv.Hash, strings.Join(pv.Items, "\n"))
		}
		if audit != nil {
			audit.Emit(gledger.NewTraceID(), "policy", "activated",
				gledger.F{"name": pv.Name, "version": pv.Version, "hash": pv.Hash[:12], "count": len(pv.Items)})
		}
	}
	return p
}
