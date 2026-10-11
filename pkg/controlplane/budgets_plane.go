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

// BudgetConfig is the governed resource envelope for a caller/model (C9/M20):
// rate, token, concurrency, and spend ceilings. KeyRef is a POINTER to a secret —
// the NAME of the environment variable that holds the key — never the key value
// itself, so credentials never land in the governed config or the DB.
type BudgetConfig struct {
	RatePerMin     int     `json:"rate_per_min,omitempty"`
	MaxTokens      int     `json:"max_tokens,omitempty"`
	MaxConcurrency int     `json:"max_concurrency,omitempty"`
	SpendCapUSD    float64 `json:"spend_cap_usd,omitempty"`
	KeyRef         string  `json:"key_ref,omitempty"` // env-var name holding the key (pointer, not the value)
}

// BudgetVersion is a resolved, content-hashed budget. Version 0 is the shipped
// default; >0 is a governed activation.
type BudgetVersion struct {
	Name    string       `json:"name"`
	Version int          `json:"version"`
	Hash    string       `json:"hash"`
	Config  BudgetConfig `json:"config"`
}

// HashBudget is the content pin for a budget config.
func HashBudget(c BudgetConfig) string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Budgets is the runtime resolver for governed budgets/limits (C9) — the plane
// twin of the gateway's enforcement. Rate/token/spend are enforced gateway-side
// (gouncer); this plane makes them versioned, hashed, rollback-able artifacts the
// operator governs, and exposes key POINTERS (never values).
type Budgets struct {
	mu         sync.RWMutex
	defaults   map[string]BudgetConfig
	active     map[string]BudgetVersion
	OnActivate func(BudgetVersion)
}

// NewBudgets seeds the resolver with the shipped default budgets by name.
func NewBudgets(defaults map[string]BudgetConfig) *Budgets {
	cp := make(map[string]BudgetConfig, len(defaults))
	for k, v := range defaults {
		cp[k] = v
	}
	return &Budgets{defaults: cp, active: map[string]BudgetVersion{}}
}

// Get returns the active budget for name, or its default (version 0).
func (p *Budgets) Get(name string) BudgetVersion {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if v, ok := p.active[name]; ok {
		return v
	}
	c := p.defaults[name]
	return BudgetVersion{Name: name, Version: 0, Hash: HashBudget(c), Config: c}
}

// Config is the active (or default) budget config for name.
func (p *Budgets) Config(name string) BudgetConfig { return p.Get(name).Config }

// List returns the current budget for every known name, sorted.
func (p *Budgets) List() []BudgetVersion {
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
	out := make([]BudgetVersion, 0, len(ordered))
	for _, n := range ordered {
		out = append(out, p.Get(n))
	}
	return out
}

// Activate records a new active budget version and returns it.
func (p *Budgets) Activate(name string, c BudgetConfig) BudgetVersion {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := 1
	if v, ok := p.active[name]; ok {
		next = v.Version + 1
	}
	pv := BudgetVersion{Name: name, Version: next, Hash: HashBudget(c), Config: c}
	p.active[name] = pv
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Rehydrate restores a persisted active budget on boot, without firing OnActivate.
func (p *Budgets) Rehydrate(name string, c BudgetConfig) {
	p.mu.Lock()
	p.active[name] = BudgetVersion{Name: name, Version: 1, Hash: HashBudget(c), Config: c}
	p.mu.Unlock()
}

// Reset reverts name to the shipped default (version 0).
func (p *Budgets) Reset(name string) BudgetVersion {
	p.mu.Lock()
	delete(p.active, name)
	p.mu.Unlock()
	pv := p.Get(name)
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Verify reports whether the active budget for name still matches wantHash.
func (p *Budgets) Verify(name, wantHash string) bool {
	return p.Get(name).Hash == wantHash
}

// GovernedBudgets persists activations (datastore.RecordBudget) and audits them to
// gledger, so a budget change survives restarts and is attributable (M20).
func GovernedBudgets(defaults map[string]BudgetConfig, inv *datastore.Store, audit *gledger.AuditLog) *Budgets {
	p := NewBudgets(defaults)
	p.OnActivate = func(pv BudgetVersion) {
		if inv != nil {
			b, _ := json.Marshal(pv.Config)
			_ = inv.RecordBudget(pv.Name, "v"+strconv.Itoa(pv.Version), pv.Hash, string(b))
		}
		if audit != nil {
			audit.Emit(gledger.NewTraceID(), "budget", "activated",
				gledger.F{"name": pv.Name, "version": pv.Version, "hash": pv.Hash[:12],
					"rate_per_min": pv.Config.RatePerMin, "key_ref": pv.Config.KeyRef})
		}
	}
	return p
}
