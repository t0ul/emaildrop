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

// SamplingConfig is a model's decoding parameters. Seed makes a generation
// reproducible — the same prompt + config yields the same output, which turns an
// eval or a forensic replay into a repeatable experiment instead of a one-off.
type SamplingConfig struct {
	Temperature float64  `json:"temperature"`
	MaxTokens   int      `json:"max_tokens"`
	TopP        float64  `json:"top_p,omitempty"`
	Seed        int      `json:"seed,omitempty"`
	Stop        []string `json:"stop,omitempty"`
}

// SamplingVersion is a resolved, content-hashed sampling config (C5). Version 0 is
// the shipped default; >0 is a governed activation.
type SamplingVersion struct {
	Name    string         `json:"name"`
	Version int            `json:"version"`
	Hash    string         `json:"hash"`
	Config  SamplingConfig `json:"config"`
}

// HashSampling is the content pin for a sampling config (sha256 over its JSON).
func HashSampling(c SamplingConfig) string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Sampling is the runtime resolver for per-model decoding parameters — the C5
// twin of the prompts/policies planes. Hardcoded CompleteOpts literals become a
// governed, versioned, rollback-able artifact; an un-set model resolves to the
// shipped default (fail-closed to what the binary trusts).
type Sampling struct {
	mu         sync.RWMutex
	defaults   map[string]SamplingConfig
	active     map[string]SamplingVersion
	OnActivate func(SamplingVersion)
}

// NewSampling seeds the resolver with the shipped default configs by model name.
func NewSampling(defaults map[string]SamplingConfig) *Sampling {
	cp := make(map[string]SamplingConfig, len(defaults))
	for k, v := range defaults {
		cp[k] = v
	}
	return &Sampling{defaults: cp, active: map[string]SamplingVersion{}}
}

// Get returns the active sampling for name, or its default (version 0).
func (p *Sampling) Get(name string) SamplingVersion {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if v, ok := p.active[name]; ok {
		return v
	}
	c := p.defaults[name]
	return SamplingVersion{Name: name, Version: 0, Hash: HashSampling(c), Config: c}
}

// Config is the active (or default) sampling config for name.
func (p *Sampling) Config(name string) SamplingConfig { return p.Get(name).Config }

// List returns the current sampling for every known model, sorted.
func (p *Sampling) List() []SamplingVersion {
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
	out := make([]SamplingVersion, 0, len(ordered))
	for _, n := range ordered {
		out = append(out, p.Get(n))
	}
	return out
}

// Activate records a new active sampling version and returns it.
func (p *Sampling) Activate(name string, c SamplingConfig) SamplingVersion {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := 1
	if v, ok := p.active[name]; ok {
		next = v.Version + 1
	}
	pv := SamplingVersion{Name: name, Version: next, Hash: HashSampling(c), Config: c}
	p.active[name] = pv
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Rehydrate restores a persisted active config loaded from the governed store on
// boot, without firing OnActivate (a reload, not a new activation).
func (p *Sampling) Rehydrate(name string, c SamplingConfig) {
	p.mu.Lock()
	p.active[name] = SamplingVersion{Name: name, Version: 1, Hash: HashSampling(c), Config: c}
	p.mu.Unlock()
}

// Reset reverts name to the shipped default (version 0).
func (p *Sampling) Reset(name string) SamplingVersion {
	p.mu.Lock()
	delete(p.active, name)
	p.mu.Unlock()
	pv := p.Get(name)
	if p.OnActivate != nil {
		p.OnActivate(pv)
	}
	return pv
}

// Verify reports whether the active sampling for name still matches wantHash.
func (p *Sampling) Verify(name, wantHash string) bool {
	return p.Get(name).Hash == wantHash
}

// GovernedSampling persists activations (datastore.RecordSampling) and audits them
// to gledger, so a sampling change survives restarts and is attributable (M19).
func GovernedSampling(defaults map[string]SamplingConfig, inv *datastore.Store, audit *gledger.AuditLog) *Sampling {
	p := NewSampling(defaults)
	p.OnActivate = func(pv SamplingVersion) {
		if inv != nil {
			b, _ := json.Marshal(pv.Config)
			_ = inv.RecordSampling(pv.Name, "v"+strconv.Itoa(pv.Version), pv.Hash, string(b))
		}
		if audit != nil {
			audit.Emit(gledger.NewTraceID(), "sampling", "activated",
				gledger.F{"name": pv.Name, "version": pv.Version, "hash": pv.Hash[:12],
					"temperature": pv.Config.Temperature, "seed": pv.Config.Seed})
		}
	}
	return p
}
