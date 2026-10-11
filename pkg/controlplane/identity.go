package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/t0ul/emaildrop/pkg/provenance"
)

// Non-human identity (NHI) and capability-based authorization (C4a).
//
// Every actor in the agent that is not a human — the agent itself, each tool,
// each MCP server, the RAG reader — is a non-human identity: a named Subject
// that must present a signed, scoped, short-lived Grant to do anything with a
// side effect. This is the least-privilege spine the API authZ layer (C4b), the
// kill-switch-as-revocation demo (C4c), the read-only RAG path (C4d), and the
// scoped MCP tokens (C4e) all build on.
//
// A Grant is a Capability (who may do what, to which resource, in which tenant,
// until when) plus a detached ed25519 signature over its canonical bytes. It
// reuses the agent's existing provenance Signer/Verifier, so an NHI credential
// and an .ics content credential share one trust root — no new key management.
// A Grant is a bearer token: hold it and you may act within its scope until it
// expires or is revoked. Scopes never widen at use; a narrower request is
// covered by a broader grant, never the reverse (no confused deputy).
//
// Fail-closed throughout: an unsigned, tampered, expired, out-of-scope, or
// revoked Grant authorizes nothing, and engaging the kill switch (Halted)
// revokes every Grant at once — the containment primitive behind the kill-switch
// demo.
//
// Data-residency-aware scoping (the paradigm). A capability is scoped on three
// axes, not one:
//
//   - Action granularity. ActionRead (one named item you were told about) is not
//     ActionList (enumerate the whole set — the *harvest* primitive) is not
//     ActionExport (egress off the identity's boundary). Exfiltration needs
//     enumerate + export; those stay privileged apart from read, so a grant that
//     lets the agent read one contact never lets it harvest the address book.
//   - Resource classification (public / internal / confidential-PII), carried by
//     the caller's policy, not by this token.
//   - Consumer trust tier: where the Subject's *bound model* runs — on-host-local
//     (data never leaves the Mac) vs off-host-frontier (data ships to a third
//     party). The same read scope that is safe for a local model is an exfil
//     vector for a frontier one.
//
// The rule lives at issuance (IssuePolicy), not in the bearer token: a grant is
// mintable only if the consumer tier is cleared for the resource classification.
// A frontier-bound Subject is denied any confidential resource and any
// ActionList/ActionExport over one; it may receive only public or
// goflage-scrubbed (declassified) data. Because of this, swapping a Subject's
// model binding local->frontier (a governed model-swap, C5) is a
// grant-invalidating event: the swap must Revoke the Subject so no outstanding
// grant silently starts leaking. You cannot raise data egress by editing a model
// binding.

var (
	// ErrGrantSignature means the Grant's signature does not verify against a
	// trusted key — forged, tampered, or signed by an unknown identity.
	ErrGrantSignature = errors.New("controlplane: grant signature does not verify")
	// ErrGrantExpired means the Grant's lifetime has elapsed.
	ErrGrantExpired = errors.New("controlplane: grant expired")
	// ErrGrantRevoked means the Grant's subject is revoked, or the kill switch
	// has revoked all grants.
	ErrGrantRevoked = errors.New("controlplane: grant revoked")
	// ErrGrantScope means the Grant does not cover the requested action,
	// resource, or tenant (over-scoped use / wrong audience).
	ErrGrantScope = errors.New("controlplane: grant does not cover requested scope")
	// ErrResidency means issuance was refused because the subject's bound model
	// runs off-host (frontier) and the capability would ship confidential data
	// to a third party.
	ErrResidency = errors.New("controlplane: capability refused by data-residency policy")
)

// Scope is a wildcard that a Grant field may hold to cover any requested value
// for that field. A request may never use it; only a grant may be broad.
const Scope = "*"

// Conventional actions, least to most dangerous. The split is the point:
// enumeration (ActionList) and egress (ActionExport) are the primitives an
// exfiltration needs and are scoped apart from a plain ActionRead, so a
// read-one grant can never harvest or ship a whole collection.
const (
	ActionRead   = "read"   // fetch one named item you already know
	ActionList   = "list"   // enumerate a collection — the harvest primitive
	ActionWrite  = "write"  // create or modify
	ActionExport = "export" // send off the identity's boundary (email, upload, frontier inference)
)

// Capability is the claim a non-human identity carries: Subject may perform
// Action on Resource within Tenant, from Issued until Expires. Nonce makes two
// otherwise-identical grants distinguishable and their signatures unique.
type Capability struct {
	Subject  string    `json:"sub"`
	Action   string    `json:"act"`
	Resource string    `json:"res"`
	Tenant   string    `json:"ten"`
	Issued   time.Time `json:"iat"`
	Expires  time.Time `json:"exp"`
	Nonce    string    `json:"jti,omitempty"`
}

// Grant is a Capability with a detached content credential over its canonical
// bytes — a signed, scoped, expiring bearer token for one non-human identity.
// Scope is one (action, resource, tenant) triple a grant authorizes, beyond its
// primary Capability. It lets a single signed grant carry several distinct scopes
// — e.g. the household App's {list corpus, write calendar, write inbox, …} — which
// a single-capability grant cannot express, while a wildcard (*) grant would
// over-authorize. Every Scope rides inside the signed payload, so none can be
// added or widened after issuance.
type GrantScope struct {
	Action   string `json:"act"`
	Resource string `json:"res"`
	Tenant   string `json:"ten"`
}

type Grant struct {
	Capability
	// Extra are additional scopes this grant also covers (least-privilege for a
	// multi-route subject like the App). Nil for a single-capability grant.
	Extra []GrantScope    `json:"extra,omitempty"`
	Mark  provenance.Mark `json:"mark"`
}

// signedPayload is the canonical byte form the Mark signs: the primary capability
// AND every Extra scope, so the signature pins the whole grant (a tampered or
// appended scope fails verification). For a grant with no Extra it is identical in
// spirit to the primary capability's canonical form, just wrapped.
func (g Grant) signedPayload() []byte {
	b, _ := json.Marshal(struct {
		Cap   Capability   `json:"cap"`
		Extra []GrantScope `json:"extra,omitempty"`
	}{Cap: g.Capability, Extra: g.Extra})
	return b
}

// canonical is the exact byte sequence that is signed and verified. json.Marshal
// of a struct is deterministic (field order is declaration order), so signer and
// verifier agree without a separate canonicalizer.
func (c Capability) canonical() []byte {
	b, _ := json.Marshal(c)
	return b
}

// covers reports whether a granted scope field authorizes a requested one: an
// exact match, or the wildcard Scope on the grant side. The request side may not
// use the wildcard — a caller cannot ask for "any resource".
func covers(granted, requested string) bool {
	return granted == Scope || granted == requested
}

// Authority issues and verifies Grants for one trust root. It owns the agent's
// provenance Signer (to mint grants) and Verifier (to check them), a revocation
// set, and an optional Halted hook wired to the kill switch. It is safe for
// concurrent use.
type Authority struct {
	signer   *provenance.Signer
	verifier *provenance.Verifier

	// Now, when set, supplies the clock (for tests and reproducible forensics).
	// Defaults to time.Now.
	Now func() time.Time
	// Halted, when set and returning true, revokes every Grant — the kill
	// switch as containment. Wire it to Safety: func() bool { return
	// safety.Level() >= LevelHalt }.
	Halted func() bool

	// IssuePolicy, when set, is consulted before minting any Grant and can
	// refuse one fail-closed by returning an error. This is where
	// data-residency rules live: refuse a confidential Resource, or an
	// ActionList/ActionExport over one, to a Subject whose bound model runs
	// off-host (frontier). It sees the capability with defaults already
	// applied. A refused issuance is audited by the caller, never silently
	// downgraded.
	IssuePolicy func(Capability) error

	mu      sync.Mutex
	revoked map[string]bool // subject -> revoked
}

// NewAuthority returns an Authority that mints Grants with signer and checks
// them with verifier. The verifier must already Trust the signer's key id.
func NewAuthority(signer *provenance.Signer, verifier *provenance.Verifier) *Authority {
	return &Authority{signer: signer, verifier: verifier, revoked: map[string]bool{}}
}

// ResidencyPolicy builds an IssuePolicy that enforces the data-residency rule: a
// subject whose bound model runs off-host (frontier) may not be granted
// ActionList or ActionExport over a confidential resource, because that ships the
// data to a third party. frontier maps subject->true (absent = on-host, trusted);
// confidential maps resource->true. Everything else — reads, public/declassified
// resources (e.g. a goflage-scrubbed corpus), local subjects — is allowed.
// Swapping a subject's binding local->frontier (a governed model-swap) therefore
// refuses its next issuance; pair it with Revoke to kill outstanding grants.
func ResidencyPolicy(frontier, confidential map[string]bool) func(Capability) error {
	return func(c Capability) error {
		if frontier[c.Subject] && confidential[c.Resource] && (c.Action == ActionList || c.Action == ActionExport) {
			return fmt.Errorf("%w: %q is frontier-bound and may not %s confidential %q", ErrResidency, c.Subject, c.Action, c.Resource)
		}
		return nil
	}
}

func (a *Authority) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Issue mints a Grant for cap, valid for ttl from now. Subject and Action must be
// set; Resource and Tenant default to the wildcard Scope (deliberately broad
// only when the caller leaves them empty — callers scope down).
func (a *Authority) Issue(cap Capability, ttl time.Duration) (Grant, error) {
	return a.IssueScoped(cap, nil, ttl)
}

// IssueScoped mints a grant whose primary capability is cap and which ALSO covers
// each Scope in extra — a least-privilege, multi-route grant (e.g. the App). The
// issue policy (residency) is applied to the primary AND every extra scope, so a
// frontier-bound subject cannot smuggle a confidential list/export in via extra.
// The signature covers the whole grant.
func (a *Authority) IssueScoped(cap Capability, extra []GrantScope, ttl time.Duration) (Grant, error) {
	if cap.Subject == "" || cap.Action == "" {
		return Grant{}, errors.New("controlplane: capability needs a subject and action")
	}
	if cap.Resource == "" {
		cap.Resource = Scope
	}
	if cap.Tenant == "" {
		cap.Tenant = Scope
	}
	if a.IssuePolicy != nil {
		if err := a.IssuePolicy(cap); err != nil {
			return Grant{}, err
		}
		for _, s := range extra {
			sc := Capability{Subject: cap.Subject, Action: s.Action, Resource: s.Resource, Tenant: s.Tenant}
			if err := a.IssuePolicy(sc); err != nil {
				return Grant{}, err
			}
		}
	}
	now := a.now()
	cap.Issued = now.UTC()
	cap.Expires = now.Add(ttl).UTC()
	g := Grant{Capability: cap, Extra: extra}
	g.Mark = a.signer.Sign(g.signedPayload())
	return g, nil
}

// Revoke marks a subject's grants invalid from now on (credential compromise,
// deprovisioning). Idempotent.
func (a *Authority) Revoke(subject string) {
	a.mu.Lock()
	a.revoked[subject] = true
	a.mu.Unlock()
}

// Reinstate clears a prior Revoke for subject.
func (a *Authority) Reinstate(subject string) {
	a.mu.Lock()
	delete(a.revoked, subject)
	a.mu.Unlock()
}

func (a *Authority) isRevoked(subject string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.revoked[subject]
}

// Verify checks that g is authentic, live, and covers want. want carries the
// action/resource/tenant the caller wants to perform now; the grant must cover
// each (exact match or the grant's wildcard). On success the authenticated
// Capability is returned for audit. Fail-closed: any failure authorizes nothing.
//
// Order matters — signature first (is this a real grant at all?), then the kill
// switch and revocation (containment outranks a still-valid scope), then expiry,
// then scope.
func (a *Authority) Verify(g Grant, want Capability) (Capability, error) {
	if err := a.verifier.Verify(g.signedPayload(), g.Mark); err != nil {
		return Capability{}, ErrGrantSignature
	}
	if a.Halted != nil && a.Halted() {
		return Capability{}, ErrGrantRevoked
	}
	if a.isRevoked(g.Subject) {
		return Capability{}, ErrGrantRevoked
	}
	if !a.now().Before(g.Expires) {
		return Capability{}, ErrGrantExpired
	}
	if want.Subject != "" && want.Subject != g.Subject {
		return Capability{}, ErrGrantScope
	}
	// The primary capability, or any extra scope, must cover the request.
	if covers(g.Action, want.Action) && covers(g.Resource, want.Resource) && covers(g.Tenant, want.Tenant) {
		return g.Capability, nil
	}
	for _, s := range g.Extra {
		if covers(s.Action, want.Action) && covers(s.Resource, want.Resource) && covers(s.Tenant, want.Tenant) {
			return Capability{Subject: g.Subject, Action: s.Action, Resource: s.Resource, Tenant: s.Tenant, Issued: g.Issued, Expires: g.Expires}, nil
		}
	}
	return Capability{}, ErrGrantScope
}

// VerifyGlass is Verify WITHOUT the kill-switch (Halted) and per-subject revocation
// checks — the break-glass path for the kill-switch endpoint itself. Engaging Halt
// revokes every grant, so a normally-gated kill switch could never be DISENGAGED;
// this lets the operator always reach it. It still enforces signature, subject,
// expiry, and scope, so a narrow (e.g. App) token cannot toggle the switch.
func (a *Authority) VerifyGlass(g Grant, want Capability) (Capability, error) {
	if err := a.verifier.Verify(g.signedPayload(), g.Mark); err != nil {
		return Capability{}, ErrGrantSignature
	}
	if !a.now().Before(g.Expires) {
		return Capability{}, ErrGrantExpired
	}
	if want.Subject != "" && want.Subject != g.Subject {
		return Capability{}, ErrGrantScope
	}
	if covers(g.Action, want.Action) && covers(g.Resource, want.Resource) && covers(g.Tenant, want.Tenant) {
		return g.Capability, nil
	}
	for _, s := range g.Extra {
		if covers(s.Action, want.Action) && covers(s.Resource, want.Resource) && covers(s.Tenant, want.Tenant) {
			return Capability{Subject: g.Subject, Action: s.Action, Resource: s.Resource, Tenant: s.Tenant, Issued: g.Issued, Expires: g.Expires}, nil
		}
	}
	return Capability{}, ErrGrantScope
}
