package controlplane

import (
	"errors"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/pkg/provenance"
)

// newTestAuthority returns an Authority whose verifier trusts its signer, with a
// fixed clock so expiry is deterministic.
func newTestAuthority(t *testing.T, now time.Time) *Authority {
	t.Helper()
	signer, pub, err := provenance.NewSigner("agent")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ver := provenance.NewVerifier().Trust("agent", pub)
	a := NewAuthority(signer, ver)
	a.Now = func() time.Time { return now }
	return a
}

func TestGrantVerifiesWithinScope(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)
	g, err := a.Issue(Capability{Subject: "agent", Action: ActionRead, Resource: "corpus", Tenant: "public"}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.Verify(g, Capability{Action: ActionRead, Resource: "corpus", Tenant: "public"}); err != nil {
		t.Fatalf("exact scope should verify: %v", err)
	}
}

func TestWildcardGrantCoversNarrowRequest(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)
	g, _ := a.Issue(Capability{Subject: "agent", Action: ActionRead, Resource: Scope, Tenant: Scope}, time.Hour)
	if _, err := a.Verify(g, Capability{Action: ActionRead, Resource: "corpus", Tenant: "public"}); err != nil {
		t.Fatalf("wildcard resource/tenant should cover a specific request: %v", err)
	}
}

func TestRequestCannotUseWildcard(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)
	g, _ := a.Issue(Capability{Subject: "agent", Action: ActionRead, Resource: "corpus", Tenant: "public"}, time.Hour)
	// A caller asking for "any resource" against a specific grant is not covered.
	if _, err := a.Verify(g, Capability{Action: ActionRead, Resource: Scope, Tenant: "public"}); !errors.Is(err, ErrGrantScope) {
		t.Fatalf("request-side wildcard must not be covered, got %v", err)
	}
}

func TestOverScopedUseRejected(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)
	// A read grant on the calendar cannot be replayed against the corpus, nor
	// escalated to list (confused deputy / over-scoped use).
	g, _ := a.Issue(Capability{Subject: "agent", Action: ActionRead, Resource: "calendar", Tenant: "public"}, time.Hour)
	for _, want := range []Capability{
		{Action: ActionRead, Resource: "corpus", Tenant: "public"},   // wrong resource
		{Action: ActionList, Resource: "calendar", Tenant: "public"}, // escalated action
		{Action: ActionRead, Resource: "calendar", Tenant: "staff"},  // wrong tenant
	} {
		if _, err := a.Verify(g, want); !errors.Is(err, ErrGrantScope) {
			t.Fatalf("want ErrGrantScope for %+v, got %v", want, err)
		}
	}
}

func TestExpiredGrantRejected(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)
	g, _ := a.Issue(Capability{Subject: "agent", Action: ActionRead, Resource: "corpus", Tenant: "public"}, time.Minute)
	a.Now = func() time.Time { return now.Add(2 * time.Minute) } // clock moves past expiry
	if _, err := a.Verify(g, Capability{Action: ActionRead, Resource: "corpus", Tenant: "public"}); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("want ErrGrantExpired, got %v", err)
	}
}

func TestRevokedSubjectRejected(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)
	g, _ := a.Issue(Capability{Subject: "agent", Action: ActionRead, Resource: "corpus", Tenant: "public"}, time.Hour)
	a.Revoke("agent")
	if _, err := a.Verify(g, Capability{Action: ActionRead, Resource: "corpus", Tenant: "public"}); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("want ErrGrantRevoked after Revoke, got %v", err)
	}
	a.Reinstate("agent")
	if _, err := a.Verify(g, Capability{Action: ActionRead, Resource: "corpus", Tenant: "public"}); err != nil {
		t.Fatalf("reinstated subject should verify: %v", err)
	}
}

// TestKillSwitchRevokesEveryGrant is the kill-switch-as-containment invariant: a
// still-valid, in-scope grant must stop authorizing the instant the switch is
// engaged — not just new requests.
func TestKillSwitchRevokesEveryGrant(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)
	halted := false
	a.Halted = func() bool { return halted }
	g, _ := a.Issue(Capability{Subject: "agent", Action: ActionRead, Resource: "corpus", Tenant: "public"}, time.Hour)
	if _, err := a.Verify(g, Capability{Action: ActionRead, Resource: "corpus", Tenant: "public"}); err != nil {
		t.Fatalf("grant should verify before halt: %v", err)
	}
	halted = true
	if _, err := a.Verify(g, Capability{Action: ActionRead, Resource: "corpus", Tenant: "public"}); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("halt must revoke an in-flight grant, got %v", err)
	}
}

func TestTamperedGrantFailsSignature(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)
	g, _ := a.Issue(Capability{Subject: "agent", Action: ActionRead, Resource: "calendar", Tenant: "public"}, time.Hour)
	g.Resource = "corpus" // forge a broader scope, keep the old signature
	if _, err := a.Verify(g, Capability{Action: ActionRead, Resource: "corpus", Tenant: "public"}); !errors.Is(err, ErrGrantSignature) {
		t.Fatalf("tampered claim must fail signature, got %v", err)
	}
}

// TestFrontierExfilRefusedAtIssuance is the data-residency paradigm: an identity
// bound to an off-host (frontier) model may not be granted list/export over
// confidential data — the /list/contacts exfil vector — even though a local
// identity holds exactly that grant. Enforced fail-closed at issuance.
func TestFrontierExfilRefusedAtIssuance(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)

	confidential := map[string]bool{"contacts": true, "email-bodies": true}
	frontier := map[string]bool{"frontier-planner": true} // subjects bound to an off-host model
	errFrontier := errors.New("frontier identity may not reach confidential data")
	a.IssuePolicy = func(c Capability) error {
		if frontier[c.Subject] && confidential[c.Resource] &&
			(c.Action == ActionList || c.Action == ActionExport) {
			return errFrontier
		}
		return nil
	}

	// Local agent: /list/contacts is fine — data stays on the host.
	if _, err := a.Issue(Capability{Subject: "agent", Action: ActionList, Resource: "contacts", Tenant: "public"}, time.Hour); err != nil {
		t.Fatalf("local list contacts should issue: %v", err)
	}
	// Frontier-bound identity: /list/contacts is refused — it would ship the
	// address book to a third party.
	if _, err := a.Issue(Capability{Subject: "frontier-planner", Action: ActionList, Resource: "contacts", Tenant: "public"}, time.Hour); !errors.Is(err, errFrontier) {
		t.Fatalf("frontier list contacts must be refused, got %v", err)
	}
	// Frontier-bound identity may still read public data.
	if _, err := a.Issue(Capability{Subject: "frontier-planner", Action: ActionRead, Resource: "handbook", Tenant: "public"}, time.Hour); err != nil {
		t.Fatalf("frontier read of public data should issue: %v", err)
	}
}

// TestResidencyPolicy exercises the reusable policy the app wires: frontier
// subjects are refused list/export of confidential resources, everyone else
// passes (reads, public/declassified resources, local subjects).
func TestResidencyPolicy(t *testing.T) {
	pol := ResidencyPolicy(
		map[string]bool{"frontier-planner": true},
		map[string]bool{"contacts": true, "email-bodies": true},
	)
	refuse := []Capability{
		{Subject: "frontier-planner", Action: ActionList, Resource: "contacts"},
		{Subject: "frontier-planner", Action: ActionExport, Resource: "email-bodies"},
	}
	for _, c := range refuse {
		if err := pol(c); err == nil {
			t.Fatalf("frontier %s/%s should be refused", c.Action, c.Resource)
		}
	}
	allow := []Capability{
		{Subject: "frontier-planner", Action: ActionRead, Resource: "contacts"}, // read, not harvest
		{Subject: "frontier-planner", Action: ActionList, Resource: "corpus"},   // scrubbed/declassified
		{Subject: "local-agent", Action: ActionExport, Resource: "contacts"},    // on-host, data stays
	}
	for _, c := range allow {
		if err := pol(c); err != nil {
			t.Fatalf("%s %s/%s should be allowed, got %v", c.Subject, c.Action, c.Resource, err)
		}
	}
}

// TestMultiScopeGrantLeastPrivilege is the App-grant invariant: one signed grant
// covers several distinct consumer scopes (primary + extra) but NOTHING on the
// governed control plane, and a scope appended after issuance fails the signature.
func TestMultiScopeGrantLeastPrivilege(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	a := newTestAuthority(t, now)
	g, err := a.IssueScoped(
		Capability{Subject: "app", Action: ActionList, Resource: "corpus", Tenant: "public"},
		[]GrantScope{
			{Action: ActionWrite, Resource: "calendar", Tenant: "public"},
			{Action: ActionExport, Resource: "link", Tenant: "public"},
		}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Authorized: the primary scope and every extra scope.
	for _, w := range []Capability{
		{Action: ActionList, Resource: "corpus", Tenant: "public"},
		{Action: ActionWrite, Resource: "calendar", Tenant: "public"},
		{Action: ActionExport, Resource: "link", Tenant: "public"},
	} {
		if _, err := a.Verify(g, w); err != nil {
			t.Errorf("app grant should authorize %+v: %v", w, err)
		}
	}
	// Refused: any governed control-plane scope — the whole point.
	for _, w := range []Capability{
		{Action: ActionWrite, Resource: "prompts", Tenant: "public"},
		{Action: ActionWrite, Resource: "sampling", Tenant: "public"},
		{Action: ActionWrite, Resource: "retrieval", Tenant: "public"},
		{Action: ActionList, Resource: "contacts", Tenant: "public"}, // no harvest
	} {
		if _, err := a.Verify(g, w); err == nil {
			t.Errorf("app grant must NOT authorize governed scope %+v", w)
		}
	}
	// Tamper: append a scope after issuance → signature fails (the scope rides inside
	// the signed payload).
	forged := g
	forged.Extra = append(append([]GrantScope{}, g.Extra...), GrantScope{Action: ActionWrite, Resource: "prompts", Tenant: "public"})
	if _, err := a.Verify(forged, Capability{Action: ActionWrite, Resource: "prompts", Tenant: "public"}); err != ErrGrantSignature {
		t.Errorf("appended scope should fail signature, got: %v", err)
	}
}
