package controlplane

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

// TestSkillsFailClosedUntilApproved is the security default: a known-but-unapproved
// skill has no pin, so it is absent from Pins() and the loader fails closed.
func TestSkillsFailClosedUntilApproved(t *testing.T) {
	p := NewSkills([]string{"calendar-helper"})
	if g := p.Get("calendar-helper"); g.Version != 0 || g.Hash != "" {
		t.Fatalf("unapproved skill should be v0/empty, got %+v", g)
	}
	if _, ok := p.Pins()["calendar-helper"]; ok {
		t.Fatal("unapproved skill must NOT appear in Pins()")
	}
	if p.Verify("calendar-helper", "anything") {
		t.Fatal("Verify must reject an unapproved skill")
	}
	// Listing still shows it (operator is aware of it; just not trusting it).
	if got := p.List(); len(got) != 1 || got[0].Version != 0 {
		t.Fatalf("known skill should list at v0, got %+v", got)
	}
}

// TestSkillsApproveResetRoundTrip: approving pins the content hash; reset revokes it
// back to fail-closed; re-approving a different hash bumps the governance version
// (the re-approval path after a rug-pull).
func TestSkillsApproveResetRoundTrip(t *testing.T) {
	p := NewSkills(nil)
	a := p.Approve("calendar-helper", "hash-v1")
	if a.Version != 1 || p.Pins()["calendar-helper"] != "hash-v1" {
		t.Fatalf("approve should pin hash-v1 at v1, got %+v", a)
	}
	if !p.Verify("calendar-helper", "hash-v1") {
		t.Fatal("Verify should accept the approved hash")
	}
	a2 := p.Approve("calendar-helper", "hash-v2")
	if a2.Version != 2 || p.Pins()["calendar-helper"] != "hash-v2" {
		t.Fatalf("re-approve should pin hash-v2 at v2, got %+v", a2)
	}
	if r := p.Reset("calendar-helper"); r.Version != 0 || r.Hash != "" {
		t.Fatalf("reset should revoke to fail-closed, got %+v", r)
	}
	if _, ok := p.Pins()["calendar-helper"]; ok {
		t.Fatal("reset skill must drop out of Pins()")
	}
}

// TestGovernedSkillsPersist proves the approval is written to the live datastore and
// can be read back for rehydrate-on-boot.
func TestGovernedSkillsPersist(t *testing.T) {
	inv, _ := datastore.Open(":memory:")
	defer inv.Close()
	p := GovernedSkills([]string{"calendar-helper"}, inv, nil)
	p.Approve("calendar-helper", "deadbeefcafebabe")
	hash, ok, err := inv.LatestSkillPin("calendar-helper")
	if err != nil || !ok || hash != "deadbeefcafebabe" {
		t.Fatalf("approval should persist the pin, ok=%v err=%v hash=%q", ok, err, hash)
	}
}
