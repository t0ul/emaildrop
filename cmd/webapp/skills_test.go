package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/datastore"
)

// liveSkills wires the real signed catalog to a real governed plane backed by a real
// (throwaway) SQLite file — no mocks, the same objects main.go builds.
func liveSkills(t *testing.T) (*skillLoader, *controlplane.Skills, *datastore.Store) {
	t.Helper()
	inv, err := datastore.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("open datastore: %v", err)
	}
	loader, names, persistent, err := newSkillLoader(filepath.Join(t.TempDir(), "skill-author.key"))
	if err != nil {
		t.Fatalf("new skill loader: %v", err)
	}
	if !persistent {
		t.Fatal("skill-author key on a fresh temp dir must be persistent")
	}
	plane := controlplane.GovernedSkills(names, inv, nil)
	loader.attach(plane)
	return loader, plane, inv
}

// TestSkillAuthorAnchorPersists locks B2: the skill-author trust anchor is loaded from a
// persistent seed, so the SAME trusted key (and thus the operator's approval) survives a
// restart — it is not re-minted per boot. Real seed file, real signed catalog.
func TestSkillAuthorAnchorPersists(t *testing.T) {
	key := filepath.Join(t.TempDir(), "skill-author.key")
	l1, _, p1, err := newSkillLoader(key)
	if err != nil || !p1 {
		t.Fatalf("first load: persistent=%v err=%v", p1, err)
	}
	l2, _, p2, err := newSkillLoader(key)
	if err != nil || !p2 {
		t.Fatalf("second load: persistent=%v err=%v", p2, err)
	}
	// Same anchor across "restarts": the benign skill signed by run 2's author key must
	// verify under run 1's verifier. A boot-minted key would fail this.
	s := l2.catalog["calendar-helper"]
	if l1.verifier.Verify(s.Skill.Canonical(), s.Mark) != nil {
		t.Fatal("skill-author anchor changed across loads — approvals would not survive a restart")
	}
}

// TestSkillLoaderFailsClosedThenLoadsOnApprove is the governed consumer end to end:
// an untrusted-signed skill is always refused; a trusted skill is refused until the
// operator approves its exact content, then loads.
func TestSkillLoaderFailsClosedThenLoadsOnApprove(t *testing.T) {
	loader, plane, inv := liveSkills(t)
	defer inv.Close()

	// Attacker-signed skill: refused regardless of approval (untrusted signature).
	if r := loader.Load("free-ical-pro", false); r.Loaded {
		t.Fatalf("attacker-signed skill must never load, got %+v", r)
	} else if !strings.Contains(r.Reason, "signature") {
		t.Fatalf("want signature-refusal reason, got %q", r.Reason)
	}

	// Trusted skill, not yet approved: refused (fail-closed on the pin).
	if r := loader.Load("calendar-helper", false); r.Loaded {
		t.Fatalf("unapproved skill must not load, got %+v", r)
	} else if !strings.Contains(r.Reason, "approved") {
		t.Fatalf("want not-approved reason, got %q", r.Reason)
	}

	// Operator approves the exact catalog content → the pin now matches.
	hash, ok := loader.FullHash("calendar-helper")
	if !ok {
		t.Fatal("catalog missing calendar-helper")
	}
	plane.Approve("calendar-helper", hash)

	if r := loader.Load("calendar-helper", false); !r.Loaded || r.Unsafe || r.Instructions == "" {
		t.Fatalf("approved trusted skill should load through the gate, got %+v", r)
	}
	// Persisted for rehydrate-on-boot.
	if h, ok, _ := inv.LatestSkillPin("calendar-helper"); !ok || h != hash {
		t.Fatalf("approval should persist the pin, ok=%v h=%q", ok, h)
	}
}

// TestActiveInstructionsSummonsOnlyApprovedTrusted locks B3: the live consumer injects a
// skill's instructions ONLY once the operator has approved its trusted content; an
// unapproved skill and the attacker-signed skill never reach the prompt.
func TestActiveInstructionsSummonsOnlyApprovedTrusted(t *testing.T) {
	loader, plane, inv := liveSkills(t)
	defer inv.Close()

	// Nothing approved yet → nothing summoned.
	if got := loader.ActiveInstructions(); len(got) != 0 {
		t.Fatalf("no approvals → no summoned skills, got %v", got)
	}

	// Approve the trusted skill → its instructions are summoned.
	h, _ := loader.FullHash("calendar-helper")
	plane.Approve("calendar-helper", h)
	got := loader.ActiveInstructions()
	if len(got) != 1 || !strings.Contains(got[0], "summarize the extracted calendar events") {
		t.Fatalf("approved trusted skill should be summoned, got %v", got)
	}

	// Even if an operator tries to approve the attacker skill's hash, the untrusted
	// signature keeps it out of the summoned set (sign gate before pin gate).
	ah, _ := loader.FullHash("free-ical-pro")
	plane.Approve("free-ical-pro", ah)
	for _, ins := range loader.ActiveInstructions() {
		if strings.Contains(ins, "PWNED-SKILL") {
			t.Fatal("attacker-signed skill must never be summoned, even if pinned")
		}
	}
}

// TestSkillLoaderUnsafeLeaksAttack is the controls-off demo invariant: bypassing the
// gate lets a poisoned skill's instructions through verbatim (the attack the control
// exists to stop).
func TestSkillLoaderUnsafeLeaksAttack(t *testing.T) {
	loader, _, inv := liveSkills(t)
	defer inv.Close()

	r := loader.Load("free-ical-pro", true)
	if !r.Loaded || !r.Unsafe {
		t.Fatalf("controls-off load should return unchecked, got %+v", r)
	}
	if !strings.Contains(r.Instructions, "PWNED-SKILL") {
		t.Fatalf("controls-off should leak the poison marker, got %q", r.Instructions)
	}
}

// TestSkillCatalogTrustFlags: the catalog reports the author skill as trusted and the
// attacker skill as untrusted, and reflects approval state.
func TestSkillCatalogTrustFlags(t *testing.T) {
	loader, plane, inv := liveSkills(t)
	defer inv.Close()
	byName := map[string]bool{}
	for _, row := range loader.Catalog() {
		byName[row.Name] = row.SignerTrusted
	}
	if !byName["calendar-helper"] {
		t.Error("author-signed skill should be trusted")
	}
	if byName["free-ical-pro"] {
		t.Error("attacker-signed skill must be untrusted")
	}
	// Approve flips the approved flag in the catalog view.
	h, _ := loader.FullHash("calendar-helper")
	plane.Approve("calendar-helper", h)
	for _, row := range loader.Catalog() {
		if row.Name == "calendar-helper" && !row.Approved {
			t.Error("approved skill should show approved=true")
		}
	}
}

// TestAuthorSkillLifecycle is the operator-authoring feature end to end on real objects:
// author → trusted+unapproved+in-catalog, validation refuses bad input, fails closed until
// approved, then loads and is injected into the prompt. No mocks.
func TestAuthorSkillLifecycle(t *testing.T) {
	loader, plane, inv := liveSkills(t)
	defer inv.Close()
	loader.loadPersisted(skillStore{inv}) // attach the store (no authored skills yet)

	row, err := loader.Author("allergy-watch", "Flag anything about allergies at the top of the answer.", []string{"calendar.read"})
	if err != nil {
		t.Fatalf("author: %v", err)
	}
	if !row.SignerTrusted || row.Approved || !row.Authored {
		t.Fatalf("authored skill should be trusted, unapproved, authored: %+v", row)
	}
	if _, ok := loader.FullHash("allergy-watch"); !ok {
		t.Fatal("authored skill not in the catalog")
	}

	// Validation: a tool outside the allow-set, and a reserved fixture name, are refused.
	if _, err := loader.Author("bad-skill", "do stuff", []string{"email.send"}); err == nil {
		t.Error("a tool outside the allow-set must be refused")
	}
	if _, err := loader.Author("calendar-helper", "override the fixture", nil); err == nil {
		t.Error("a reserved fixture name must be refused")
	}

	// Fails closed until approved, then loads and is injected.
	if r := loader.Load("allergy-watch", false); r.Loaded {
		t.Fatalf("authored skill must be unapproved until pinned: %+v", r)
	}
	hash, _ := loader.FullHash("allergy-watch")
	plane.Approve("allergy-watch", hash)
	if r := loader.Load("allergy-watch", false); !r.Loaded || r.Instructions == "" {
		t.Fatalf("approved authored skill should load: %+v", r)
	}
	found := false
	for _, ins := range loader.ActiveInstructions() {
		if strings.Contains(ins, "allergies") {
			found = true
		}
	}
	if !found {
		t.Error("an approved authored skill should be injected into the prompt (shape Chat)")
	}

	// Delete removes it from the catalog and revokes the approval.
	if err := loader.Delete("allergy-watch"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := loader.FullHash("allergy-watch"); ok {
		t.Error("deleted skill must be gone from the catalog")
	}
	if err := loader.Delete("calendar-helper"); err == nil {
		t.Error("a shipped fixture must not be deletable")
	}
}

// TestAuthoredSkillPersistsAcrossRestart: an authored skill survives a "restart" (new loader
// over the same author key + DB) and re-signs deterministically to the SAME hash, so a prior
// approval still matches. Real key seed, real SQLite.
func TestAuthoredSkillPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "skill-author.key")
	inv, err := datastore.Open(filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()

	l1, names, _, _ := newSkillLoader(key)
	l1.attach(controlplane.GovernedSkills(names, inv, nil))
	l1.loadPersisted(skillStore{inv})
	if _, err := l1.Author("allergy-watch", "Flag allergies.", []string{"calendar.read"}); err != nil {
		t.Fatalf("author: %v", err)
	}
	h1, _ := l1.FullHash("allergy-watch")

	// "restart": a fresh loader over the same key + DB.
	l2, names2, _, _ := newSkillLoader(key)
	l2.attach(controlplane.GovernedSkills(names2, inv, nil))
	l2.loadPersisted(skillStore{inv})
	h2, ok := l2.FullHash("allergy-watch")
	if !ok {
		t.Fatal("authored skill did not persist across restart")
	}
	if h1 != h2 {
		t.Fatalf("re-signed hash differs across restart (%s vs %s) — approvals would break", h1, h2)
	}
}
