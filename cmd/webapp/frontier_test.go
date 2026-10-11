package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/provenance"
)

// TestFrontierStoreSecretByPointer locks C1: a frontier binding persists the KeyRef
// (env-var NAME) and resolves KeySet from the environment — it never stores the token
// value — and the live frontier set updates so the residency policy sees the binding.
func TestFrontierStoreSecretByPointer(t *testing.T) {
	inv, err := datastore.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	set := newFrontierSet()
	fs := frontierStore{inv: inv, set: set}

	t.Setenv("MY_FRONTIER_KEY", "sk-secret-value")
	if err := fs.UpsertFrontier("summarizer", "https://api.frontier.test/v1", "MY_FRONTIER_KEY"); err != nil {
		t.Fatal(err)
	}
	rows, err := fs.ListFrontier()
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %v rows=%d", err, len(rows))
	}
	if r := rows[0]; r.Subject != "summarizer" || r.KeyRef != "MY_FRONTIER_KEY" || !r.KeySet {
		t.Errorf("unexpected row %+v", r)
	}
	// The token VALUE must never be stored (secret-by-pointer: only the KeyRef name).
	if raw, _, _ := inv.GetConfig(frontierConfigKey); strings.Contains(raw, "sk-secret-value") {
		t.Error("the token value must never be persisted")
	}
	// The live set reflects the binding (what residency consults).
	if !set.has("summarizer") {
		t.Error("the live frontier set must include a bound subject")
	}

	// Unset env var → KeySet false.
	if err := fs.UpsertFrontier("planner-x", "https://x.test", "NOT_SET_ANYWHERE"); err != nil {
		t.Fatal(err)
	}
	rows, _ = fs.ListFrontier()
	for _, r := range rows {
		if r.Subject == "planner-x" && r.KeySet {
			t.Error("an unset KeyRef must report key_set=false")
		}
	}

	// Delete removes it from the live set.
	if err := fs.DeleteFrontier("summarizer"); err != nil {
		t.Fatal(err)
	}
	if set.has("summarizer") {
		t.Error("deleting a binding must clear it from the live set")
	}
}

// TestFrontierResidencyEnforced locks the enforcement half of C1: a subject bound to a
// frontier endpoint is refused a confidential list/export grant, while an on-host subject
// and a non-confidential resource are allowed. Real Authority + the live frontier set.
func TestFrontierResidencyEnforced(t *testing.T) {
	signer, pub, err := provenance.NewSigner("op")
	if err != nil {
		t.Fatal(err)
	}
	authz := controlplane.NewAuthority(signer, provenance.NewVerifier().Trust("op", pub))
	set := newFrontierSet()
	confidential := map[string]bool{"contacts": true, "email-bodies": true}
	authz.IssuePolicy = func(c controlplane.Capability) error {
		if set.has(c.Subject) && confidential[c.Resource] && (c.Action == controlplane.ActionList || c.Action == controlplane.ActionExport) {
			return errors.New("residency")
		}
		return nil
	}
	set.replace(map[string]bool{"summarizer": true})

	if _, err := authz.Issue(controlplane.Capability{Subject: "summarizer", Action: controlplane.ActionList, Resource: "contacts", Tenant: "public"}, time.Hour); err == nil {
		t.Error("a frontier-bound subject must be refused confidential list")
	}
	if _, err := authz.Issue(controlplane.Capability{Subject: "summarizer", Action: controlplane.ActionList, Resource: "corpus", Tenant: "public"}, time.Hour); err != nil {
		t.Errorf("non-confidential resource must be allowed: %v", err)
	}
	if _, err := authz.Issue(controlplane.Capability{Subject: "local-agent", Action: controlplane.ActionList, Resource: "contacts", Tenant: "public"}, time.Hour); err != nil {
		t.Errorf("on-host subject must be allowed: %v", err)
	}
}
