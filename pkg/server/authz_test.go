package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/provenance"
)

func bearer(t *testing.T, g controlplane.Grant) string {
	t.Helper()
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + base64.URLEncoding.EncodeToString(b)
}

// TestEndpointAuthzLeastPrivilege locks the Pass-2 security fix that the suite had
// missed: operator reads AND the kill switch require the operator grant; the narrow App
// grant (list/corpus + consumer writes, nothing operator/safety) and an anonymous caller
// are refused; consumer reads still work for the App grant; and the kill switch is
// break-glass — an operator can DISENGAGE a halt even though Halt revoked every grant.
// Real Authority + real signed grants + a real httptest Server — no mocks.
func TestEndpointAuthzLeastPrivilege(t *testing.T) {
	signer, pub, err := provenance.NewSigner("op")
	if err != nil {
		t.Fatal(err)
	}
	authz := controlplane.NewAuthority(signer, provenance.NewVerifier().Trust("op", pub))
	opGrant, err := authz.Issue(controlplane.Capability{Subject: controlplane.Scope, Action: controlplane.Scope, Resource: controlplane.Scope, Tenant: "public"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	appGrant, err := authz.IssueScoped(
		controlplane.Capability{Subject: "app", Action: controlplane.ActionList, Resource: "corpus", Tenant: "public"},
		[]controlplane.GrantScope{{Action: controlplane.ActionWrite, Resource: "calendar"}, {Action: controlplane.ActionWrite, Resource: "profile"}},
		time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	opTok, appTok := bearer(t, opGrant), bearer(t, appGrant)

	safety := controlplane.NewSafety(nil)
	srv := httptest.NewServer(New(Config{
		Authz:     authz,
		Safety:    safety,
		Prompts:   controlplane.NewPrompts(map[string]string{"chat_system": "x"}), // registers /api/prompts (operator read)
		OutboxDir: t.TempDir(),                                                     // registers /api/events (consumer read)
	}).Handler())
	defer srv.Close()

	do := func(method, path, tok, body string) int {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if tok != "" {
			req.Header.Set("Authorization", tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Operator read: operator OK, App forbidden, anonymous unauthorized.
	if c := do("GET", "/api/prompts", opTok, ""); c != http.StatusOK {
		t.Errorf("operator /api/prompts: got %d, want 200", c)
	}
	if c := do("GET", "/api/prompts", appTok, ""); c != http.StatusForbidden {
		t.Errorf("App token must NOT read operator state: /api/prompts got %d, want 403", c)
	}
	if c := do("GET", "/api/prompts", "", ""); c != http.StatusUnauthorized {
		t.Errorf("anonymous /api/prompts: got %d, want 401", c)
	}

	// Consumer read: the App grant can read the household calendar.
	if c := do("GET", "/api/events", appTok, ""); c != http.StatusOK {
		t.Errorf("App token should read /api/events: got %d, want 200", c)
	}

	// Kill switch: operator can engage; App token cannot.
	if c := do("POST", "/api/killswitch", opTok, `{"level":3}`); c != http.StatusOK {
		t.Errorf("operator killswitch engage: got %d, want 200", c)
	}
	if c := do("POST", "/api/killswitch", appTok, `{"level":3}`); c != http.StatusForbidden {
		t.Errorf("App token must NOT toggle the kill switch: got %d, want 403", c)
	}

	// Break-glass: with Halt engaged (which revokes every grant), the operator can STILL
	// disengage via the kill switch — a normal gate would deadlock here.
	authz.Halted = func() bool { return safety.Level() >= controlplane.LevelHalt }
	if _, err := authz.Verify(opGrant, controlplane.Capability{Action: controlplane.ActionWrite, Resource: "safety", Tenant: "public"}); err == nil {
		t.Fatal("precondition: normal Verify should refuse during Halt (revoked)")
	}
	if c := do("POST", "/api/killswitch", opTok, `{"level":0}`); c != http.StatusOK {
		t.Errorf("operator disengage during Halt (break-glass): got %d, want 200", c)
	}
}
