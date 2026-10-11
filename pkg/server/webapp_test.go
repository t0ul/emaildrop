package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/ics"
	"github.com/t0ul/emaildrop/pkg/agent/pipeline"
	"github.com/t0ul/emaildrop/pkg/agent/schema"
	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/domain"
	"github.com/t0ul/emaildrop/pkg/netpolicy"
	"github.com/t0ul/emaildrop/pkg/provenance"
	"github.com/t0ul/emaildrop/pkg/server"
	"github.com/t0ul/gledger"
)

func TestEventsAPIReadsICS(t *testing.T) {
	dir := t.TempDir()
	icsText, _, _ := ics.Write([]schema.Event{schema.New("PTA Meeting", "2026-09-24T08:30:00")}, "cal")
	os.WriteFile(filepath.Join(dir, "3.events.ics"), []byte(icsText), 0o644)

	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir}).Handler())
	defer srv.Close()
	resp := mustGet(t, srv.URL+"/api/events")
	defer resp.Body.Close()
	var out struct {
		Events []server.Event `json:"events"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Events) != 1 || out.Events[0].Title != "PTA Meeting" || !out.Events[0].HasReminder {
		t.Fatalf("expected 1 PTA event with reminder, got %+v", out.Events)
	}
}

func TestEventsAPIReadsTaskAndAction(t *testing.T) {
	dir := t.TempDir()
	icsText, _, _ := ics.Write([]schema.Event{
		{Kind: schema.KindTask, Title: "Buy popcorn", Due: "2026-09-29", AllDay: true},
		{Kind: schema.KindAction, Title: "Accept invite", Due: "2026-09-20", AllDay: true, URL: "https://class.example/join"},
	}, "cal")
	os.WriteFile(filepath.Join(dir, "1.events.ics"), []byte(icsText), 0o644)

	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir}).Handler())
	defer srv.Close()
	resp := mustGet(t, srv.URL+"/api/events")
	defer resp.Body.Close()
	var out struct {
		Events []server.Event `json:"events"`
	}
	json.NewDecoder(resp.Body).Decode(&out)

	byKind := map[string]server.Event{}
	for _, e := range out.Events {
		byKind[e.Kind] = e
	}
	if task, ok := byKind["task"]; !ok || task.Title != "Buy popcorn" || task.Due != "2026-09-29" {
		t.Fatalf("task not parsed: %+v", byKind)
	}
	if act, ok := byKind["action"]; !ok || act.URL != "https://class.example/join" {
		t.Fatalf("action/URL not parsed: %+v", byKind)
	}
}

func writeSidecar(t *testing.T, dir string) {
	t.Helper()
	es := pipeline.EmailSummary{
		Source: "wk.txt", TraceID: "t",
		Tools: map[string]string{"digest": "Subject: PS123\n1 dated line", "contacts": "teacher@school.org"},
		Items: []schema.Event{
			{Kind: schema.KindTask, Title: "Buy popcorn", Due: "2026-10-02", AllDay: true, Confidence: 0.9},
			{Kind: schema.KindEvent, Title: "Back to School Night", Start: "2026-09-29T18:00:00", Confidence: 1},
		},
		NeedsReview: []schema.Event{
			{Kind: schema.KindEvent, Title: "Maybe meeting", Start: "2026-09-29", Confidence: 0.4, Warnings: []string{"low_conf"}},
		},
	}
	b, _ := json.Marshal(es)
	os.WriteFile(filepath.Join(dir, "wk.summary.json"), b, 0o644)
}

func TestItemsAPIFiltersByKind(t *testing.T) {
	dir := t.TempDir()
	writeSidecar(t, dir)
	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir}).Handler())
	defer srv.Close()

	resp := mustGet(t, srv.URL+"/api/items?kind=task")
	defer resp.Body.Close()
	var out struct {
		Items []server.Event `json:"items"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Items) != 1 || out.Items[0].Title != "Buy popcorn" {
		t.Fatalf("kind=task filter wrong: %+v", out.Items)
	}
}

func TestSummaryAndReviewAPI(t *testing.T) {
	dir := t.TempDir()
	writeSidecar(t, dir)
	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir}).Handler())
	defer srv.Close()

	resp := mustGet(t, srv.URL+"/api/summary?file=wk.summary.json")
	defer resp.Body.Close()
	var sum pipeline.EmailSummary
	json.NewDecoder(resp.Body).Decode(&sum)
	if sum.Tools["contacts"] != "teacher@school.org" {
		t.Fatalf("summary contacts missing: %+v", sum.Tools)
	}

	rv := mustGet(t, srv.URL+"/api/review")
	defer rv.Body.Close()
	var out struct {
		Items []server.Event `json:"items"`
	}
	json.NewDecoder(rv.Body).Decode(&out)
	if len(out.Items) != 1 || out.Items[0].Title != "Maybe meeting" {
		t.Fatalf("review queue wrong: %+v", out.Items)
	}
}

func TestSummaryAPIRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir}).Handler())
	defer srv.Close()
	resp := mustGet(t, srv.URL+"/api/summary?file=../../etc/passwd")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("traversal not rejected: %d", resp.StatusCode)
	}
}

// hitlConfirm runs the two-phase approval: phase 1 gets the nonce, phase 2
// confirms. Returns the phase-2 response.
func hitlConfirm(t *testing.T, url, file string, index int) *http.Response {
	t.Helper()
	r1, err := http.Post(url, "application/json", strings.NewReader(fmt.Sprintf(`{"file":%q,"index":%d}`, file, index)))
	if err != nil {
		t.Fatal(err)
	}
	var ch struct {
		ConfirmRequired bool   `json:"confirm_required"`
		Nonce           string `json:"nonce"`
	}
	json.NewDecoder(r1.Body).Decode(&ch)
	r1.Body.Close()
	if !ch.ConfirmRequired || ch.Nonce == "" {
		t.Fatalf("phase 1 should issue a confirm challenge, got %+v", ch)
	}
	r2, err := http.Post(url, "application/json", strings.NewReader(
		fmt.Sprintf(`{"file":%q,"index":%d,"nonce":%q,"confirm":true}`, file, index, ch.Nonce)))
	if err != nil {
		t.Fatal(err)
	}
	return r2
}

func TestAcceptRequiresHITLConfirm(t *testing.T) {
	dir := t.TempDir()
	writeSidecar(t, dir)
	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir}).Handler())
	defer srv.Close()

	// Phase 1 alone must NOT write anything.
	r1 := mustPost(t, srv.URL+"/api/accept", "application/json", strings.NewReader(`{"file":"wk.summary.json","index":0}`))
	r1.Body.Close()
	if entries, _ := os.ReadDir(dir); hasAccept(entries) {
		t.Fatal("the challenge phase must not write an .ics")
	}
	// Confirm writes it.
	resp := hitlConfirm(t, srv.URL+"/api/accept", "wk.summary.json", 0)
	resp.Body.Close()
	if entries, _ := os.ReadDir(dir); !hasAccept(entries) {
		t.Fatal("confirmed accept did not write an .ics")
	}
}

func TestAcceptForgedNonceRefused(t *testing.T) {
	dir := t.TempDir()
	writeSidecar(t, dir)
	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir}).Handler())
	defer srv.Close()

	// A confirm with a nonce that was never issued (forged/replayed) is refused.
	resp := mustPost(t, srv.URL+"/api/accept", "application/json",
		strings.NewReader(`{"file":"wk.summary.json","index":0,"nonce":"deadbeef","confirm":true}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged nonce should be 403, got %d", resp.StatusCode)
	}
	if entries, _ := os.ReadDir(dir); hasAccept(entries) {
		t.Fatal("a forged approval must not write an .ics")
	}
}

func hasAccept(entries []os.DirEntry) bool {
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "wk.accept-") && strings.HasSuffix(e.Name(), ".ics") {
			return true
		}
	}
	return false
}

func writeActionSidecar(t *testing.T, dir, url string) {
	t.Helper()
	es := pipeline.EmailSummary{
		Source: "wk.txt", TraceID: "t", Tools: map[string]string{},
		Items: []schema.Event{{Kind: schema.KindAction, Title: "Accept invite", URL: url, AllDay: true, Due: "2026-09-20", Confidence: 0.9}},
	}
	b, _ := json.Marshal(es)
	os.WriteFile(filepath.Join(dir, "wk.summary.json"), b, 0o644)
}

func TestActionFetchesAllowlistedURL(t *testing.T) {
	dir := t.TempDir()
	writeActionSidecar(t, dir, "https://class.example/join")
	fetched := ""
	srv := httptest.NewServer(server.New(server.Config{
		OutboxDir: dir,
		Egress:    netpolicy.Policy{Allow: []string{"class.example"}, Resolve: func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }},
		Fetch:     func(_ context.Context, url string) (string, error) { fetched = url; return "HTTP 200\nhello", nil },
	}).Handler())
	defer srv.Close()

	resp := hitlConfirm(t, srv.URL+"/api/action", "wk.summary.json", 0)
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if out["ok"] != true || fetched != "https://class.example/join" {
		t.Fatalf("allow-listed action should fetch the item's URL: %+v (fetched=%q)", out, fetched)
	}
}

func TestActionRefusesNonAllowlisted(t *testing.T) {
	dir := t.TempDir()
	writeActionSidecar(t, dir, "http://169.254.169.254/latest/meta-data/")
	called := false
	srv := httptest.NewServer(server.New(server.Config{
		OutboxDir: dir,
		Egress:    netpolicy.Policy{}, // deny all
		Fetch:     func(_ context.Context, _ string) (string, error) { called = true; return "", nil },
	}).Handler())
	defer srv.Close()

	resp := hitlConfirm(t, srv.URL+"/api/action", "wk.summary.json", 0)
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if out["ok"] == true || called {
		t.Fatalf("non-allow-listed action must be refused before fetch: %+v (called=%v)", out, called)
	}
}

func TestICSServesOnlyICS(t *testing.T) {
	dir := t.TempDir()
	writeSidecar(t, dir) // writes wk.summary.json (PII)
	os.WriteFile(filepath.Join(dir, "wk.events.ics"), []byte("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"), 0o644)
	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir}).Handler())
	defer srv.Close()

	r1 := mustGet(t, srv.URL+"/ics/wk.summary.json")
	r1.Body.Close()
	if r1.StatusCode != http.StatusNotFound {
		t.Fatalf("the PII sidecar must NOT be served, got %d", r1.StatusCode)
	}
	r2 := mustGet(t, srv.URL+"/ics/wk.events.ics")
	r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf(".ics should be served, got %d", r2.StatusCode)
	}
}

func TestCrossOriginPostRefused(t *testing.T) {
	srv := httptest.NewServer(server.New(server.Config{InboxPath: t.TempDir()}).Handler())
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/api/drop", strings.NewReader("text=hi"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST must be refused (403), got %d", resp.StatusCode)
	}
}

func TestEventsReportProvenance(t *testing.T) {
	dir := t.TempDir()
	signer, pub, _ := provenance.NewSigner("email-agent")
	icsText, _, _ := ics.Write([]schema.Event{schema.New("PTA Meeting", "2026-09-24T08:30:00")}, "cal")
	os.WriteFile(filepath.Join(dir, "3.events.ics"), []byte(icsText), 0o644)
	mb, _ := json.Marshal(signer.Sign([]byte(icsText)))
	os.WriteFile(filepath.Join(dir, "3.events.ics.sig"), mb, 0o644)

	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir, Verifier: provenance.NewVerifier().Trust("email-agent", pub)}).Handler())
	defer srv.Close()
	get := func() server.Event {
		resp := mustGet(t, srv.URL+"/api/events")
		defer resp.Body.Close()
		var out struct {
			Events []server.Event `json:"events"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		if len(out.Events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(out.Events))
		}
		return out.Events[0]
	}
	if !get().Signed {
		t.Fatal("a correctly signed .ics must report signed=true")
	}
	// Tamper the .ics — the content credential must no longer verify.
	os.WriteFile(filepath.Join(dir, "3.events.ics"), []byte(icsText+"\r\nX:TAMPER\r\n"), 0o644)
	if get().Signed {
		t.Fatal("a tampered .ics must report signed=false")
	}
}

func TestKillSwitchGatesSideEffects(t *testing.T) {
	dir := t.TempDir()
	writeSidecar(t, dir)
	safety := controlplane.NewSafety(nil)
	srv := httptest.NewServer(server.New(server.Config{OutboxDir: dir, InboxPath: t.TempDir(), Safety: safety}).Handler())
	defer srv.Close()
	setLevel := func(l int) {
		r := mustPost(t, srv.URL+"/api/killswitch", "application/json", strings.NewReader(fmt.Sprintf(`{"level":%d}`, l)))
		r.Body.Close()
	}
	drop := func() int {
		r := mustPost(t, srv.URL+"/api/drop", "application/x-www-form-urlencoded", strings.NewReader("text=hi"))
		r.Body.Close()
		return r.StatusCode
	}

	setLevel(2) // Pause: refuse new processing
	if drop() != http.StatusServiceUnavailable {
		t.Fatal("paused drop should be 503")
	}
	setLevel(1) // BlockTools: drops allowed again, but side effects blocked
	if drop() == http.StatusServiceUnavailable {
		t.Fatal("block-tools should still allow drops")
	}
	r := mustPost(t, srv.URL+"/api/accept", "application/json", strings.NewReader(`{"file":"wk.summary.json","index":0}`))
	r.Body.Close()
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("block-tools accept should be 503, got %d", r.StatusCode)
	}
	setLevel(0) // Resume
	if drop() == http.StatusServiceUnavailable {
		t.Fatal("resumed drop should be allowed")
	}
}

func TestAskSearchesCorpus(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(server.New(server.Config{
		Search: func(q string, k int) ([]domain.SearchHit, error) {
			gotQuery = q
			return []domain.SearchHit{{Source: "handbook.txt", Snippet: "the nurse is in Room 219", Untrusted: true}}, nil
		},
	}).Handler())
	defer srv.Close()

	resp := mustGet(t, srv.URL+"/api/ask?q=nurse")
	defer resp.Body.Close()
	var out struct {
		Hits []domain.SearchHit `json:"hits"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if gotQuery != "nurse" || len(out.Hits) != 1 || !strings.Contains(out.Hits[0].Snippet, "Room 219") {
		t.Fatalf("ask did not search the corpus: q=%q hits=%+v", gotQuery, out.Hits)
	}
}

func TestScorecardAPIAllPass(t *testing.T) {
	srv := httptest.NewServer(server.New(server.Config{}).Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/scorecard")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Results []map[string]any `json:"results"`
		AllPass bool             `json:"all_pass"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Results) == 0 || !out.AllPass {
		t.Fatalf("scorecard should run and pass: results=%d all_pass=%v", len(out.Results), out.AllPass)
	}
}

func TestDropWritesToInbox(t *testing.T) {
	inbox := t.TempDir()
	srv := httptest.NewServer(server.New(server.Config{InboxPath: inbox}).Handler())
	defer srv.Close()
	resp, err := http.PostForm(srv.URL+"/api/drop", map[string][]string{"text": {"Back to School Night Sept 29th 6PM"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("drop returned %d", resp.StatusCode)
	}
	entries, _ := os.ReadDir(inbox)
	if len(entries) != 1 {
		t.Fatalf("expected one dropped file in inbox, got %d", len(entries))
	}
}

func TestIncidentsAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := gledger.Open(path, "test")
	if err != nil {
		t.Fatal(err)
	}
	trace := gledger.NewTraceID()
	a.Emit(trace, "request", "start", nil)
	a.Emit(trace, "policy", "gate", gledger.F{"decision": "block"})

	srv := httptest.NewServer(server.New(server.Config{AuditPath: path}).Handler())
	defer srv.Close()
	resp := mustGet(t, srv.URL+"/api/incidents")
	defer resp.Body.Close()
	var out struct {
		Traces []struct {
			ID string `json:"id"`
			N  int    `json:"n"`
		} `json:"traces"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Traces) != 1 || out.Traces[0].N != 2 {
		t.Fatalf("expected one 2-event incident, got %+v", out.Traces)
	}
}

// mustGet / mustPost do the request and fail the test on a transport error, so
// callers can defer-close the body without a vet "used before error check".
func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func mustPost(t *testing.T, url, contentType string, body io.Reader) *http.Response {
	t.Helper()
	resp, err := http.Post(url, contentType, body)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}
