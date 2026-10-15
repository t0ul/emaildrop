package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

// The "Needs your OK" queue must shrink as the human works it: an accepted row is
// recorded as done and a "Not real" row as dismissed, keyed like the Tasks overlay,
// so neither comes back on reload. ?all=1 still lists everything with its status.
// Real Server, real sidecar, real SQLite overlay, the real two-phase HITL accept.
func TestReviewQueueForgetsHandledRows(t *testing.T) {
	outbox := t.TempDir()
	sidecar := `{"source":"nl.txt","tools":{},
	 "items":[{"title":"Back to School Night","start":"2026-09-29","all_day":true,"kind":"event","confidence":0.6},
	          {"title":"Chancellor's Conference Day","start":"2026-10-27","all_day":true,"kind":"event","confidence":0.6}],
	 "needs_review":[{"title":"Back to School Night","start":"2026-09-29","all_day":true,"kind":"event","confidence":0.6},
	                 {"title":"Chancellor's Conference Day","start":"2026-10-27","all_day":true,"kind":"event","confidence":0.6}]}`
	if err := os.WriteFile(filepath.Join(outbox, "nl.summary.json"), []byte(sidecar), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := datastore.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	srv := httptest.NewServer(New(Config{OutboxDir: outbox, ItemStatus: memStatus{inv}}).Handler())
	defer srv.Close()

	post := func(path, body string) (int, map[string]any) {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	review := func(query string) []map[string]any {
		resp, err := http.Get(srv.URL + "/api/review" + query)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var d struct {
			Items []map[string]any `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&d)
		return d.Items
	}

	if n := len(review("")); n != 2 {
		t.Fatalf("both flagged items must start in the queue, got %d", n)
	}

	// Accept the first through the real two-phase gate, with an edit so the key of the
	// written event differs from the row's: the ROW must still leave the queue.
	edit := `"edit":{"title":"Back to School Night (edited)","start":"2026-09-29T18:30:00","all_day":false}`
	_, ch := post("/api/accept", `{"file":"nl.summary.json","index":0,`+edit+`}`)
	nonce, _ := ch["nonce"].(string)
	if nonce == "" {
		t.Fatalf("expected a HITL nonce, got %v", ch)
	}
	if code, res := post("/api/accept", `{"file":"nl.summary.json","index":0,`+edit+`,"nonce":"`+nonce+`","confirm":true}`); code != 200 || res["ok"] != true {
		t.Fatalf("confirmed accept must succeed, got %d %v", code, res)
	}
	left := review("")
	if len(left) != 1 || left[0]["title"] != "Chancellor's Conference Day" {
		t.Fatalf("an accepted row must leave the queue, got %v", left)
	}

	// "Not real" on the second: it leaves too.
	if code, res := post("/api/reject", `{"file":"nl.summary.json","index":1}`); code != 200 || res["ok"] != true {
		t.Fatalf("reject must succeed, got %d %v", code, res)
	}
	if n := len(review("")); n != 0 {
		t.Fatalf("a rejected row must leave the queue, got %d", n)
	}

	// Everything is still there under ?all=1, carrying the status it was handled with.
	all := review("?all=1")
	if len(all) != 2 {
		t.Fatalf("?all=1 must list every flagged item, got %d", len(all))
	}
	got := map[string]string{}
	for _, it := range all {
		got[it["title"].(string)], _ = it["status"].(string)
	}
	if got["Back to School Night"] != "done" || got["Chancellor's Conference Day"] != "dismissed" {
		t.Fatalf("statuses must be done/dismissed, got %v", got)
	}

	// The Tasks overlay sees the same keys: the accepted event is hidden there too.
	resp, err := http.Get(srv.URL + "/api/items")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var items struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&items)
	if len(items.Items) != 0 {
		t.Fatalf("handled rows must be hidden from the default items list too, got %d", len(items.Items))
	}
}
