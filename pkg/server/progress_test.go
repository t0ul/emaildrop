package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A bulk drop must be visible: files waiting in the inbox, the one in flight, and
// each finished file with its counts. Real inbox directory, real tracker.
func TestProgressReportsQueueCurrentAndRecent(t *testing.T) {
	inbox := t.TempDir()
	for _, n := range []string{"a.txt", "b.txt", "notes.md"} {
		if err := os.WriteFile(filepath.Join(inbox, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := NewProgress()
	srv := httptest.NewServer(New(Config{InboxPath: inbox, Progress: p}).Handler())
	defer srv.Close()

	get := func() map[string]any {
		resp, err := http.Get(srv.URL + "/api/progress")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m
	}

	m := get()
	if m["pending"] != 2.0 || m["active"] != true || m["current"] != nil {
		t.Fatalf("two .txt files waiting and nothing in flight, got %v", m)
	}
	p.Begin("a.txt")
	m = get()
	cur, _ := m["current"].(map[string]any)
	if cur == nil || cur["file"] != "a.txt" {
		t.Fatalf("a.txt must be reported in flight, got %v", m)
	}
	p.End("a.txt", "20261015-a.txt", 3, 1, "")
	p.Begin("b.txt")
	p.End("b.txt", "", 0, 0, "boom")
	m = get()
	if m["done"] != 1.0 || m["failed"] != 1.0 || m["current"] != nil {
		t.Fatalf("one done, one failed, none in flight, got %v", m)
	}
	recent, _ := m["recent"].([]any)
	if len(recent) != 2 {
		t.Fatalf("two recent results, got %v", m["recent"])
	}
	first, _ := recent[0].(map[string]any)
	if first["file"] != "b.txt" || first["error"] != "boom" {
		t.Fatalf("newest first with its error, got %v", first)
	}
	second, _ := recent[1].(map[string]any)
	if second["sidecar"] != "a.summary.json" || second["events"] != 3.0 {
		t.Fatalf("a finished file names its sidecar and counts, got %v", second)
	}
}
