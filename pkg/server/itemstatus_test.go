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

// memStatus is the real datastore overlay used as the ItemStatusStore. It converts the
// datastore type to the server boundary type exactly as cmd/webapp does — no mock.
type memStatus struct{ inv *datastore.Store }

func (m memStatus) SetItemStatus(k, s, su string) error { return m.inv.SetItemStatus(k, s, su) }
func (m memStatus) LoadItemStatuses() (map[string]ItemStatus, error) {
	raw, err := m.inv.LoadItemStatuses()
	if err != nil {
		return nil, err
	}
	out := map[string]ItemStatus{}
	for k, v := range raw {
		out[k] = ItemStatus{Status: v.Status, SnoozeUntil: v.SnoozeUntil}
	}
	return out, nil
}

// TestItemStatusLifecycle locks C2: a task can be marked done (and is then hidden from
// the default list, shown under ?all=1), and un-done back to active. Real Server reading
// a real .summary.json sidecar + a real SQLite status overlay.
func TestItemStatusLifecycle(t *testing.T) {
	outbox := t.TempDir()
	sidecar := `{"source":"nl.txt","tools":{},"items":[{"title":"Return permission slip","due":"2026-10-20","kind":"task","confidence":0.9}]}`
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

	itemsCount := func(query string) (int, string) {
		resp, err := http.Get(srv.URL + "/api/items" + query)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var d struct {
			Items []struct {
				Key    string `json:"key"`
				Status string `json:"status"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&d)
		if len(d.Items) == 0 {
			return 0, ""
		}
		return len(d.Items), d.Items[0].Key
	}

	n, key := itemsCount("")
	if n != 1 || key == "" {
		t.Fatalf("expected 1 item with a stable key, got n=%d key=%q", n, key)
	}

	setStatus := func(k, status string) {
		body, _ := json.Marshal(map[string]string{"key": k, "status": status})
		resp, err := http.Post(srv.URL+"/api/items/status", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %s: got %d", status, resp.StatusCode)
		}
	}

	// Mark done → hidden from the default list, still visible (with status) under ?all=1.
	setStatus(key, "done")
	if n, _ := itemsCount(""); n != 0 {
		t.Errorf("a done item must be hidden from the default list, got %d", n)
	}
	if n, _ := itemsCount("?all=1"); n != 1 {
		t.Errorf("?all=1 must still show the done item, got %d", n)
	}

	// Un-done → back in the default list (active clears the override).
	setStatus(key, "active")
	if n, _ := itemsCount(""); n != 1 {
		t.Errorf("un-done item must return to the default list, got %d", n)
	}

	// Durable across a status reload (the overlay is in SQLite, keyed by content).
	setStatus(key, "dismissed")
	if got, _ := inv.LoadItemStatuses(); got[key].Status != "dismissed" {
		t.Errorf("status overlay must persist to the DB, got %+v", got[key])
	}
}
