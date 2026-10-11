package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

// TestEventCreateAndDelete locks the household calendar CRUD: an operator can add an event
// from scratch (written to its own .ics and shown on the calendar) and delete any event
// (hidden by fingerprint without mutating the source .ics). Real Server + real overlay.
func TestEventCreateAndDelete(t *testing.T) {
	outbox := t.TempDir()
	inv, err := datastore.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	srv := httptest.NewServer(New(Config{OutboxDir: outbox, HiddenEvents: inv}).Handler())
	defer srv.Close()

	post := func(path, body string) map[string]any {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m
	}
	listEvents := func() []map[string]any {
		resp, err := http.Get(srv.URL + "/api/events")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var d struct {
			Events []map[string]any `json:"events"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&d)
		return d.Events
	}

	if len(listEvents()) != 0 {
		t.Fatal("precondition: calendar empty")
	}
	// Create.
	if r := post("/api/events/create", `{"title":"Dentist appointment","start":"2026-11-02T09:00:00","location":"Main St"}`); r["ok"] != true {
		t.Fatalf("create failed: %v", r)
	}
	evs := listEvents()
	if len(evs) != 1 || evs[0]["title"] != "Dentist appointment" {
		t.Fatalf("created event must appear on the calendar, got %v", evs)
	}
	key, _ := evs[0]["key"].(string)
	if key == "" {
		t.Fatal("event must carry a delete key")
	}
	// Delete.
	if r := post("/api/events/delete", `{"key":"`+key+`"}`); r["ok"] != true {
		t.Fatalf("delete failed: %v", r)
	}
	if n := len(listEvents()); n != 0 {
		t.Fatalf("deleted event must be hidden from the calendar, got %d", n)
	}
	// The source .ics is untouched (delete is an overlay, not a file mutation).
	matches, _ := filepath.Glob(filepath.Join(outbox, "manual-*.events.ics"))
	if len(matches) != 1 {
		t.Errorf("the source .ics must remain on disk after delete, got %d", len(matches))
	}
}
