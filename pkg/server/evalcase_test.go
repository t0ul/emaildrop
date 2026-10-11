package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

// evalCaseAdapter wires *datastore.Store to the server interface (as cmd/webapp does).
type evalCaseAdapter struct{ inv *datastore.Store }

func (e evalCaseAdapter) AddEvalCase(s, l, n string) (int64, error) { return e.inv.AddEvalCase(s, l, n) }
func (e evalCaseAdapter) DeleteEvalCase(id int64) error             { return e.inv.DeleteEvalCase(id) }
func (e evalCaseAdapter) ListEvalCases(limit int) ([]EvalCase, error) {
	rows, err := e.inv.ListEvalCases(limit)
	if err != nil {
		return nil, err
	}
	out := make([]EvalCase, 0, len(rows))
	for _, c := range rows {
		out = append(out, EvalCase{ID: c.ID, Source: c.Source, Label: c.Label, Note: c.Note, At: c.At})
	}
	return out, nil
}

// TestEvalCasePromoteLifecycle locks the feedback→eval loop: a thumbs-down is promoted
// into a durable regression case (with expected behavior), listed, then resolved. Real
// SQLite, real Server.
func TestEvalCasePromoteLifecycle(t *testing.T) {
	inv, err := datastore.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	srv := httptest.NewServer(New(Config{EvalCases: evalCaseAdapter{inv}}).Handler())
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
	list := func() []map[string]any {
		resp, err := http.Get(srv.URL + "/api/eval/cases")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var d struct {
			Cases []map[string]any `json:"cases"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&d)
		return d.Cases
	}

	r := post("/api/eval/cases/promote", `{"source":"chat","label":"wrong nurse name","note":"should say Luiza Davidova, Room 219"}`)
	if r["ok"] != true {
		t.Fatalf("promote failed: %v", r)
	}
	cs := list()
	if len(cs) != 1 || cs[0]["label"] != "wrong nurse name" || cs[0]["note"] == "" {
		t.Fatalf("promoted case not listed with its note: %v", cs)
	}
	id, _ := cs[0]["id"].(float64)
	if int64(id) == 0 {
		t.Fatal("case must have an id")
	}

	// A label is required.
	if r := post("/api/eval/cases/promote", `{"source":"chat","label":""}`); r["ok"] == true {
		t.Error("promote without a label must be refused")
	}

	// Resolve (delete).
	if r := post("/api/eval/cases/delete", `{"id":`+strconv.FormatInt(int64(id), 10)+`}`); r["ok"] != true {
		t.Fatalf("delete failed: %v", r)
	}
	if n := len(list()); n != 0 {
		t.Fatalf("resolved case must be gone, got %d", n)
	}
}
