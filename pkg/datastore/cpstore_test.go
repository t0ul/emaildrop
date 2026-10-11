package datastore_test

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/datastore"
)

func open(t *testing.T) *datastore.Store {
	t.Helper()
	s, err := datastore.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestLatestEvalFeedsGate(t *testing.T) {
	s := open(t)
	if _, ok, _ := s.LatestEval("1.txt"); ok {
		t.Fatal("expected no score yet")
	}
	if err := s.RecordEval("1.txt", 0.47); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordEval("1.txt", 1.00); err != nil {
		t.Fatal(err)
	}
	e, ok, err := s.LatestEval("1.txt")
	if err != nil || !ok || e.F1 != 1.00 {
		t.Fatalf("latest score = %+v ok=%v err=%v, want F1 1.00", e, ok, err)
	}
}

func TestApprovalsPersistAndList(t *testing.T) {
	s := open(t)
	if err := s.RecordApproval("p1", "alice", "bob", "config.write", "upgrade planner", 1); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListApprovals(10)
	if err != nil || len(got) != 1 {
		t.Fatalf("approvals = %v err=%v", got, err)
	}
	if got[0].Proposer != "alice" || got[0].Approver != "bob" || got[0].Version != 1 {
		t.Fatalf("unexpected approval row: %+v", got[0])
	}
}

func TestPromptsPersistAndList(t *testing.T) {
	s, _ := datastore.Open(":memory:")
	defer s.Close()
	if err := s.RecordPrompt("planner", "v1", "abc123", "hello"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListPrompts(10)
	if err != nil || len(rows) != 1 || rows[0].Name != "planner" || rows[0].Hash != "abc123" {
		t.Fatalf("prompt not persisted/listed: %+v (%v)", rows, err)
	}
}

func TestPinsPersistAndList(t *testing.T) {
	s, _ := datastore.Open(":memory:")
	defer s.Close()
	if err := s.RecordPin("search", "deadbeef", "operator"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListPins(10)
	if err != nil || len(rows) != 1 || rows[0].Server != "search" || rows[0].ApprovedBy != "operator" {
		t.Fatalf("pin not persisted/listed: %+v (%v)", rows, err)
	}
}

func TestRecordersDoNotError(t *testing.T) {
	s := open(t)
	if err := s.RecordPrompt("planner", "v2", "deadbeef", "You are..."); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordPin("search", "abc123", "carol"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAdmin("carol", "killswitch", "level=block_tools"); err != nil {
		t.Fatal(err)
	}
}

// TestChatTurnUnsafeFlag locks D2: a controls-off (unsafe) turn is persisted with its
// flag and reads back set, so the history distinguishes the demo answers. A defended
// turn reads back unflagged.
func TestChatTurnUnsafeFlag(t *testing.T) {
	s := open(t)
	if _, err := s.AppendChatTurn(datastore.ChatTurn{Role: "assistant", Content: "defended", Unsafe: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendChatTurn(datastore.ChatTurn{Role: "assistant", Content: "controls off", Unsafe: true}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.LoadChatTurns(10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("load: %v rows=%d", err, len(rows))
	}
	byContent := map[string]bool{}
	for _, r := range rows {
		byContent[r.Content] = r.Unsafe
	}
	if byContent["defended"] {
		t.Error("a defended turn must not be flagged unsafe")
	}
	if !byContent["controls off"] {
		t.Error("a controls-off turn must persist its unsafe flag")
	}
}
