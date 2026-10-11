package main

import (
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/memory"
)

// TestMemoryCommands locks A3: the chat's durable memory is actually wired — a
// "remember:" command stores a trusted fact, recall returns it, a restatement updates in
// place, and "forget" erases the scope (DSAR). Real memory.Store, no model.
func TestMemoryCommands(t *testing.T) {
	c := &chatService{memory: memory.New()}

	// remember: stores and confirms.
	r, ok := c.memoryCommand("remember: pickup is 3pm on Fridays")
	if !ok || !strings.Contains(r.Answer, "pickup is 3pm") {
		t.Fatalf("remember should store + confirm, got ok=%v %q", ok, r.Answer)
	}
	if got := c.memory.Recall(memoryScope); len(got) != 1 || !strings.Contains(got[0].Value, "pickup is 3pm") {
		t.Fatalf("fact not recalled, got %v", got)
	}

	// "remember that X" form also works and keys the same so a restatement updates.
	if _, ok := c.memoryCommand("remember that pickup is 3pm on Fridays"); !ok {
		t.Fatal("remember-that form should be handled")
	}
	if got := c.memory.Recall(memoryScope); len(got) != 1 {
		t.Fatalf("restating the same fact must update in place, got %d entries", len(got))
	}

	// A normal question is NOT a memory command.
	if _, ok := c.memoryCommand("what time is pickup?"); ok {
		t.Error("a question must not be treated as a memory command")
	}

	// forget erases the scope (right-to-erasure).
	r, ok = c.memoryCommand("forget")
	if !ok || !strings.Contains(r.Answer, "Erased 1") {
		t.Fatalf("forget should erase + report, got ok=%v %q", ok, r.Answer)
	}
	if got := c.memory.Recall(memoryScope); len(got) != 0 {
		t.Fatalf("scope must be empty after forget, got %v", got)
	}

	// No memory store configured → not handled (chat falls through to the model).
	if _, ok := (&chatService{}).memoryCommand("remember: x"); ok {
		t.Error("nil memory store must not handle commands")
	}
}

// TestMemKeyNoPrefixCollision locks the review fix: two distinct facts that share a long
// opening must get DISTINCT keys (a prefix-truncated key merged them), while the same
// fact always keys the same so a restatement overwrites.
func TestMemKeyNoPrefixCollision(t *testing.T) {
	a := "pickup is at 3pm on fridays from the main entrance by the gym on tuesday"
	b := "pickup is at 3pm on fridays from the main entrance by the gym on thursday"
	if memKey(a) == memKey(b) {
		t.Error("facts differing only past 48 chars must not collide")
	}
	if memKey(a) != memKey("Pickup is at 3pm on Fridays from the main entrance by the gym on Tuesday") {
		t.Error("the same fact (case/space-normalized) must key identically so it overwrites")
	}
}
