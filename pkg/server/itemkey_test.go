package server

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/schema"
)

// TestItemKeyIgnersKind locks the review fix: the status key matches the dedup identity
// (title | day) and does NOT depend on kind — the deduped projection holds one item per
// (title, day), and the surviving item's kind can flip across rebuilds, so a kind-keyed
// status would silently drop a prior done/dismiss.
func TestItemKeyIgnoresKind(t *testing.T) {
	task := schema.Event{Title: "Return permission slip", Due: "2026-10-20", Kind: schema.KindTask}
	action := schema.Event{Title: "Return permission slip", Due: "2026-10-20", Kind: schema.KindAction}
	if itemKey(task) != itemKey(action) {
		t.Errorf("status key must not depend on kind: %q vs %q", itemKey(task), itemKey(action))
	}
	// A different day is a different item.
	other := schema.Event{Title: "Return permission slip", Due: "2026-10-21", Kind: schema.KindTask}
	if itemKey(task) == itemKey(other) {
		t.Error("items on different days must have different keys")
	}
}
