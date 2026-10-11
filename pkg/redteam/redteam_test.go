package redteam_test

import (
	"testing"

	"github.com/t0ul/ADD"
	"github.com/t0ul/emaildrop/pkg/redteam"
)

// The ADD framework drives the invariant for every technique: the attack must
// breach the undefended baseline (ASR 100% — so the test proves something) and
// the control must block it (ASR 0%). add.Gate runs each as a subtest and logs
// the OWASP coverage grid.
func TestADDGate(t *testing.T) {
	outs := add.Gate(t, redteam.Techniques()...)
	if len(outs) == 0 {
		t.Fatal("no techniques ran")
	}
}

// Every technique must carry an OWASP tag so the coverage grid has no silent
// gaps (an untagged technique is an untracked risk).
func TestEveryTechniqueTagged(t *testing.T) {
	for _, tech := range redteam.Techniques() {
		if tech.Risk == "" {
			t.Errorf("technique %q has no OWASP risk tag", tech.Name)
		}
	}
}

func TestAllSeedsNonEmpty(t *testing.T) {
	if n := len(redteam.AllSeeds()); n < 5 {
		t.Fatalf("expected the full seed corpus, got %d", n)
	}
}
