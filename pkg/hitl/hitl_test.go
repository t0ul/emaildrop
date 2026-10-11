package hitl_test

import (
	"errors"
	"testing"

	"github.com/t0ul/emaildrop/pkg/hitl"
)

func TestEvidenceFirstApproval(t *testing.T) {
	r := hitl.NewRequest("accept .ics", "3 events", "no injection found")
	ok, err := r.Confirm(r.Nonce(), true)
	if err != nil || !ok {
		t.Fatalf("legitimate approval should pass: ok=%v err=%v", ok, err)
	}
}

func TestClickjackRejected(t *testing.T) {
	r := hitl.NewRequest("accept .ics", "evidence")
	// A clickjacked/overlaid click cannot echo the nonce it never saw.
	if _, err := r.Confirm("attacker-guess", true); !errors.Is(err, hitl.ErrNonceMismatch) {
		t.Fatalf("mismatched nonce must be rejected, got %v", err)
	}
}

func TestEvidenceFreeRejected(t *testing.T) {
	r := hitl.NewRequest("accept blindly") // no evidence
	if _, err := r.Confirm(r.Nonce(), true); !errors.Is(err, hitl.ErrNoEvidence) {
		t.Fatalf("evidence-free approval must be rejected, got %v", err)
	}
}

func TestExplicitDenial(t *testing.T) {
	r := hitl.NewRequest("accept", "evidence")
	if ok, _ := r.Confirm(r.Nonce(), false); ok {
		t.Fatal("approve=false must not approve")
	}
}
