package quorum_test

import (
	"errors"
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/a2a"
	"github.com/t0ul/emaildrop/pkg/agent/quorum"
)

const action = "detonate: rm -rf /important"

func setup() (*a2a.Signer, *a2a.Signer, quorum.Policy) {
	pk, ck := []byte("planner-key"), []byte("coder-key")
	planner := a2a.NewSigner("planner", pk)
	coder := a2a.NewSigner("coder", ck)
	v := a2a.NewVerifier().Trust("planner", pk).Trust("coder", ck)
	return planner, coder, quorum.Policy{Threshold: 2, Verifier: v}
}

func TestTwoDistinctAgentsApprove(t *testing.T) {
	planner, coder, p := setup()
	if err := p.Approve(action, []a2a.Message{planner.Sign(action), coder.Sign(action)}); err != nil {
		t.Fatalf("two distinct signers should approve, got %v", err)
	}
}

func TestSingleRogueInsufficient(t *testing.T) {
	planner, _, p := setup()
	if err := p.Approve(action, []a2a.Message{planner.Sign(action)}); !errors.Is(err, quorum.ErrInsufficient) {
		t.Fatalf("one agent must not meet quorum, got %v", err)
	}
}

func TestSameAgentCannotDoubleCount(t *testing.T) {
	planner, _, p := setup()
	if err := p.Approve(action, []a2a.Message{planner.Sign(action), planner.Sign(action)}); !errors.Is(err, quorum.ErrDuplicate) {
		t.Fatalf("same agent twice must be rejected, got %v", err)
	}
}

func TestForgedAttestationIgnored(t *testing.T) {
	planner, _, p := setup()
	forged := a2a.Message{From: "coder", Body: action, Nonce: "n", Sig: "bad"}
	if err := p.Approve(action, []a2a.Message{planner.Sign(action), forged}); !errors.Is(err, quorum.ErrInsufficient) {
		t.Fatalf("forged peer attestation must not count, got %v", err)
	}
}
