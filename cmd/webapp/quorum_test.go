package main

import (
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/a2a"
	"github.com/t0ul/emaildrop/pkg/agent/quorum"
)

// TestActionQuorumGate locks A4/A5: the egress action gate requires TWO distinct trusted
// agents to a2a-attest the exact action. One party is insufficient, the same party twice
// is rejected, a forged/untrusted attestation is ignored, and attesting a different
// action does not count. Real a2a signers + real quorum.Policy — the on-path control.
func TestActionQuorumGate(t *testing.T) {
	k1 := []byte("agent-key-0000000000000000000000")
	k2 := []byte("fetcher-key-00000000000000000000")
	agent := a2a.NewSigner("agent", k1)
	fetcher := a2a.NewSigner("action-fetcher", k2)
	ver := a2a.NewVerifier().Trust("agent", k1).Trust("action-fetcher", k2)
	pol := quorum.Policy{Threshold: 2, Verifier: ver}
	const action = "fetch:https://schools.nyc.gov/handbook"

	if err := pol.Approve(action, []a2a.Message{agent.Sign(action), fetcher.Sign(action)}); err != nil {
		t.Fatalf("two distinct trusted attestations must approve: %v", err)
	}
	if err := pol.Approve(action, []a2a.Message{agent.Sign(action)}); err == nil {
		t.Error("a single party must be insufficient")
	}
	if err := pol.Approve(action, []a2a.Message{agent.Sign(action), agent.Sign(action)}); err == nil {
		t.Error("the same agent twice must be rejected (no self-collusion)")
	}
	rogue := a2a.NewSigner("action-fetcher", []byte("WRONG-key-00000000000000000000000"))
	if err := pol.Approve(action, []a2a.Message{agent.Sign(action), rogue.Sign(action)}); err == nil {
		t.Error("a forged attestation must not count toward the quorum")
	}
	if err := pol.Approve(action, []a2a.Message{agent.Sign(action), fetcher.Sign("fetch:https://evil.test")}); err == nil {
		t.Error("attesting a DIFFERENT action must not approve this one")
	}
}
