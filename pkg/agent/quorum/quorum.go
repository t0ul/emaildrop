// Package quorum defends against a rogue or colluding agent authorizing a
// sensitive action alone. An action is approved only when at least Threshold
// DISTINCT trusted agents have each signed that exact action (a2a signatures).
// A single compromised agent cannot reach the threshold, cannot forge a peer's
// signature, and cannot be counted twice — the inter-agent analogue of
// four-eyes.
package quorum

import (
	"errors"
	"fmt"

	"github.com/t0ul/emaildrop/pkg/agent/a2a"
)

var (
	ErrDuplicate    = errors.New("quorum: the same agent attested more than once")
	ErrInsufficient = errors.New("quorum: not enough distinct valid attestations")
)

// Policy requires Threshold distinct attesting agents, verified against Verifier.
type Policy struct {
	Threshold int
	Verifier  *a2a.Verifier
}

// Approve accepts the action only if at least Threshold distinct trusted agents
// signed exactly that action. Invalid/forged attestations are ignored; a repeat
// from an already-counted agent is rejected.
func (p Policy) Approve(action string, attestations []a2a.Message) error {
	seen := map[string]bool{}
	valid := 0
	for _, m := range attestations {
		if m.Body != action {
			continue // attesting something else
		}
		if p.Verifier.Verify(m) != nil {
			continue // forged / untrusted / replayed
		}
		if seen[m.From] {
			return fmt.Errorf("%w: %q", ErrDuplicate, m.From)
		}
		seen[m.From] = true
		valid++
	}
	if valid < p.Threshold {
		return fmt.Errorf("%w: have %d distinct, need %d", ErrInsufficient, valid, p.Threshold)
	}
	return nil
}
