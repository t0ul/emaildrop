// Package skills is the agent's on-demand capability library (the "skills"
// dimension of the agent factory). A skill is a NAMED, VERSIONED, loaded-on-demand
// procedure — instructions (± scripts/resources) an agent pulls into context when a
// task needs it, to keep the always-on prompt lean.
//
// That makes a skill the sharpest supply-chain surface in an agentic system: it is
// runtime-loaded instructions/code from a possibly-untrusted source. A poisoned
// skill is persistent prompt injection (LLM03); a skill that reaches for a tool the
// agent was never granted is a confused deputy. So loading is fail-closed and
// layered, exactly like the .ics/M20 and MCP-pin controls this repo already runs:
//
//  1. SIGN   — the skill's content must carry a valid signature from a trusted key.
//  2. PIN    — its content hash must match the operator-approved pin (approve this
//              exact version; a changed skill is refused until re-approved — rug-pull).
//  3. SCOPE  — every tool the skill requires must be in the agent's allow-set
//              (a skill can only use tools the agent itself may use).
//
// Only when all three hold are the skill's instructions returned (trusted). The
// unchecked path (LoadUnsafe) exists ONLY as the undefended target of the ADD pair
// that proves why the control is here.
package skills

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/t0ul/emaildrop/pkg/provenance"
)

// Fail-closed load errors. Each is a distinct reason a skill was refused.
var (
	ErrUnsigned  = errors.New("skills: skill is unsigned or signed by an untrusted key")
	ErrUnpinned  = errors.New("skills: skill hash does not match the approved pin")
	ErrToolScope = errors.New("skills: skill requires a tool the agent is not allowed to use")
)

// Skill is a loadable capability: instructions (± a declared set of tools it needs).
// The content hash pins it; the signature authenticates it.
type Skill struct {
	Name         string   `json:"name"`
	Version      int      `json:"version"`
	Instructions string   `json:"instructions"`
	RequiredTools []string `json:"required_tools,omitempty"`
}

// Canonical is the deterministic byte form that is signed and hashed.
func (s Skill) Canonical() []byte {
	b, _ := json.Marshal(s)
	return b
}

// Hash is the content pin for a skill (sha256 over its canonical form).
func (s Skill) Hash() string {
	sum := sha256.Sum256(s.Canonical())
	return hex.EncodeToString(sum[:])
}

// Signed is a skill plus the author's content signature.
type Signed struct {
	Skill
	Mark provenance.Mark `json:"mark"`
}

// Sign produces a Signed skill from a trusted author's signer.
func Sign(s Skill, signer *provenance.Signer) Signed {
	return Signed{Skill: s, Mark: signer.Sign(s.Canonical())}
}

// Library loads skills under the sign + pin + scope controls (fail-closed).
type Library struct {
	verifier *provenance.Verifier // trusts the approved author key(s)
	pins     map[string]string    // skill name -> operator-approved content hash
	allowed  map[string]bool      // tools the agent may use
}

// NewLibrary builds a loader that trusts verifier's keys, honors the given pins, and
// scopes skills to the given tool allow-set.
func NewLibrary(verifier *provenance.Verifier, pins map[string]string, allowedTools []string) *Library {
	allow := make(map[string]bool, len(allowedTools))
	for _, t := range allowedTools {
		allow[t] = true
	}
	return &Library{verifier: verifier, pins: pins, allowed: allow}
}

// Load returns the skill's instructions only if it is signed by a trusted key, its
// hash matches the approved pin, and every required tool is in the allow-set.
// Otherwise it refuses — the instructions never reach the agent. DEFENDED path.
func (l *Library) Load(s Signed) (string, error) {
	if l.verifier == nil || l.verifier.Verify(s.Skill.Canonical(), s.Mark) != nil {
		return "", ErrUnsigned
	}
	if l.pins[s.Name] != s.Hash() {
		return "", ErrUnpinned
	}
	for _, t := range s.RequiredTools {
		if !l.allowed[t] {
			return "", ErrToolScope
		}
	}
	return s.Instructions, nil
}

// LoadUnsafe returns the skill's instructions with NO checks. It is the UNDEFENDED
// target of the skill-supply-chain ADD pair (a poisoned skill's instructions reach
// the agent verbatim). Never use it on a real load path.
func LoadUnsafe(s Signed) string { return s.Instructions }
