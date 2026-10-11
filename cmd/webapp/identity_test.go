package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/t0ul/emaildrop/pkg/provenance"
)

// TestAgentIdentityPersistence locks the G1 fix: the agent identity must NEVER degrade
// to an ephemeral key silently. A real seed file on a real temp dir — no mocks.
func TestAgentIdentityPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.key")

	// First boot: no seed yet. It creates + persists one, and reports persistent.
	s1, _, persistent, err := agentIdentity(path)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	if !persistent {
		t.Fatal("first boot must be persistent (seed written to disk)")
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("seed not written: %v", err)
	}

	// Restart: the same seed on disk must yield the SAME key, so artifacts signed in
	// the first run still verify in the second. Persistent again.
	s2, v2, persistent, err := agentIdentity(path)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if !persistent {
		t.Fatal("restart must be persistent (seed already on disk)")
	}
	msg := []byte("calendar.ics")
	sig1 := s1.Sign(msg)
	if err := v2.Verify(msg, sig1); err != nil {
		t.Fatalf("a signature from run 1 must verify under run 2's key (persistent identity): %v", err)
	}
	if sig2 := s2.Sign(msg); sig2.KeyID != sig1.KeyID {
		t.Fatalf("stable keyID expected, got %q vs %q", sig2.KeyID, sig1.KeyID)
	}

	// The seed is a real 32-byte ed25519 seed, so SignerFromSeed round-trips it.
	if _, _, err := provenance.SignerFromSeed("email-agent", seed); err != nil {
		t.Fatalf("persisted seed unusable: %v", err)
	}

	// Degraded path: a directory where the seed can't be written (the path IS a dir)
	// forces an in-memory key — which MUST be reported non-persistent so the boot path
	// can refuse it. This is the exact silent-downgrade the fix removes.
	badDir := filepath.Join(dir, "asdir")
	if err := os.Mkdir(badDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, persistent, err = agentIdentity(badDir) // writing a file at a dir path fails
	if err != nil {
		t.Fatalf("degraded path should still return a signer, got err: %v", err)
	}
	if persistent {
		t.Fatal("an unpersistable seed MUST be reported non-persistent (no silent ephemeral downgrade)")
	}
}
