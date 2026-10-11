package provenance_test

import (
	"errors"
	"testing"

	"github.com/t0ul/emaildrop/pkg/provenance"
)

func TestSignedOutputVerifies(t *testing.T) {
	s, pub, err := provenance.NewSigner("agent")
	if err != nil {
		t.Fatal(err)
	}
	v := provenance.NewVerifier().Trust("agent", pub)
	out := []byte("BEGIN:VCALENDAR...")
	if err := v.Verify(out, s.Sign(out)); err != nil {
		t.Fatalf("genuine output should verify, got %v", err)
	}
}

func TestTamperedOutputFails(t *testing.T) {
	s, pub, _ := provenance.NewSigner("agent")
	v := provenance.NewVerifier().Trust("agent", pub)
	m := s.Sign([]byte("original"))
	if err := v.Verify([]byte("tampered"), m); !errors.Is(err, provenance.ErrBadSignature) {
		t.Fatalf("tampered output must fail, got %v", err)
	}
}

func TestUntrustedKeyRejected(t *testing.T) {
	rogue, _, _ := provenance.NewSigner("rogue")
	v := provenance.NewVerifier() // trusts no one
	if err := v.Verify([]byte("x"), rogue.Sign([]byte("x"))); !errors.Is(err, provenance.ErrUnknownKey) {
		t.Fatalf("untrusted signer must be rejected, got %v", err)
	}
}
