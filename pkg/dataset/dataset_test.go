package dataset_test

import (
	"errors"
	"testing"

	"github.com/t0ul/emaildrop/pkg/dataset"
	"github.com/t0ul/emaildrop/pkg/provenance"
)

func TestSignedRecordTrusted(t *testing.T) {
	s, pub, _ := provenance.NewSigner("corpus")
	v := provenance.NewVerifier().Trust("corpus", pub)
	text := "approved training document"
	r := dataset.Record{ID: "1", Text: text, Signed: true, Mark: s.Sign([]byte(text))}
	trusted, err := dataset.Verify(v, r)
	if err != nil || !trusted {
		t.Fatalf("validly signed record should be trusted: trusted=%v err=%v", trusted, err)
	}
}

func TestForgedRecordRejected(t *testing.T) {
	_, pub, _ := provenance.NewSigner("corpus")
	v := provenance.NewVerifier().Trust("corpus", pub)
	// Claims to be signed by corpus, but the signature is bogus.
	r := dataset.Record{ID: "2", Text: "poisoned doc", Signed: true, Mark: provenance.Mark{KeyID: "corpus", Alg: "ed25519", Sig: "deadbeef"}}
	if _, err := dataset.Verify(v, r); !errors.Is(err, dataset.ErrForged) {
		t.Fatalf("forged record must be rejected, got %v", err)
	}
}

func TestUnsignedRecordUntrusted(t *testing.T) {
	v := provenance.NewVerifier()
	trusted, err := dataset.Verify(v, dataset.Record{ID: "3", Text: "an email", Signed: false})
	if err != nil || trusted {
		t.Fatalf("unsigned record should be accepted-but-untrusted: trusted=%v err=%v", trusted, err)
	}
}
