// Package dataset validates the provenance of data at ingestion (M19 / LLM04
// data poisoning). A record that claims to come from a trusted source must carry
// a valid signature over its content; a forged or tampered "trusted" record is
// rejected. Unsigned data is accepted but marked untrusted, so it is contained
// downstream (retrieval sanitization, spotlighting) rather than trusted.
package dataset

import (
	"errors"
	"fmt"

	"github.com/t0ul/emaildrop/pkg/provenance"
)

// ErrForged is returned when a record presents a signature that does not verify.
var ErrForged = errors.New("dataset: record signature does not verify (forged or tampered source)")

// Record is a document offered for ingestion, optionally signed by its source.
type Record struct {
	ID     string
	Source string
	Text   string
	Signed bool            // whether a content credential is attached
	Mark   provenance.Mark // the credential, when Signed
}

// Verify decides a record's trust at ingestion:
//   - signed and valid against v  -> (true, nil)   trusted
//   - signed but invalid          -> (false, ErrForged)   REJECT
//   - unsigned                    -> (false, nil)   accept as untrusted
func Verify(v *provenance.Verifier, r Record) (trusted bool, err error) {
	if !r.Signed {
		return false, nil
	}
	if err := v.Verify([]byte(r.Text), r.Mark); err != nil {
		return false, fmt.Errorf("%w: %v", ErrForged, err)
	}
	return true, nil
}
