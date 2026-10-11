package controlplane

import (
	"errors"
	"fmt"

	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/registry"
)

// PromoteWithLatestEval closes the MLOps loop: it reads the latest persisted
// eval score for label from the inventory, stamps it on the model, then runs the
// gated promotion — so "ship to prod" is backed by a real, auditable score, not
// an operator's say-so (M11 eval → M19 promotion gate).
func PromoteWithLatestEval(reg *registry.Registry, inv *datastore.Store, name, version, label string) error {
	e, ok, err := inv.LatestEval(label)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("controlplane: no eval score recorded for %q", label)
	}
	if err := reg.SetEval(name, version, e.F1); err != nil {
		return err
	}
	if err := reg.Promote(name, version); err != nil {
		return errors.New("controlplane: promotion blocked: " + err.Error())
	}
	return nil
}
