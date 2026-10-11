package controlplane

import (
	"fmt"

	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/gledger"
	"github.com/t0ul/goverlord"
)

// Governance puts the agent's operational config (model routes, extraction mode,
// policy knobs) under a governed control plane: RBAC, four-eyes approval on
// mutations, versioned rollback, and a fail-closed kill switch — all audited to
// gledger. In production the dangerous moments are config changes, incidents,
// and the compromised operator, not just the model; this is the Track II layer
// that governs them.
//
// Config mutations and rollbacks require dual control (a second, different
// approver). The kill switch, once engaged, refuses all mutations and signals
// the orchestrator to halt the agent loop.
type Governance struct {
	cp *goverlord.ControlPlane
	// Inventory, if set, durably records approvals and admin actions (cpstore),
	// so decisions survive a restart and the console shows real history.
	Inventory *datastore.Store
}

// Standard role names seeded by NewGovernance.
const (
	RoleAdmin    = "admin"    // everything
	RoleOperator = "operator" // propose config changes
	RoleApprover = "approver" // approve config changes and roll back
	RoleSRE      = "sre"      // engage/disengage the kill switch
)

// NewGovernance seeds the control plane with the agent's initial config, the
// standard role set, dual control on config.write and rollback, and the given
// operators, auditing every decision to the shared gledger log.
func NewGovernance(audit *gledger.AuditLog, initial map[string]any, operators ...goverlord.Operator) *Governance {
	opts := []goverlord.Option{
		goverlord.WithConfig(initial),
		goverlord.WithAuditor(audit),
		goverlord.WithRole(goverlord.Role{Name: RoleAdmin, Permissions: []goverlord.Permission{goverlord.PermWildcard}}),
		goverlord.WithRole(goverlord.Role{Name: RoleOperator, Permissions: []goverlord.Permission{goverlord.PermConfigWrite}}),
		goverlord.WithRole(goverlord.Role{Name: RoleApprover, Permissions: []goverlord.Permission{goverlord.PermConfigWrite, goverlord.PermRollback}}),
		goverlord.WithRole(goverlord.Role{Name: RoleSRE, Permissions: []goverlord.Permission{goverlord.PermKillSwitch}}),
		goverlord.WithDualControl(goverlord.PermConfigWrite, goverlord.PermRollback),
	}
	for _, op := range operators {
		opts = append(opts, goverlord.WithOperator(op))
	}
	return &Governance{cp: goverlord.New(opts...)}
}

// ProposeConfig proposes a config change. If config.write is under dual control
// (it is by default) the change is pending until a different approver commits
// it; applied reports whether it took effect immediately.
func (g *Governance) ProposeConfig(opID, note string, set map[string]any) (proposalID string, applied bool, err error) {
	return g.cp.Propose(opID, goverlord.PermConfigWrite, goverlord.Change{Note: note, Set: set})
}

// Approve commits a pending proposal (four-eyes: approverID must differ from the
// proposer and hold the permission). On success the decision is recorded to the
// inventory, if one is attached.
func (g *Governance) Approve(approverID, proposalID string) (bool, error) {
	// Capture proposal details before goverlord discards the committed proposal.
	var pr goverlord.Proposal
	for _, p := range g.cp.Pending() {
		if p.ID == proposalID {
			pr = p
		}
	}
	ok, err := g.cp.Approve(approverID, proposalID)
	if err == nil && ok && g.Inventory != nil {
		_ = g.Inventory.RecordApproval(proposalID, pr.By, approverID, string(pr.Perm), pr.Change.Note, g.cp.Version())
	}
	return ok, err
}

// Reject discards a pending proposal.
func (g *Governance) Reject(approverID, proposalID string) error {
	return g.cp.Reject(approverID, proposalID)
}

// Rollback reverts config to the snapshot at version `to`, recorded as a new
// version (history is never rewritten).
func (g *Governance) Rollback(opID string, to int) error { return g.cp.Rollback(opID, to) }

// SetKillSwitch engages or disengages the fail-closed switch, recording the
// admin action to the inventory if one is attached.
func (g *Governance) SetKillSwitch(opID string, engage bool) error {
	err := g.cp.KillSwitch(opID, engage)
	if err == nil && g.Inventory != nil {
		_ = g.Inventory.RecordAdmin(opID, "killswitch", fmt.Sprintf("engage=%v", engage))
	}
	return err
}

// Killed reports whether the kill switch is engaged. Pass this as the
// Orchestrator's Killed hook to halt the agent loop fail-closed.
func (g *Governance) Killed() bool { return g.cp.Killed() }

// Config returns the current effective config snapshot.
func (g *Governance) Config() map[string]any { return g.cp.Config() }

// String reads a string config value, or def when absent/non-string. The
// orchestrator uses this to pick up governed values (e.g. the planner model).
func (g *Governance) String(key, def string) string {
	if v, ok := g.cp.Config()[key].(string); ok && v != "" {
		return v
	}
	return def
}

// Version, History, and Pending expose the governed state for an operator view.
func (g *Governance) Version() int                  { return g.cp.Version() }
func (g *Governance) History() []goverlord.Version  { return g.cp.History() }
func (g *Governance) Pending() []goverlord.Proposal { return g.cp.Pending() }
