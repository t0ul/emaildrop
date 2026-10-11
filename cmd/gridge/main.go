// Command gridge serves the operator console for the governed control plane:
// the live, wired-to-real-state backbone (the Wails desktop GUI, the fleet
// gridge repo, is the Capstone II wrapper around this same API). Open the
// printed URL; every action is enforced server-side by goverlord and recorded
// to the gledger audit log.
//
//	gridge [-addr :8787]
//
// Env: AUDIT_LOG (default controlplane/logs/governance.jsonl).
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/gledger"
	"github.com/t0ul/goverlord"
)

func main() {
	addr := flag.String("addr", ":8787", "listen address")
	flag.Parse()

	auditPath := envOr("AUDIT_LOG", filepath.Join("controlplane", "logs", "governance.jsonl"))
	audit, err := gledger.Open(auditPath, "gridge")
	if err != nil {
		log.Fatalf("gridge: %v", err)
	}

	gov := controlplane.NewGovernance(audit,
		map[string]any{"planner_model": "planner", "coder_model": "coder", "extract_mode": "llm"},
		goverlord.Operator{ID: "alice", Roles: []string{controlplane.RoleOperator}},
		goverlord.Operator{ID: "bob", Roles: []string{controlplane.RoleApprover}},
		goverlord.Operator{ID: "carol", Roles: []string{controlplane.RoleSRE}},
	)
	if inv, ierr := datastore.Open(envOr("INVENTORY_DB", filepath.Join("controlplane", "logs", "inventory.db"))); ierr == nil {
		defer inv.Close()
		gov.Inventory = inv // approvals + admin actions persist; console reads history
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           (&controlplane.ConsoleServer{Gov: gov}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("gridge console on http://localhost%s", *addr)
	log.Fatal(srv.ListenAndServe())
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
