// Package roster is the app's default tool line-up, in one place so every entry
// point (cmd/emaildrop, cmd/webapp) registers the same set and runs them in the
// same order. The write tools emit inert .ics artifacts; the read-only tools'
// text is persisted by the pipeline into the per-email summary sidecar.
package roster

import (
	"github.com/t0ul/emaildrop/pkg/agent/extractor"
	"github.com/t0ul/emaildrop/pkg/agent/items"
	"github.com/t0ul/emaildrop/pkg/agent/tool"
	"github.com/t0ul/emaildrop/pkg/agent/tools"
)

// Register adds the default roster to r.
func Register(r *tool.Registry) {
	r.Register(extractor.New())       // event_extractor (write_ics): meetings -> .ics
	r.Register(items.ItemExtractor{}) // item_extractor (write_ics): tasks/heads-ups/actions -> items.ics
	r.Register(tools.ActionItems{})   // action_items (read_only)
	r.Register(tools.Digest{})        // digest (read_only)
	r.Register(tools.Contacts{})      // contacts (read_only, PII-scoped)
}

// Names is the pipeline run order for the default roster.
func Names() []string {
	return []string{"event_extractor", "item_extractor", "action_items", "digest", "contacts"}
}
