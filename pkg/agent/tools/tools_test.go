package tools_test

import (
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/tool"
	"github.com/t0ul/emaildrop/pkg/agent/tools"
)

const sample = `PS 123 Newsletter
Back to School Night: Thursday, September 29th at 6:00 PM
Please RSVP by Friday. Contact mrs.smith@ps123.edu for questions.
Back to School Night: Tuesday, October 7th (rescheduled)
`

func TestAllRosterToolsAreReadOnly(t *testing.T) {
	for _, tl := range []tool.Tool{tools.ActionItems{}, tools.Digest{}, tools.Contacts{}, tools.Conflicts{}} {
		if tl.Capability() != tool.ReadOnly {
			t.Errorf("%s must be read-only, got %s", tl.Name(), tl.Capability())
		}
		if res := tl.Run(sample, tool.Ctx{DefaultYear: 2026}); len(res.Artifacts) != 0 {
			t.Errorf("%s (read-only) must not emit artifacts", tl.Name())
		}
	}
}

func TestActionItems(t *testing.T) {
	res := tools.ActionItems{}.Run(sample, tool.Ctx{})
	if !strings.Contains(res.Text, "RSVP") {
		t.Fatalf("expected an RSVP action item, got %q", res.Text)
	}
}

func TestDigest(t *testing.T) {
	res := tools.Digest{}.Run(sample, tool.Ctx{})
	if !strings.Contains(res.Text, "Subject: PS 123 Newsletter") {
		t.Fatalf("digest missing subject: %q", res.Text)
	}
}

func TestContactsSurfacesEmail(t *testing.T) {
	res := tools.Contacts{}.Run(sample, tool.Ctx{})
	if !strings.Contains(res.Text, "mrs.smith@ps123.edu") {
		t.Fatalf("contacts should surface the email, got %q", res.Text)
	}
}

func TestConflictDetector(t *testing.T) {
	res := tools.Conflicts{}.Run(sample, tool.Ctx{DefaultYear: 2026})
	if len(res.Warnings) == 0 || !strings.Contains(res.Text, "conflict") {
		t.Fatalf("expected a conflict for the rescheduled event, got %q warns=%v", res.Text, res.Warnings)
	}
}
