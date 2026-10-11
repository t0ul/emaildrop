package argcheck_test

import (
	"errors"
	"testing"

	"github.com/t0ul/emaildrop/pkg/argcheck"
)

var schema = argcheck.Schema{"query": argcheck.String, "limit": argcheck.Int}

func TestValidArgsPass(t *testing.T) {
	out, err := argcheck.Validate(schema, map[string]any{"query": "october events", "limit": 5})
	if err != nil {
		t.Fatalf("valid args rejected: %v", err)
	}
	if out["query"] != "october events" || out["limit"] != 5 {
		t.Fatalf("unexpected cleaned args: %v", out)
	}
}

func TestShellMetacharRejected(t *testing.T) {
	if _, err := argcheck.Validate(schema, map[string]any{"query": "x; rm -rf /", "limit": 1}); !errors.Is(err, argcheck.ErrShellMeta) {
		t.Fatalf("command injection must be rejected, got %v", err)
	}
}

func TestUnknownArgRejected(t *testing.T) {
	if _, err := argcheck.Validate(schema, map[string]any{"query": "x", "limit": 1, "evil": "y"}); !errors.Is(err, argcheck.ErrUnknownArg) {
		t.Fatalf("unknown arg must be rejected, got %v", err)
	}
}

func TestPathConfinement(t *testing.T) {
	if _, err := argcheck.ConfinePath("/srv/data", "reports/x.txt"); err != nil {
		t.Fatalf("in-bounds path rejected: %v", err)
	}
	if _, err := argcheck.ConfinePath("/srv/data", "../../etc/passwd"); !errors.Is(err, argcheck.ErrPathEscape) {
		t.Fatalf("traversal must be rejected, got %v", err)
	}
	if _, err := argcheck.ConfinePath("/srv/data", "/etc/passwd"); !errors.Is(err, argcheck.ErrPathEscape) {
		t.Fatalf("absolute escape must be rejected, got %v", err)
	}
}
