package controlplane

import (
	"context"
	"errors"
	"testing"

	"github.com/t0ul/emaildrop/pkg/mcp"
	"github.com/t0ul/gustoms"
)

func fetchStub() mcp.Tool {
	return mcp.Tool{
		Name:        "web_fetch",
		Description: "fetch an allow-listed URL in the MicroVM",
		Handler: func(context.Context, map[string]any) (any, error) {
			return map[string]any{"output": "FETCHED"}, nil
		},
	}
}

func TestToolGatewayCallsThroughWhenAllowed(t *testing.T) {
	gw := NewToolGateway("sandbox", fetchStub(), func() bool { return true })
	out, err := gw.Call(context.Background(), "t1", "action-fetcher", "sandbox", "web_fetch", map[string]any{"url": "https://ok"})
	if err != nil {
		t.Fatalf("call should pass: %v", err)
	}
	if out.(map[string]any)["output"] != "FETCHED" {
		t.Fatalf("unexpected output: %v", out)
	}
}

// TestToolGatewayDeniesWhenToolsBlocked is the "drop pins on halt" behavior: the
// authorizer refuses every MCP call while the kill switch blocks tools.
func TestToolGatewayDeniesWhenToolsBlocked(t *testing.T) {
	blocked := false
	gw := NewToolGateway("sandbox", fetchStub(), func() bool { return !blocked })
	if _, err := gw.Call(context.Background(), "t1", "action-fetcher", "sandbox", "web_fetch", nil); err != nil {
		t.Fatalf("call should pass before block: %v", err)
	}
	blocked = true
	if _, err := gw.Call(context.Background(), "t1", "action-fetcher", "sandbox", "web_fetch", nil); !errors.Is(err, gustoms.ErrForbidden) {
		t.Fatalf("blocked tools must refuse the MCP call, got %v", err)
	}
}

// TestToolGatewayOnlyAllowsPinnedTool rejects a tool the manifest does not list.
func TestToolGatewayOnlyAllowsPinnedTool(t *testing.T) {
	gw := NewToolGateway("sandbox", fetchStub(), nil)
	if _, err := gw.Call(context.Background(), "t1", "action-fetcher", "sandbox", "exfiltrate", nil); err == nil {
		t.Fatal("an unlisted tool must be rejected")
	}
}
