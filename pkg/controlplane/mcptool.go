package controlplane

import (
	"context"
	"fmt"

	"github.com/t0ul/emaildrop/pkg/mcp"
	"github.com/t0ul/gustoms"
)

// MCP on the app path (C4e). The agent's executing tool (the MicroVM-brokered
// web_fetch) is reached through a gustoms gateway rather than called directly, so
// every invocation is subject to MCP governance: the server's manifest is pinned
// (a silently-swapped tool — a rug-pull — is rejected), only the allow-listed
// tool may run, and a per-call authorizer decides whether the call proceeds. The
// authorizer is wired to the kill switch, so engaging it refuses every MCP call —
// the functional "drop pins on halt" (the pins remain; calls are denied).

// toolClient adapts one in-process mcp.Tool to the gustoms.Client interface, so a
// local tool can be served through the MCP gateway with the same pinning and
// authZ a remote MCP server gets.
type toolClient struct{ tool mcp.Tool }

func (c toolClient) ListTools(context.Context) ([]gustoms.ToolSpec, error) {
	return []gustoms.ToolSpec{{Name: c.tool.Name, Description: c.tool.Description}}, nil
}

func (c toolClient) CallTool(ctx context.Context, name string, args map[string]any) (any, error) {
	if name != c.tool.Name {
		return nil, fmt.Errorf("gustoms: server does not advertise tool %q", name)
	}
	return c.tool.Handler(ctx, args)
}

// NewToolGateway serves tool through a gustoms gateway as server `name`, strictly
// pinned to its current manifest and allowing only that one tool. allowTools, when
// set, gates every call: it returns false while the kill switch blocks tools, so
// an engaged switch refuses all MCP calls. The returned gateway's Call routes to
// the tool's handler only after pin-verify + allow-list + this authZ pass.
func NewToolGateway(name string, tool mcp.Tool, allowTools func() bool) *gustoms.Gateway {
	spec := []gustoms.ToolSpec{{Name: tool.Name, Description: tool.Description}}
	return gustoms.New(
		gustoms.WithServer(gustoms.Server{
			Name:         name,
			Client:       toolClient{tool: tool},
			Pin:          gustoms.ManifestHash(spec), // pinned to the manifest we shipped
			AllowedTools: []string{tool.Name},
		}),
		gustoms.WithStrictPinning(),
		gustoms.WithAuthorizer(func(_, _, _ string) bool {
			return allowTools == nil || allowTools()
		}),
	)
}
