package controlplane

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/t0ul/emaildrop/pkg/argcheck"
	"github.com/t0ul/emaildrop/pkg/mcp"
)

// SandboxExecTool exposes the egress-denied MicroVM detonation chamber as a
// governed MCP tool, so any agent — or the gustoms gateway sitting in front of
// it (allowlist + manifest pin + per-call authorization) — can run untrusted
// commands through the one isolation boundary instead of on the host.
//
// The caller passes an argv array; the interpreter's Policy enforces the
// argv[0] allowlist and rejects shell metacharacters (argcheck), then detonates
// the array with NO shell inside the VM over vsock. Two properties make this
// safe to expose: an argument can never break out into command injection (no
// shell), and a detonated command cannot beacon out (the VM has no egress).
func SandboxExecTool(in *Interpreter) mcp.Tool {
	return mcp.Tool{
		Name:        "sandbox_exec",
		Description: "Run an allow-listed command (argv array) inside the isolated, egress-denied MicroVM and return its output.",
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			argv, err := toArgv(args["argv"])
			if err != nil {
				return nil, err
			}
			traceID, _ := args["trace_id"].(string)
			// Policy block vs sandbox output both come back as the output string;
			// a blocked command is prefixed "[Interpreter] BLOCKED".
			return map[string]any{"output": in.ExecuteArgv(ctx, traceID, argv)}, nil
		},
	}
}

// SandboxFetchTool is web_fetch done right for an agent: the fetch EXECUTES
// inside the egress-denied MicroVM (via the in-VM `vmfetch` tool), not on the
// host, so untrusted response bytes are parsed off the host. The guest has no
// network of its own — vmfetch reaches the target only through the host egress
// broker, where netpolicy (allowlist + dial-pinning + no-IMDS) is the single
// authority. Contrast mcp.WebFetchTool, which fetches on the host behind the
// same netpolicy; prefer this one for anything that processes the response.
func SandboxFetchTool(in *Interpreter) mcp.Tool {
	return mcp.Tool{
		Name:        "web_fetch",
		Description: "Fetch an allow-listed HTTP(S) URL inside the isolated MicroVM (egress brokered through the host) and return its status and body.",
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			// Tool-argument injection gate (M16, A6): validate the args BEFORE they
			// cross the vsock boundary into the VM. Reject unknown args; require a
			// well-formed http(s) URL (netpolicy still re-checks SSRF/allowlist); and
			// reject shell metacharacters in the trace_id token via argcheck.
			if err := fetchArgsOK(args); err != nil {
				return nil, err
			}
			rawURL, _ := args["url"].(string)
			traceID, _ := args["trace_id"].(string)
			return map[string]any{"output": in.ExecuteFetch(ctx, traceID, rawURL)}, nil
		},
	}
}

// fetchArgsOK is the tool-argument injection gate (M16, A6) that runs BEFORE a web_fetch
// crosses the vsock boundary into the VM. It rejects unknown arguments, a url that is not
// a string / is empty / carries control characters or whitespace (an injection shape),
// and a trace_id — which becomes part of the in-VM command context — containing shell
// metacharacters (argcheck). It deliberately does NOT police the URL scheme/host: the
// interpreter's allowlist + netpolicy remain the egress/SSRF authority (and audit a
// refused scheme as a BLOCKED detonation), so this gate only hardens arg SHAPE.
func fetchArgsOK(args map[string]any) error {
	for k := range args {
		if k != "url" && k != "trace_id" {
			return fmt.Errorf("web_fetch: unexpected argument %q", k)
		}
	}
	rawURL, ok := args["url"].(string)
	if !ok || rawURL == "" {
		return errors.New("web_fetch: 'url' argument is required")
	}
	if strings.ContainsAny(rawURL, "\x00\n\r\t ") {
		return errors.New("web_fetch: 'url' contains control characters or whitespace")
	}
	if tid, ok := args["trace_id"]; ok {
		s, ok := tid.(string)
		if !ok {
			return errors.New("web_fetch: 'trace_id' must be a string")
		}
		if s != "" {
			if err := argcheck.CheckToken(s); err != nil {
				return fmt.Errorf("web_fetch: %w", err)
			}
		}
	}
	return nil
}

// toArgv coerces a JSON array of strings into an argv slice.
func toArgv(v any) ([]string, error) {
	raw, ok := v.([]any)
	if !ok || len(raw) == 0 {
		return nil, errors.New("sandbox_exec: 'argv' must be a non-empty array of strings")
	}
	argv := make([]string, len(raw))
	for i, e := range raw {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("sandbox_exec: argv[%d] is not a string", i)
		}
		argv[i] = s
	}
	return argv, nil
}
