package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/t0ul/emaildrop/pkg/argcheck"
	"github.com/t0ul/gledger"
)

// ForbiddenSignatures is the secondary tripwire: a command containing any of
// these is blocked outright. A blocklist is bypassable (it missed `rm
// --recursive /` and base64-obfuscated payloads), so it is NOT the primary gate
// — DefaultAllowedCommands is. The blocklist stays only as a cheap extra net.
var ForbiddenSignatures = []string{"rm -rf", "nc -e", "mkfifo", "> /dev/tcp"}

// DefaultAllowedCommands is the primary gate: only these argv[0] programs may be
// detonated. An allowlist of known-safe, read-only commands is not bypassable
// the way a blocklist of bad ones is — anything unlisted is refused by default.
var DefaultAllowedCommands = []string{
	"uname", "ls", "cat", "head", "tail", "echo", "pwd", "id",
	"env", "date", "git", "whoami", "wc", "grep", "sort", "true",
	"vmfetch", // in-VM fetch tool; reaches the net only via the host egress broker
}

// Policy is the outbound-command gate applied before anything reaches the
// sandbox. Allowed (argv[0] allowlist) is the primary control; Block is the
// secondary signature tripwire. The zero value uses the package defaults.
type Policy struct {
	Allowed []string // permitted argv[0]; empty = DefaultAllowedCommands
	Block   []string // secondary signature tripwire; nil = ForbiddenSignatures
}

func (p Policy) allowed() []string {
	if len(p.Allowed) > 0 {
		return p.Allowed
	}
	return DefaultAllowedCommands
}

func (p Policy) block() []string {
	if p.Block != nil {
		return p.Block
	}
	return ForbiddenSignatures
}

// Check validates an argv array. It returns a non-empty reason string when the
// command is refused (empty reason = allowed). argv[0] must be on the allowlist,
// every argument must be free of shell metacharacters (so the array can never be
// re-interpreted by a shell), and the joined command must trip no blocklist
// signature.
func (p Policy) Check(argv []string) string {
	if len(argv) == 0 {
		return "empty command"
	}
	allowed := false
	for _, a := range p.allowed() {
		if argv[0] == a {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Sprintf("command %q not on allowlist", argv[0])
	}
	for _, arg := range argv[1:] {
		if err := argcheck.CheckToken(arg); err != nil {
			return fmt.Sprintf("argument rejected: %v", err)
		}
	}
	joined := strings.Join(argv, " ")
	for _, sig := range p.block() {
		if strings.Contains(joined, sig) {
			return fmt.Sprintf("malicious signature %q", sig)
		}
	}
	return ""
}

// Interpreter validates a planner-chosen command against the policy (allowlist +
// argcheck + blocklist tripwire), then pushes it across the vsock boundary
// (bridged to host loopback) to the egress-denied MicroVM for isolated
// detonation as an argv array — never a shell string. Every decision is audited
// under the request's trace_id: the policy gate and the vsock result.
type Interpreter struct {
	MicroVMURL string // default http://127.0.0.1:5000 (vsock bridge; use 127.0.0.1, not localhost)
	Audit      *gledger.AuditLog
	HTTP       *http.Client
	Policy     Policy // zero value = package defaults
}

// NewInterpreter returns an interpreter targeting microVMURL (empty = default
// local bridge) and auditing to the given log.
func NewInterpreter(microVMURL string, audit *gledger.AuditLog) *Interpreter {
	if microVMURL == "" {
		microVMURL = "http://127.0.0.1:5000"
	}
	return &Interpreter{MicroVMURL: microVMURL, Audit: audit, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

type detonateRequest struct {
	Command string   `json:"command,omitempty"`
	Argv    []string `json:"argv,omitempty"`
	TraceID string   `json:"trace_id"`
}

type detonateResponse struct {
	Output  string `json:"output"`
	TraceID string `json:"trace_id"`
}

// ExecuteInSandbox is the string-command entry point (the planner emits a
// read-only shell string). The command is tokenized on whitespace into an argv
// array and routed through ExecuteArgv — so shell operators (pipes, redirects,
// globs, substitution) are not supported by design; that is the security
// property, not a limitation.
func (in *Interpreter) ExecuteInSandbox(ctx context.Context, traceID, command string) string {
	return in.ExecuteArgv(ctx, traceID, strings.Fields(command))
}

// ExecuteArgv applies the policy gate, then detonates argv in the MicroVM as an
// argument array (no shell). A blocked command never leaves the host; a
// connection failure is reported, not fatal. The returned string is the sandbox
// output, or a status message prefixed with [Interpreter] to signal
// block/failure to the caller.
func (in *Interpreter) ExecuteArgv(ctx context.Context, traceID string, argv []string) string {
	if reason := in.Policy.Check(argv); reason != "" {
		in.Audit.Emit(traceID, "policy", "gate", gledger.F{
			"decision": "block", "reason": reason, "argv": argv,
		})
		return fmt.Sprintf("[Interpreter] BLOCKED: %s.", reason)
	}
	in.Audit.Emit(traceID, "policy", "gate", gledger.F{"decision": "allow", "argv": argv})
	return in.detonate(ctx, traceID, argv)
}

// ExecuteFetch detonates the in-VM `vmfetch` tool against rawURL. The URL is
// validated as an http/https URL here (not run through the shell-metacharacter
// gate, which would wrongly reject legal URL characters) and passed as a single
// argv element — the VM execs it with no shell, and vmfetch reaches the network
// only through the host egress broker (netpolicy). So the fetch EXECUTES in the
// chamber, not on the host, yet egress stays a single audited chokepoint.
func (in *Interpreter) ExecuteFetch(ctx context.Context, traceID, rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		in.Audit.Emit(traceID, "policy", "gate", gledger.F{"decision": "block", "reason": "invalid url", "url": rawURL})
		return "[Interpreter] BLOCKED: url must be a valid http(s) URL."
	}
	if strings.ContainsAny(rawURL, " \t\r\n") {
		in.Audit.Emit(traceID, "policy", "gate", gledger.F{"decision": "block", "reason": "whitespace in url", "url": rawURL})
		return "[Interpreter] BLOCKED: url contains whitespace."
	}
	in.Audit.Emit(traceID, "policy", "gate", gledger.F{"decision": "allow", "tool": "vmfetch", "url": rawURL})
	return in.detonate(ctx, traceID, []string{"vmfetch", rawURL})
}

// detonate POSTs argv to the MicroVM and returns the sandbox output (or a status
// message prefixed with [Interpreter]). It performs no policy checks — callers
// gate first.
func (in *Interpreter) detonate(ctx context.Context, traceID string, argv []string) string {
	buf, _ := json.Marshal(detonateRequest{Argv: argv, TraceID: traceID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.MicroVMURL, bytes.NewReader(buf))
	if err != nil {
		in.Audit.Emit(traceID, "vsock", "detonate", gledger.F{"ok": false, "error": err.Error()})
		return fmt.Sprintf("[Interpreter] MicroVM request build failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := in.HTTP.Do(req)
	if err != nil {
		in.Audit.Emit(traceID, "vsock", "detonate", gledger.F{"ok": false, "error": err.Error()})
		return fmt.Sprintf("[Interpreter] MicroVM connection failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		in.Audit.Emit(traceID, "vsock", "detonate", gledger.F{"ok": false, "status": resp.StatusCode})
		return fmt.Sprintf("[Interpreter] MicroVM returned status %d", resp.StatusCode)
	}
	var data detonateResponse
	if err := json.Unmarshal(body, &data); err != nil {
		in.Audit.Emit(traceID, "vsock", "detonate", gledger.F{"ok": false, "error": "bad json"})
		return "[Interpreter] MicroVM returned unreadable response"
	}
	in.Audit.Emit(traceID, "vsock", "detonate", gledger.F{
		"ok": true, "out_len": len(data.Output), "vm_trace": data.TraceID,
	})
	return data.Output
}
