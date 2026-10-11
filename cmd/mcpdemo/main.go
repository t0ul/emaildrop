// Command mcpdemo shows the MCP security pillar end to end: an agent reaches a
// web_fetch tool only through the gustoms gateway (registry allowlist, manifest
// pin / rug-pull defense, per-tool authorization), and the tool itself screens
// every target through netpolicy (M16: default-deny egress, no loopback/private/
// IMDS). Every decision is recorded to gledger.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/t0ul/emaildrop/pkg/broker"
	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/mcp"
	"github.com/t0ul/emaildrop/pkg/netpolicy"
	"github.com/t0ul/emaildrop/pkg/sandbox"
	"github.com/t0ul/gledger"
	"github.com/t0ul/gustoms"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mcpdemo:", err)
		os.Exit(1)
	}
}

func run() error {
	audit, err := gledger.Open(filepath.Join("controlplane", "logs", "mcp.jsonl"), "mcpdemo")
	if err != nil {
		return err
	}

	// A legitimate, allow-listed target the browse tool may reach.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<html>search result</html>"))
	}))
	defer target.Close()

	policy := netpolicy.Policy{
		Allow:         []string{"127.0.0.1", "intranet.test"},
		AllowLoopback: true, // dev: the demo target is on loopback
		Resolve: func(host string) ([]net.IP, error) {
			if host == "intranet.test" { // an allow-listed name that rebinds internally
				return []net.IP{net.ParseIP("10.0.0.9")}, nil
			}
			return net.LookupIP(host)
		},
	}
	// Stand-in detonation chamber: the real sandbox.Daemon reached over HTTP,
	// exactly as the vsock bridge exposes the in-VM daemon. In production this URL
	// is the launchvm bridge (127.0.0.1:5000) backed by the egress-denied MicroVM;
	// here it runs the same daemon in-process so the demo needs no VM. The
	// interpreter's allowlist + argcheck gate every command before it is sent.
	daemon := sandbox.NewDaemon()
	deton := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sandbox.Request
		json.NewDecoder(r.Body).Decode(&req)
		json.NewEncoder(w).Encode(daemon.Execute(req))
	}))
	defer deton.Close()
	interp := &controlplane.Interpreter{MicroVMURL: deton.URL, Audit: audit, HTTP: deton.Client()}

	mcpSrv := httptest.NewServer(mcp.NewServer(mcp.WebFetchTool(policy, 0), controlplane.SandboxExecTool(interp)))
	defer mcpSrv.Close()

	// Persist approved MCP manifest pins to the durable inventory (survives
	// restarts; the console reads real pins).
	inv, _ := datastore.Open(filepath.Join("controlplane", "logs", "inventory.db"))
	if inv != nil {
		defer inv.Close()
	}
	gw := gustoms.New(
		gustoms.WithServer(gustoms.Server{Name: "search", Client: &mcp.HTTPClient{URL: mcpSrv.URL}, AllowedTools: []string{"web_fetch", "sandbox_exec"}}),
		gustoms.WithAuthorizer(func(caller, _, _ string) bool { return caller == "agent" }),
		gustoms.WithAuditor(audit),
		gustoms.WithPinRecorder(func(server, hash string) {
			if inv != nil {
				_ = inv.RecordPin(server, hash, "operator")
			}
		}),
	)
	_ = gw.Approve(context.Background(), gledger.NewTraceID(), "search") // pin + persist the current manifest

	call := func(caller, server, tool, url string) {
		args := map[string]any{}
		if url != "" {
			args["url"] = url
		}
		out, err := gw.Call(context.Background(), gledger.NewTraceID(), caller, server, tool, args)
		label := fmt.Sprintf("%s -> %s/%s %s", caller, server, tool, url)
		if err != nil {
			fmt.Printf("  BLOCKED  %s\n           %v\n", label, err)
			return
		}
		fmt.Printf("  ALLOWED  %s\n           %v\n", label, out)
	}

	fmt.Println("== MCP gateway + egress containment demo ==")
	fmt.Println("1) allow-listed fetch via the gateway:")
	call("agent", "search", "web_fetch", target.URL)
	fmt.Println("2) SSRF to cloud metadata (IMDS):")
	call("agent", "search", "web_fetch", "http://169.254.169.254/latest/meta-data/")
	fmt.Println("3) non-allow-listed host (default-deny):")
	call("agent", "search", "web_fetch", "https://evil.example/")
	fmt.Println("4) DNS-rebinding: allow-listed name resolving internal:")
	call("agent", "search", "web_fetch", "http://intranet.test/")
	fmt.Println("5) tool not permitted on this server:")
	call("agent", "search", "shell_exec", "")
	fmt.Println("6) unknown (non-allow-listed) MCP server:")
	call("agent", "rogue", "web_fetch", target.URL)
	fmt.Println("7) unauthorized caller:")
	call("attacker", "search", "web_fetch", target.URL)

	// The detonation chamber reached as a governed MCP tool: same gateway, same
	// audit; the interpreter's allowlist + argcheck gate each command.
	callArgv := func(argv ...string) {
		anyv := make([]any, len(argv))
		for i, a := range argv {
			anyv[i] = a
		}
		label := "agent -> search/sandbox_exec [" + strings.Join(argv, " ") + "]"
		out, err := gw.Call(context.Background(), gledger.NewTraceID(), "agent", "search", "sandbox_exec", map[string]any{"argv": anyv})
		if err != nil {
			fmt.Printf("  GATEWAY-BLOCKED  %s\n                   %v\n", label, err)
			return
		}
		fmt.Printf("  %s\n           %v\n", label, out)
	}
	fmt.Println("8) detonate an allow-listed command in the egress-denied MicroVM:")
	callArgv("uname", "-a")
	fmt.Println("9) non-allow-listed command (allowlist refuses before detonation):")
	callArgv("rm", "--recursive", "/")
	fmt.Println("10) shell-metacharacter argument (argcheck refuses before detonation):")
	callArgv("ls", "x; echo PWNED")

	// Egress broker: how an in-VM tool (vmfetch) reaches the network without the
	// guest having a NIC — every dial is gated by netpolicy on the host. Shown
	// here over TCP; in the VM the same client dials the host over vsock.
	bln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer bln.Close()
	go (&broker.Broker{Policy: policy}).Serve(bln)
	bdial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", bln.Addr().String())
	}
	bclient := broker.HTTPClient(bdial, 5*time.Second)
	fmt.Println("11) egress broker — allow-listed fetch from inside the VM:")
	if resp, err := bclient.Get(target.URL); err != nil {
		fmt.Printf("  BLOCKED  broker fetch %s\n           %v\n", target.URL, err)
	} else {
		resp.Body.Close()
		fmt.Printf("  ALLOWED  broker fetch %s -> HTTP %d\n", target.URL, resp.StatusCode)
	}
	fmt.Println("12) egress broker — SSRF to IMDS refused at the chokepoint:")
	if _, err := bclient.Get("http://169.254.169.254/latest/meta-data/"); err != nil {
		fmt.Printf("  BLOCKED  broker fetch IMDS\n           %v\n", err)
	}

	ok, n := audit.Verify()
	fmt.Printf("\naudit: chain_ok=%t records=%d\n", ok, n)
	return nil
}
