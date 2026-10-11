package sandbox_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/pkg/sandbox"
)

func TestRunCommandCapturesStdout(t *testing.T) {
	d := sandbox.NewDaemon()
	if out := d.RunCommand("echo hello"); out != "hello" {
		t.Fatalf("got %q, want %q", out, "hello")
	}
}

func TestRunCommandMergesStderr(t *testing.T) {
	d := sandbox.NewDaemon()
	out := d.RunCommand("echo out; echo boom 1>&2")
	if !strings.Contains(out, "out") || !strings.Contains(out, "[stderr]") || !strings.Contains(out, "boom") {
		t.Fatalf("stderr not merged: %q", out)
	}
}

func TestRunCommandTimeout(t *testing.T) {
	d := &sandbox.Daemon{Timeout: 150 * time.Millisecond}
	start := time.Now()
	out := d.RunCommand("sleep 5")
	if !strings.Contains(out, "timed out") {
		t.Fatalf("expected timeout message, got %q", out)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout did not kill the command promptly")
	}
}

func TestRunArgvNoShell(t *testing.T) {
	d := sandbox.NewDaemon()
	// A single argv element carrying shell metacharacters must be treated as one
	// literal argument — no shell splits or interprets it.
	out := d.RunArgv([]string{"echo", "a;b|c&d"})
	if out != "a;b|c&d" {
		t.Fatalf("argv not passed literally (shell interpreted it?): %q", out)
	}
}

func TestRunArgvEphemeralCwd(t *testing.T) {
	d := sandbox.NewDaemon()
	// Each detonation runs in its own fresh temp dir, so two runs never share a
	// working directory.
	a := d.RunArgv([]string{"pwd"})
	b := d.RunArgv([]string{"pwd"})
	if a == "" || a == b {
		t.Fatalf("expected distinct per-detonation cwds, got %q and %q", a, b)
	}
}

func TestExecutePrefersArgv(t *testing.T) {
	d := sandbox.NewDaemon()
	r := d.Execute(sandbox.Request{Argv: []string{"echo", "argv-path"}, Command: "echo command-path", TraceID: "t"})
	if r.Output != "argv-path" {
		t.Fatalf("Argv should take precedence over Command, got %q", r.Output)
	}
}

func TestExecuteNoCommand(t *testing.T) {
	d := sandbox.NewDaemon()
	r := d.Execute(sandbox.Request{TraceID: "t"})
	if !strings.Contains(r.Output, "no command provided") || r.TraceID != "t" {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestExecuteLogsRequestOnly(t *testing.T) {
	var loggedCmd, loggedTrace string
	d := &sandbox.Daemon{Timeout: sandbox.DefaultTimeout, Log: func(trace, cmd string) {
		loggedTrace, loggedCmd = trace, cmd
	}}
	d.Execute(sandbox.Request{Command: "echo secret-output", TraceID: "t7"})
	if loggedTrace != "t7" || loggedCmd != "echo secret-output" {
		t.Fatalf("log hook got trace=%q cmd=%q", loggedTrace, loggedCmd)
	}
}

// parseHTTPResponseBody splits off the HTTP head and returns the JSON body.
func parseHTTPResponseBody(t *testing.T, raw []byte) sandbox.Response {
	t.Helper()
	_, body, ok := strings.Cut(string(raw), "\r\n\r\n")
	if !ok {
		t.Fatalf("no header/body split in response: %q", raw)
	}
	var resp sandbox.Response
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("bad JSON body %q: %v", body, err)
	}
	return resp
}

func TestServeConnProtocolRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	d := sandbox.NewDaemon()
	go d.ServeConn(server)

	body := `{"command":"echo hi","trace_id":"t9"}`
	req := fmt.Sprintf("POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	go func() { _, _ = io.WriteString(client, req) }()

	raw, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	resp := parseHTTPResponseBody(t, raw)
	if resp.Output != "hi" || resp.TraceID != "t9" {
		t.Fatalf("round trip got %+v", resp)
	}
}

func TestServeListenerOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d := sandbox.NewDaemon()
	go d.ServeListener(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := `{"command":"echo tcp-ok","trace_id":"tcp1"}`
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s", len(body), body)

	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	resp := parseHTTPResponseBody(t, raw)
	if resp.Output != "tcp-ok" || resp.TraceID != "tcp1" {
		t.Fatalf("tcp round trip got %+v", resp)
	}
}
