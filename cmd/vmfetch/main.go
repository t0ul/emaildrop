// Command vmfetch is the in-VM fetch tool: it runs INSIDE the egress-denied
// MicroVM (detonated via sandbox_exec) and fetches a URL through the host egress
// broker over vsock — the guest has no network of its own. TLS and response
// handling happen here, in the guest, so untrusted bytes are parsed off the
// host; the host only enforces egress policy (netpolicy) at the broker.
//
//	vmfetch <url>        # vsock to the host broker (real deployment)
//	BROKER_TCP=host:port vmfetch <url>   # TCP to the broker (host-side dev/tests)
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/t0ul/emaildrop/pkg/broker"
	"github.com/t0ul/emaildrop/pkg/sandbox"
)

const maxBody = 64 * 1024

func main() {
	if len(os.Args) < 2 || os.Args[1] == "" {
		fmt.Fprintln(os.Stderr, "usage: vmfetch <url>")
		os.Exit(2)
	}
	url := os.Args[1]

	dial := func(ctx context.Context) (net.Conn, error) {
		if addr := os.Getenv("BROKER_TCP"); addr != "" {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}
		return sandbox.DialHost(broker.DefaultPort)
	}

	client := broker.HTTPClient(dial, 15*time.Second)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vmfetch: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	// First line is the status; the rest is the (bounded) body.
	fmt.Printf("HTTP %d\n%s", resp.StatusCode, body)
}
