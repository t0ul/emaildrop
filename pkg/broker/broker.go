// Package broker is the egress broker that lets a tool run INSIDE the
// egress-denied MicroVM yet still reach the network, without giving the guest a
// NIC. The guest has no route of its own; when it needs the network it opens a
// vsock connection to this broker on the host and sends one line — the target
// host:port. The broker validates that target through netpolicy (the single
// egress authority: allowlist + DNS resolution + block loopback/private/IMDS +
// dial-pinning to the vetted IP), dials it, and then tunnels raw bytes. The
// guest speaks TLS/HTTP over the tunnel, so the host never parses the (untrusted)
// response — execution and content handling stay in the VM, egress stays a
// single audited chokepoint on the host.
//
// Wire protocol (one request per connection):
//
//	guest -> host:  "example.com:443\n"
//	host  -> guest: "OK\n"            then a raw byte tunnel
//	             or "ERR <reason>\n"  then close (policy refused the target)
//
// The transport is vsock in the real deployment, but the broker and its client
// are OS-independent and unit-tested on any platform over TCP / net.Pipe.
package broker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/t0ul/emaildrop/pkg/netpolicy"
)

// DefaultPort is the host vsock port the broker listens on for guest-initiated
// egress (distinct from the detonation daemon's 5000, which runs the other way).
const DefaultPort = 5001

// DefaultTimeout bounds one brokered dial+tunnel setup.
const DefaultTimeout = 20 * time.Second

// Broker runs on the host and gates guest egress through netpolicy.
type Broker struct {
	Policy  netpolicy.Policy
	Timeout time.Duration
	// Log, if set, receives one line per brokered target: the target, whether it
	// was allowed, and (on refusal) the reason. Never the tunneled bytes.
	Log func(target string, allowed bool, reason string)
}

func (b *Broker) timeout() time.Duration {
	if b.Timeout > 0 {
		return b.Timeout
	}
	return DefaultTimeout
}

// Serve accepts broker connections until the listener is closed.
func (b *Broker) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go b.ServeConn(conn)
	}
}

// ServeConn handles one guest connection: read the target, apply netpolicy, and
// either refuse or tunnel. netpolicy.DialContext does the real work — it
// resolves the host, refuses any internal address, and connects only to a vetted
// IP, so there is no rebinding window between the check and the dial.
func (b *Broker) ServeConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	target := strings.TrimSpace(line)
	if target == "" {
		fmt.Fprint(conn, "ERR empty target\n")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.timeout())
	defer cancel()

	up, err := b.Policy.DialContext(ctx, "tcp", target)
	if err != nil {
		if b.Log != nil {
			b.Log(target, false, err.Error())
		}
		fmt.Fprintf(conn, "ERR %s\n", err.Error())
		return
	}
	defer up.Close()
	if b.Log != nil {
		b.Log(target, true, "")
	}
	if _, err := io.WriteString(conn, "OK\n"); err != nil {
		return
	}

	// Tunnel. Read the guest side from br (not conn) so any bytes buffered after
	// the target line are not lost.
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, br); done <- struct{}{} }()
	go func() { io.Copy(conn, up); done <- struct{}{} }()
	<-done
}

// DialFunc opens a fresh connection to the broker. In the guest it is a vsock
// dial to the host CID; in host-side development it is a plain TCP dial.
type DialFunc func(ctx context.Context) (net.Conn, error)

// HTTPClient returns an http.Client whose every dial is brokered: it opens a
// broker connection, sends the CONNECT target, waits for OK, then runs HTTP/TLS
// over the tunnel. All egress policy is enforced host-side by the broker, so the
// guest needs no allowlist of its own and no network stack beyond vsock.
func HTTPClient(dial DialFunc, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return DialTarget(ctx, dial, addr)
			},
		},
	}
}

// DialTarget opens a brokered connection to addr ("host:port") and returns a
// net.Conn ready for the caller to speak its own protocol (TLS/HTTP) over.
func DialTarget(ctx context.Context, dial DialFunc, addr string) (net.Conn, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("broker: bad target %q: %w", addr, err)
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "%s\n", addr); err != nil {
		conn.Close()
		return nil, err
	}
	r := bufio.NewReader(conn)
	status, err := r.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("broker: no status for %q: %w", addr, err)
	}
	status = strings.TrimSpace(status)
	if status != "OK" {
		conn.Close()
		return nil, fmt.Errorf("broker refused %q: %s", addr, strings.TrimPrefix(status, "ERR "))
	}
	return &bufConn{Conn: conn, r: r}, nil
}

// bufConn preserves any bytes the status-line reader buffered past "OK\n".
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }
