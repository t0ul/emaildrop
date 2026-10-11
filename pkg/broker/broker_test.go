package broker_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/pkg/broker"
	"github.com/t0ul/emaildrop/pkg/netpolicy"
)

// startBroker runs a broker over TCP (standing in for vsock) and returns a
// DialFunc that reaches it, plus a cleanup.
func startBroker(t *testing.T, pol netpolicy.Policy) (broker.DialFunc, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &broker.Broker{Policy: pol, Timeout: 3 * time.Second}
	go b.Serve(ln)
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
	return dial, func() { ln.Close() }
}

func TestBrokerTunnelsAllowedTarget(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello from upstream"))
	}))
	defer target.Close()

	dial, stop := startBroker(t, netpolicy.Policy{Allow: []string{"127.0.0.1"}, AllowLoopback: true})
	defer stop()

	client := broker.HTTPClient(dial, 5*time.Second)
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("brokered GET failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from upstream" {
		t.Fatalf("got %q", body)
	}
}

func TestBrokerRefusesNonAllowlisted(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("should never be reached"))
	}))
	defer target.Close()

	// Default-deny policy: loopback is not allowlisted.
	dial, stop := startBroker(t, netpolicy.Policy{})
	defer stop()

	client := broker.HTTPClient(dial, 5*time.Second)
	_, err := client.Get(target.URL)
	if err == nil {
		t.Fatal("expected the broker to refuse a non-allowlisted target")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected a broker refusal, got %v", err)
	}
}

func TestBrokerRefusesInternalRebind(t *testing.T) {
	// An allowlisted name that resolves to an internal address must still be
	// refused (the broker resolves and dials the vetted IP itself).
	pol := netpolicy.Policy{
		Allow: []string{"intranet.test"},
		Resolve: func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil // IMDS
		},
	}
	dial, stop := startBroker(t, pol)
	defer stop()

	client := broker.HTTPClient(dial, 5*time.Second)
	_, err := client.Get("http://intranet.test/latest/meta-data/")
	if err == nil {
		t.Fatal("expected refusal of a name resolving to an internal address")
	}
}
