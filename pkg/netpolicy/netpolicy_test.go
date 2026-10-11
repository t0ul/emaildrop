package netpolicy_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/pkg/netpolicy"
)

// fakeDNS maps hostnames to IPs so Check is deterministic without real DNS.
func fakeDNS(m map[string]string) func(string) ([]net.IP, error) {
	return func(host string) ([]net.IP, error) {
		if s, ok := m[host]; ok {
			return []net.IP{net.ParseIP(s)}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
}

func TestAllowsAllowlistedPublicHost(t *testing.T) {
	p := netpolicy.Policy{Allow: []string{"api.example.com"}, Resolve: fakeDNS(map[string]string{"api.example.com": "93.184.216.34"})}
	if err := p.Check("https://api.example.com/v1/search?q=x"); err != nil {
		t.Fatalf("allowlisted public host should pass, got %v", err)
	}
}

func TestAllowsSubdomainOfAllowlistedDomain(t *testing.T) {
	p := netpolicy.Policy{
		Allow:   []string{"schools.nyc.gov"},
		Resolve: fakeDNS(map[string]string{"www.schools.nyc.gov": "93.184.216.34", "schools.nyc.gov": "93.184.216.34", "evilschools.nyc.gov": "93.184.216.34"}),
	}
	if err := p.Check("https://www.schools.nyc.gov/menus"); err != nil {
		t.Fatalf("subdomain of an allowlisted domain should pass, got %v", err)
	}
	if err := p.Check("https://schools.nyc.gov/"); err != nil {
		t.Fatalf("the domain itself should pass, got %v", err)
	}
	if err := p.Check("https://evilschools.nyc.gov/"); err == nil {
		t.Fatal("a look-alike sibling domain must NOT pass")
	}
}

func TestBlocksIMDS(t *testing.T) {
	p := netpolicy.Policy{Allow: []string{"metadata"}, Resolve: fakeDNS(map[string]string{"metadata": "169.254.169.254"})}
	if err := p.Check("http://metadata/latest/meta-data/iam/security-credentials/"); !errors.Is(err, netpolicy.ErrBlockedIP) {
		t.Fatalf("IMDS link-local must be blocked, got %v", err)
	}
}

func TestBlocksPrivateAndLoopback(t *testing.T) {
	p := netpolicy.Policy{Allow: []string{"h"}}
	p.Resolve = fakeDNS(map[string]string{"h": "10.0.0.5"})
	if err := p.Check("http://h/"); !errors.Is(err, netpolicy.ErrBlockedIP) {
		t.Fatalf("private IP must be blocked, got %v", err)
	}
	p.Resolve = fakeDNS(map[string]string{"h": "127.0.0.1"})
	if err := p.Check("http://h/"); !errors.Is(err, netpolicy.ErrBlockedIP) {
		t.Fatalf("loopback must be blocked by default, got %v", err)
	}
	p.AllowLoopback = true
	if err := p.Check("http://h/"); err != nil {
		t.Fatalf("loopback should pass when AllowLoopback set, got %v", err)
	}
}

func TestBlocksCGNATandMulticast(t *testing.T) {
	for _, ip := range []string{"100.64.0.1", "198.18.0.5", "224.0.0.1", "255.255.255.255"} {
		p := netpolicy.Policy{Allow: []string{"h"}, Resolve: fakeDNS(map[string]string{"h": ip})}
		if err := p.Check("http://h/"); !errors.Is(err, netpolicy.ErrBlockedIP) {
			t.Errorf("%s must be blocked, got %v", ip, err)
		}
	}
}

func TestDefaultDenyNotAllowlisted(t *testing.T) {
	p := netpolicy.Policy{Allow: []string{"good.com"}, Resolve: fakeDNS(map[string]string{"evil.com": "93.184.216.34"})}
	if err := p.Check("https://evil.com/"); !errors.Is(err, netpolicy.ErrNotAllowlisted) {
		t.Fatalf("non-allowlisted host must be denied, got %v", err)
	}
}

func TestRejectsNonHTTPScheme(t *testing.T) {
	p := netpolicy.Policy{Allow: []string{"x"}}
	if err := p.Check("file:///etc/passwd"); !errors.Is(err, netpolicy.ErrScheme) {
		t.Fatalf("non-http scheme must be rejected, got %v", err)
	}
}

func TestBlocksDNSRebinding(t *testing.T) {
	// Host is allowlisted but resolves to an internal IP — the rebinding attack.
	p := netpolicy.Policy{Allow: []string{"good.test"}, Resolve: fakeDNS(map[string]string{"good.test": "10.1.2.3"})}
	if err := p.Check("https://good.test/"); !errors.Is(err, netpolicy.ErrBlockedIP) {
		t.Fatalf("allowlisted host resolving internal must be blocked (rebinding), got %v", err)
	}
}

// TestDialTimeEnforcement proves the authoritative control: the HTTP client
// dials only the IP the policy vetted at connect time, against a LOCAL test
// server (never the public internet).
func TestDialTimeEnforcement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	// srv.URL is http://127.0.0.1:PORT; address the allow-listed name on that port.
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")

	// Allowed: "ok.test" resolves to the loopback test server -> connects.
	allow := netpolicy.Policy{
		Allow: []string{"ok.test"}, AllowLoopback: true,
		Resolve: fakeDNS(map[string]string{"ok.test": "127.0.0.1"}),
	}
	resp, err := allow.HTTPClient(2 * time.Second).Get("http://ok.test:" + port + "/")
	if err != nil {
		t.Fatalf("allow-listed loopback target should connect: %v", err)
	}
	resp.Body.Close()

	// Rebinding: an allow-listed name resolving to an internal IP is refused at
	// dial — the connection is never made.
	rebind := netpolicy.Policy{
		Allow:   []string{"ok.test"},
		Resolve: fakeDNS(map[string]string{"ok.test": "10.0.0.9"}),
	}
	if _, err := rebind.HTTPClient(2 * time.Second).Get("http://ok.test:" + port + "/"); err == nil {
		t.Fatal("dial to an internal IP must be refused (rebinding bypass)")
	}
}

// TestRedirectToInternalBlocked proves a 302 to an internal host is refused
// (redirect-based SSRF), using only local servers.
func TestRedirectToInternalBlocked(t *testing.T) {
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://metadata.test/latest/", http.StatusFound)
	}))
	defer redir.Close()
	port := strings.TrimPrefix(redir.URL, "http://127.0.0.1:")

	p := netpolicy.Policy{
		Allow: []string{"ok.test"}, AllowLoopback: true,
		Resolve: fakeDNS(map[string]string{"ok.test": "127.0.0.1", "metadata.test": "169.254.169.254"}),
	}
	// The first hop is allowed; the redirect target (metadata.test / IMDS) is not.
	if _, err := p.HTTPClient(2 * time.Second).Get("http://ok.test:" + port + "/"); err == nil {
		t.Fatal("redirect to an internal/non-vetted host must be blocked")
	}
}
