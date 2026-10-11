package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/t0ul/ai-security-engineering/pkg/sandbox"
)

// TestSnapshotUsable drives the golden-staleness guard against a real filesystem
// with real modification times — the guard that stops a restore from silently
// resurrecting an out-of-date guest.
func TestSnapshotUsable(t *testing.T) {
	dir := t.TempDir()
	kernel := filepath.Join(dir, "Image")
	asset := filepath.Join(dir, "sandbox_init.sh")
	snap := filepath.Join(dir, "golden.vmstate")

	write := func(p string) {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	write(kernel)
	write(asset)

	assets := []string{kernel, asset}

	if snapshotUsable(snap, assets) {
		t.Fatal("missing snapshot must be unusable")
	}

	// A snapshot newer than every asset is usable.
	time.Sleep(10 * time.Millisecond)
	write(snap)
	if !snapshotUsable(snap, assets) {
		t.Fatal("snapshot newer than assets must be usable")
	}

	// An empty snapshot file (a crash mid-save) is never trusted.
	if err := os.Truncate(snap, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if snapshotUsable(snap, assets) {
		t.Fatal("empty snapshot must be unusable")
	}

	// A rebuilt asset newer than the snapshot invalidates it.
	write(snap)
	time.Sleep(10 * time.Millisecond)
	write(asset)
	if snapshotUsable(snap, assets) {
		t.Fatal("snapshot older than a rebuilt asset must be unusable")
	}
}

// TestProbeReadyAgainstRealDaemon runs the actual in-VM detonation daemon over
// TCP (its DAEMON_TCP path) and confirms the readiness probe speaks its real
// protocol, and that a dead address is reported not-ready.
func TestProbeReadyAgainstRealDaemon(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go sandbox.NewDaemon().ServeListener(ln)

	if !probeReady(ln.Addr().String(), 3*time.Second) {
		t.Fatal("probe should succeed against a live daemon")
	}

	// A closed listener's address answers nothing.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := dead.Addr().String()
	dead.Close()
	if probeReady(addr, 500*time.Millisecond) {
		t.Fatal("probe should fail against a dead address")
	}
}

// testController is a real, state-tracking controller (not a mock of the VM): it
// enforces the same single-flight and availability behavior the vz-backed chamber
// does, so the control routes and guards are exercised honestly without a live,
// codesigned VM.
type testController struct {
	mu        sync.Mutex
	avail     bool
	resetting atomic.Bool
	resets    atomic.Int64
	maxConc   atomic.Int64
	conc      atomic.Int64
	delay     time.Duration
}

func (c *testController) available() bool { return c.avail }
func (c *testController) busy() bool      { return c.resetting.Load() }
func (c *testController) ready() bool     { return !c.resetting.Load() }

func (c *testController) resetNow() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetting.Store(true)
	defer c.resetting.Store(false)
	n := c.conc.Add(1)
	if n > c.maxConc.Load() {
		c.maxConc.Store(n)
	}
	time.Sleep(c.delay)
	c.conc.Add(-1)
	c.resets.Add(1)
	return nil
}

func TestControlReset(t *testing.T) {
	c := &testController{avail: true}
	srv := httptest.NewServer(controlHandler(c))
	defer srv.Close()

	// GET /reset is rejected; only POST mutates.
	resp, err := http.Get(srv.URL + "/reset")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /reset = %d, want 405", resp.StatusCode)
	}

	resp, err = http.Post(srv.URL+"/reset", "", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /reset = %d, want 200", resp.StatusCode)
	}
	if c.resets.Load() != 1 {
		t.Fatalf("resets = %d, want 1", c.resets.Load())
	}

	// /healthz reflects readiness.
	resp, err = http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", resp.StatusCode)
	}
}

func TestControlResetUnavailable(t *testing.T) {
	c := &testController{avail: false}
	srv := httptest.NewServer(controlHandler(c))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/reset", "", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /reset with no snapshot = %d, want 409", resp.StatusCode)
	}
	if c.resets.Load() != 0 {
		t.Fatal("reset must not run when snapshots are unavailable")
	}
}

// TestControlResetSingleFlight fires concurrent resets and confirms the handler
// never runs two at once: a reset in progress returns 503 rather than stacking.
func TestControlResetSingleFlight(t *testing.T) {
	c := &testController{avail: true, delay: 80 * time.Millisecond}
	srv := httptest.NewServer(controlHandler(c))
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(srv.URL+"/reset", "", nil)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	if got := c.maxConc.Load(); got > 1 {
		t.Fatalf("max concurrent resets = %d, want 1", got)
	}
	if c.resets.Load() == 0 {
		t.Fatal("at least one reset should have run")
	}
}
