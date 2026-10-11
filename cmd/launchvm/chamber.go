package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Code-Hex/vz/v3"
	"github.com/t0ul/emaildrop/internal/modelserve"
)

// errNoSnapshot is returned by reset when save/restore is unavailable for this
// configuration (validator rejected it, or snapshotting is disabled).
var errNoSnapshot = errors.New("golden snapshot unavailable")

// chamber wraps the detonation MicroVM with Apple Virtualization save/restore so
// the guest can be reset to a pristine, already-booted state instead of being
// cold-booted (slow) or reused indefinitely (state drift).
//
// The guest already runs each command in a throwaway working directory, so
// per-command filesystem bleed is handled in the daemon. A golden-snapshot reset
// is the stronger guarantee: a fresh kernel and userland per reset, defeating a
// detonation that persists outside its temp dir, leaves a lingering process, or
// drifts daemon/kernel state over a long-lived VM.
//
// reset and the /reset control are mutually exclusive with in-flight bridge
// connections via gate: a detonation holds it shared (RLock); a reset holds it
// exclusive (Lock).
type chamber struct {
	vm       *vz.VirtualMachine
	snapshot string // golden snapshot path; "" disables snapshotting
	bridge   string // host loopback addr the vsock bridge listens on (for readiness probes)
	savable  bool   // Apple validateSaveRestoreSupport passed for this config
	reset    bool   // -reset-each: restore the golden before each detonation

	gate      sync.RWMutex // RLock per detonation; Lock for reset/save
	dirty     atomic.Bool  // a detonation has run since the last restore
	resetting atomic.Bool  // a reset or save is in progress
}

// available reports whether snapshot-backed operations can run at all.
func (c *chamber) available() bool { return c.savable && c.snapshot != "" }

// busy reports whether a reset or save is currently in progress.
func (c *chamber) busy() bool { return c.resetting.Load() }

// ready reports whether the in-VM detonation daemon answers on the bridge and no
// reset is mid-flight.
func (c *chamber) ready() bool {
	if c.resetting.Load() {
		return false
	}
	return probeReady(c.bridge, 1500*time.Millisecond)
}

// saveGolden pauses the running VM, writes the golden snapshot atomically, and
// resumes. It is called once after a cold boot reaches readiness so the next
// launch takes the restore fast path and /reset has a target. A save failure
// (e.g. VZErrorInternal, which can happen even when the validator passed) is
// returned; the VM is always resumed.
func (c *chamber) saveGolden() error {
	if !c.available() {
		return errNoSnapshot
	}
	c.gate.Lock()
	defer c.gate.Unlock()
	c.resetting.Store(true)
	defer c.resetting.Store(false)

	if err := c.vm.Pause(); err != nil {
		return fmt.Errorf("pause: %w", err)
	}
	if err := waitState(c.vm, vz.VirtualMachineStatePaused, 15*time.Second); err != nil {
		return err
	}
	tmp := c.snapshot + ".tmp"
	saveErr := c.vm.SaveMachineStateToPath(tmp)
	// Resume regardless of the save outcome so a failed snapshot never strands
	// the chamber paused.
	if err := c.vm.Resume(); err != nil {
		return fmt.Errorf("resume after save: %w", err)
	}
	_ = waitState(c.vm, vz.VirtualMachineStateRunning, 15*time.Second)
	if saveErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("save: %w", saveErr)
	}
	// Rename last: a crash mid-save never leaves a half-written golden that
	// snapshotUsable would later trust.
	return os.Rename(tmp, c.snapshot)
}

// restoreGolden performs a destructive stop, restores the golden snapshot, and
// resumes, then waits for the daemon to answer again. The caller must hold gate
// exclusively.
func (c *chamber) restoreGolden() error {
	if !c.available() {
		return errNoSnapshot
	}
	if err := c.vm.Stop(); err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	if err := waitState(c.vm, vz.VirtualMachineStateStopped, 15*time.Second); err != nil {
		return err
	}
	if err := c.vm.RestoreMachineStateFromURL(c.snapshot); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if err := waitState(c.vm, vz.VirtualMachineStatePaused, 15*time.Second); err != nil {
		return err
	}
	if err := c.vm.Resume(); err != nil {
		return fmt.Errorf("resume: %w", err)
	}
	if err := waitState(c.vm, vz.VirtualMachineStateRunning, 15*time.Second); err != nil {
		return err
	}
	if !probeReady(c.bridge, 15*time.Second) {
		return errors.New("daemon not ready after restore")
	}
	return nil
}

// resetNow restores the golden snapshot unconditionally. Used by the /reset
// control for an operator-requested pristine chamber.
func (c *chamber) resetNow() error {
	if !c.available() {
		return errNoSnapshot
	}
	c.gate.Lock()
	defer c.gate.Unlock()
	c.resetting.Store(true)
	defer c.resetting.Store(false)
	if err := c.restoreGolden(); err != nil {
		return err
	}
	c.dirty.Store(false)
	return nil
}

// resetIfDirty restores the golden snapshot before the next detonation when
// -reset-each is set and a detonation has run since the last reset. A concurrent
// caller that finds the chamber already clean returns immediately.
func (c *chamber) resetIfDirty() {
	if !c.reset || !c.available() || !c.dirty.Load() {
		return
	}
	c.gate.Lock()
	defer c.gate.Unlock()
	if !c.dirty.Load() { // another conn reset it while we waited for the lock
		return
	}
	c.resetting.Store(true)
	defer c.resetting.Store(false)
	if err := c.restoreGolden(); err != nil {
		os.Stdout.Write([]byte("\rreset-each: restore failed: " + err.Error() + "\r\n"))
		return
	}
	c.dirty.Store(false)
}

// handleConn bridges one host TCP connection to the guest's detonation daemon
// over vsock. With -reset-each it first restores the golden snapshot if a prior
// detonation dirtied the chamber, then marks the chamber dirty for the next one.
func (c *chamber) handleConn(tcpConn net.Conn) {
	defer tcpConn.Close()
	c.resetIfDirty()

	c.gate.RLock()
	defer c.gate.RUnlock()

	devices := c.vm.SocketDevices()
	if len(devices) == 0 {
		return
	}
	vsockConn, err := devices[0].Connect(vsockPort)
	if err != nil {
		return
	}
	defer vsockConn.Close()
	c.dirty.Store(true)

	done := make(chan struct{}, 2)
	go func() { io.Copy(vsockConn, tcpConn); done <- struct{}{} }()
	go func() { io.Copy(tcpConn, vsockConn); done <- struct{}{} }()
	<-done
}

// controller is the chamber behavior the control server needs, factored out so
// the HTTP routing and guards are testable without a live, codesigned VM.
type controller interface {
	resetNow() error
	ready() bool
	busy() bool
	available() bool
}

// controlHandler builds the loopback control routes: GET /healthz for readiness
// and POST /reset to restore the golden snapshot on demand.
func controlHandler(c controller) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if c.ready() {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "ok\n")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "not ready\n")
	})
	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !c.available() {
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, "snapshot unavailable for this configuration\n")
			return
		}
		if c.busy() {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "reset already in progress\n")
			return
		}
		if err := c.resetNow(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "reset failed: %v\n", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "reset ok\n")
	})
	return mux
}

// serveControl runs the control server on a loopback address, reclaiming the
// port from a stale launchvm the same way the vsock bridge does.
func (c *chamber) serveControl(addr string) {
	if addr == "" {
		return
	}
	if _, p, perr := net.SplitHostPort(addr); perr == nil {
		if port, aerr := strconv.Atoi(p); aerr == nil {
			modelserve.ReclaimPort(port, os.Stdout)
		}
	}
	srv := &http.Server{Addr: addr, Handler: controlHandler(c)}
	os.Stdout.Write([]byte("\r\ncontrol up: " + addr + " (GET /healthz, POST /reset)\r\n"))
	if err := srv.ListenAndServe(); err != nil {
		os.Stdout.Write([]byte("\rcontrol server: " + err.Error() + "\r\n"))
	}
}

// probeReady dials the vsock bridge and sends an empty detonation request; a
// well-formed HTTP 200 means the in-VM daemon is accepting commands. It reuses
// the daemon's real protocol (an empty body yields "no command provided"), so no
// command actually runs.
func probeReady(bridgeAddr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if httpPing(bridgeAddr) {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

func httpPing(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	const body = "{}"
	req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: vm\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	if _, err := io.WriteString(conn, req); err != nil {
		return false
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.Contains(line, " 200")
}

// waitState blocks until the VM reaches target, the VM enters an error state, or
// the timeout elapses.
func waitState(vm *vz.VirtualMachine, target vz.VirtualMachineState, timeout time.Duration) error {
	if vm.State() == target {
		return nil
	}
	notify := vm.StateChangedNotify()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case s := <-notify:
			if s == target {
				return nil
			}
			if s == vz.VirtualMachineStateError {
				return errors.New("vm entered error state")
			}
		case <-timer.C:
			return fmt.Errorf("timeout waiting for vm state %v (now %v)", target, vm.State())
		}
	}
}

// snapshotUsable reports whether the golden snapshot exists, is non-empty, and is
// newer than every asset the VM boots from. A snapshot older than any asset is
// stale: restoring it would silently resurrect an old guest or detonationd — the
// same footgun as booting unrebuilt guest binaries — so it is ignored and rebuilt.
func snapshotUsable(path string, assets []string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return false
	}
	snap := fi.ModTime()
	for _, a := range assets {
		if newestMod(a).After(snap) {
			return false
		}
	}
	return true
}

// newestMod returns the newest modification time at or under path (walking it if
// it is a directory). A missing path contributes the zero time.
func newestMod(path string) time.Time {
	var newest time.Time
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return newest
}
