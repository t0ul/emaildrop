// Command launchvm boots the PUI PUI Linux MicroVM (Apple Virtualization
// Framework) that serves as the detonation chamber, and bridges host
// 127.0.0.1:5000 to the guest's vsock:5000 so the control plane can reach the
// in-VM detonation daemon with no IP route into the host.
//
// The Apple Virtualization Framework requires the running binary to be codesigned
// with the com.apple.security.virtualization entitlement, so `go run` fails. Build
// then sign:
//
//	go build -o launchvm ./cmd/launchvm
//	codesign --entitlements set-up/entitlements.plist -s - --force launchvm
//	./launchvm            # -dir defaults to set-up/vm-assets
//
// The in-guest bring-up runs sandbox_init.sh, which launches the static Go
// cmd/detonationd (cross-built into the shared assets mount by prepareassets) on
// vsock:5000 — no python in the guest.
//
// Snapshot/restore (macOS 14+, same virtualization entitlement): with -snapshot
// (default), launchvm captures a golden VM snapshot once the daemon is ready
// after a cold boot, then fast-boots later launches by restoring it instead of
// cold-booting the kernel and scripting the console. The golden is invalidated
// automatically when any boot asset is newer than it. The loopback control
// endpoint (-control) exposes GET /healthz and POST /reset, where /reset restores
// the golden for a pristine, already-booted guest; -reset-each does that reset
// before every detonation. If Apple's validateSaveRestoreSupport rejects this
// configuration (or the save itself fails), launchvm logs it and runs exactly as
// it did before, cold-booting with no snapshot.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Code-Hex/vz/v3"
	"github.com/t0ul/ai-security-engineering/internal/modelserve"
	"github.com/t0ul/ai-security-engineering/pkg/broker"
	"github.com/t0ul/ai-security-engineering/pkg/netpolicy"
	"golang.org/x/term"
)

const vsockPort = 5000 // guest vsock port where detonationd listens (internal to the VM)

func main() {
	dir := flag.String("dir", "set-up/vm-assets", "MicroVM assets directory")
	allow := flag.String("allow", "", "comma-separated egress allowlist for the in-VM broker (default: deny all)")
	bridge := flag.String("bridge", "127.0.0.1:5000", "host address for the guest-vsock command bridge; change if :5000 is taken (macOS AirPlay Receiver owns it) and pass the matching -microvm to cmd/webapp")
	snapshot := flag.Bool("snapshot", true, "save a golden VM snapshot after bring-up and fast-boot by restoring it (Apple Virtualization save/restore, macOS 14+)")
	resetEach := flag.Bool("reset-each", false, "restore the golden snapshot before each detonation for a pristine guest per command (adds restore latency)")
	control := flag.String("control", "127.0.0.1:5002", "loopback control endpoint for GET /healthz and POST /reset; empty to disable")
	flag.Parse()

	var allowHosts []string
	for _, h := range strings.Split(*allow, ",") {
		if h = strings.TrimSpace(h); h != "" {
			allowHosts = append(allowHosts, h)
		}
	}
	egressPolicy := netpolicy.Policy{Allow: allowHosts}

	kernelPath := filepath.Join(*dir, "Image")
	initrdPath := filepath.Join(*dir, "initramfs.cpio.gz")

	bootLoader, err := vz.NewLinuxBootLoader(kernelPath, vz.WithCommandLine("console=hvc0"), vz.WithInitrd(initrdPath))
	if err != nil {
		log.Fatalf("launchvm: bootloader: %v", err)
	}
	config, err := vz.NewVirtualMachineConfiguration(bootLoader, 4, 2*1024*1024*1024)
	if err != nil {
		log.Fatalf("launchvm: vm config: %v", err)
	}

	vmReader, vmWriter, _ := os.Pipe()
	hostReader, hostWriter, _ := os.Pipe()

	serialAttachment, err := vz.NewFileHandleSerialPortAttachment(vmReader, hostWriter)
	if err != nil {
		log.Fatalf("launchvm: serial attachment: %v", err)
	}
	consoleConfig, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(serialAttachment)
	if err != nil {
		log.Fatalf("launchvm: console config: %v", err)
	}
	config.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{consoleConfig})

	sharedDir, err := vz.NewSharedDirectory(*dir, true)
	if err != nil {
		log.Fatalf("launchvm: shared dir: %v", err)
	}
	dirShare, err := vz.NewSingleDirectoryShare(sharedDir)
	if err != nil {
		log.Fatalf("launchvm: dir share: %v", err)
	}
	fsConfig, err := vz.NewVirtioFileSystemDeviceConfiguration("assets")
	if err != nil {
		log.Fatalf("launchvm: fs config: %v", err)
	}
	fsConfig.SetDirectoryShare(dirShare)
	config.SetDirectorySharingDevicesVirtualMachineConfiguration([]vz.DirectorySharingDeviceConfiguration{fsConfig})

	// NO network device is attached on purpose: the detonation chamber is
	// egress-denied. A command detonated inside the guest has no interface, no
	// route, and no DNS, so it cannot beacon or exfiltrate. Any network a tool
	// legitimately needs goes out through the host netpolicy proxy (allowlist +
	// dial-pinned + no-IMDS), never the guest's own stack. vsock below is the one
	// and only channel in or out.

	// virtio-vsock: the ONLY channel into the detonation chamber.
	vsockConfig, err := vz.NewVirtioSocketDeviceConfiguration()
	if err != nil {
		log.Fatalf("launchvm: vsock config: %v", err)
	}
	config.SetSocketDevicesVirtualMachineConfiguration([]vz.SocketDeviceConfiguration{vsockConfig})

	if valid, err := config.Validate(); !valid || err != nil {
		log.Fatalf("launchvm: invalid vm config: %v", err)
	}

	// Decide up front whether this configuration can be snapshotted. The verdict
	// is authoritative only on the running Mac: Apple's validator rejects some
	// device sets (notably graphics devices, which this headless VM has none of),
	// and a save can still fail at runtime even when the validator passes. Either
	// way launchvm degrades to the plain cold-boot path.
	snapshotPath := ""
	savable := false
	if *snapshot {
		snapshotPath = filepath.Join(*dir, "golden.vmstate")
		if ok, verr := config.ValidateSaveRestoreSupport(); ok && verr == nil {
			savable = true
		} else {
			log.Printf("launchvm: snapshot/restore unsupported for this configuration (%v); continuing without snapshots", verr)
			snapshotPath = ""
		}
	}

	vm, err := vz.NewVirtualMachine(config)
	if err != nil {
		log.Fatalf("launchvm: instantiate: %v", err)
	}

	ch := &chamber{vm: vm, snapshot: snapshotPath, bridge: *bridge, savable: savable, reset: *resetEach}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalf("launchvm: raw terminal: %v", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	assets := []string{kernelPath, initrdPath, filepath.Join(*dir, "alpine-root"), filepath.Join(*dir, "sandbox_init.sh")}
	restored := false
	if savable && snapshotUsable(snapshotPath, assets) {
		os.Stdout.Write([]byte("\r\nRestoring PUI PUI Linux MicroVM from golden snapshot...\r\n"))
		if rerr := ch.restoreBoot(); rerr != nil {
			os.Stdout.Write([]byte("\rrestore failed (" + rerr.Error() + "); cold booting\r\n"))
		} else {
			restored = true
		}
	}

	if restored {
		// The restored guest is already past login with detonationd running, so
		// the console only needs surfacing and stdin wiring — no login scripting.
		go copyConsole(hostReader)
		go io.Copy(vmWriter, os.Stdin)
	} else {
		os.Stdout.Write([]byte("\r\nBooting PUI PUI Linux MicroVM...\r\n"))
		if err := vm.Start(); err != nil {
			term.Restore(int(os.Stdin.Fd()), oldState)
			log.Fatalf("\r\nlaunchvm: start: %v\r\n", err)
		}
		go driveConsole(hostReader, vmWriter)
	}

	go startVsockBridge(ch, *bridge)
	go startEgressBroker(vm, egressPolicy)
	go ch.serveControl(*control)

	// After a cold boot, capture the golden snapshot once the daemon answers so
	// the next launch takes the restore fast path and /reset has a target.
	if !restored && savable {
		go func() {
			if !probeReady(*bridge, 90*time.Second) {
				os.Stdout.Write([]byte("\rdaemon not ready in time; skipping golden snapshot\r\n"))
				return
			}
			if serr := ch.saveGolden(); serr != nil {
				os.Stdout.Write([]byte("\rgolden snapshot not saved (" + serr.Error() + "); continuing without one\r\n"))
				return
			}
			os.Stdout.Write([]byte("\rgolden snapshot saved: " + snapshotPath + "\r\n"))
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	os.Stdout.Write([]byte("\r\nTerminating MicroVM...\r\n"))
	_, _ = vm.RequestStop()
}

// restoreBoot restores the golden snapshot into a freshly instantiated (stopped)
// VM and resumes it, skipping the kernel cold boot and login scripting entirely.
func (c *chamber) restoreBoot() error {
	if err := c.vm.RestoreMachineStateFromURL(c.snapshot); err != nil {
		return err
	}
	if err := waitState(c.vm, vz.VirtualMachineStatePaused, 15*time.Second); err != nil {
		return err
	}
	return c.vm.Resume()
}

// copyConsole surfaces the guest console on stdout without scripting any input
// (used on the restore path, where the guest is already at an interactive shell).
func copyConsole(hostReader io.Reader) {
	io.Copy(os.Stdout, hostReader)
}

// driveConsole watches the guest console and scripts the login + bring-up.
func driveConsole(hostReader io.Reader, vmWriter io.Writer) {
	buf := make([]byte, 1024)
	var stream string
	state := 0
	for {
		n, err := hostReader.Read(buf)
		if n > 0 {
			os.Stdout.Write(buf[:n])
			stream += string(buf[:n])
			switch state {
			case 0:
				if strings.Contains(stream, "login:") {
					time.Sleep(100 * time.Millisecond)
					vmWriter.Write([]byte("root\n"))
					stream, state = "", 1
				}
			case 1:
				if strings.Contains(strings.ToLower(stream), "password:") {
					time.Sleep(100 * time.Millisecond)
					vmWriter.Write([]byte("passwd\n"))
					stream, state = "", 2
				}
			case 2:
				if strings.Contains(stream, "#") {
					time.Sleep(300 * time.Millisecond)
					vmWriter.Write([]byte(bringUpCmd))
					go io.Copy(vmWriter, os.Stdin)
					stream, state = "", 3
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// bringUpCmd mounts the shared assets, chroots into Alpine, and runs
// sandbox_init.sh — which launches the static Go detonationd and exec's the
// interactive shell. The daemon binary is cross-compiled into the shared assets
// dir by prepareassets. No networking is brought up (no `ip link`/`udhcpc`) and
// no `apk`/DNS is configured: the chamber is egress-denied by construction, and
// since Python is gone the guest needs nothing from the internet.
const bringUpCmd = "mkdir -p /mnt/assets && mount -t virtiofs assets /mnt/assets && cp -a /mnt/assets/alpine-root /alpine && mkdir -p /alpine/mnt/assets && mount -o bind /mnt/assets /alpine/mnt/assets && mount -t proc none /alpine/proc && mount -t sysfs none /alpine/sys && mount -o bind /dev /alpine/dev && chroot /alpine /bin/sh /mnt/assets/sandbox_init.sh\n"

// startVsockBridge accepts TCP on host loopback and pipes each connection to the
// guest's vsock listener through the chamber (which applies -reset-each), exposing
// a plain 127.0.0.1:5000 endpoint backed by the isolated MicroVM.
func startVsockBridge(ch *chamber, addr string) {
	// Reclaim the bridge port from any leftover launchvm so a re-run never binds a
	// stale VM (same pattern as modeld's model ports). Only reclaim a loopback port
	// — never kill whatever owns a non-local one.
	if _, p, perr := net.SplitHostPort(addr); perr == nil {
		if port, aerr := strconv.Atoi(p); aerr == nil {
			modelserve.ReclaimPort(port, os.Stdout)
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("vsock bridge: listen %s: %v (is macOS AirPlay Receiver on :5000? turn it off, or pass -bridge 127.0.0.1:5050 and -microvm http://127.0.0.1:5050)", addr, err)
		return
	}
	os.Stdout.Write([]byte("\r\nvsock bridge up: " + addr + " -> guest vsock:5000\r\n"))
	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			continue
		}
		go ch.handleConn(tcpConn)
	}
}

// startEgressBroker listens on the guest-initiated vsock port and gates every
// outbound connection the in-VM tools attempt through netpolicy. The guest has
// NO network device (egress-denied), so this host-side broker is its only path
// out — and a single, audited, allow-listed one. Byte tunneling and policy live
// in the broker package; this just wires the vz vsock listener to it.
//
// The listener is re-established if it drops (a snapshot restore tears down the
// guest end of the vsock), so /reset and -reset-each keep a working egress path.
func startEgressBroker(vm *vz.VirtualMachine, pol netpolicy.Policy) {
	b := &broker.Broker{Policy: pol, Log: func(target string, allowed bool, reason string) {
		if allowed {
			os.Stdout.Write([]byte("\regress ALLOW " + target + "\r\n"))
		} else {
			os.Stdout.Write([]byte("\regress DENY  " + target + " (" + reason + ")\r\n"))
		}
	}}
	announced := false
	for {
		devices := vm.SocketDevices()
		if len(devices) == 0 {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		ln, err := devices[0].Listen(broker.DefaultPort)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if !announced {
			os.Stdout.Write([]byte("\r\negress broker up: guest vsock:5001 -> host netpolicy\r\n"))
			announced = true
		}
		_ = b.Serve(ln) // returns when the listener breaks (e.g. after a restore); re-listen below
		time.Sleep(200 * time.Millisecond)
	}
}
