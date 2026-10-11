// Command detonationd is the in-VM detonation daemon (the Go replacement for
// set-up/vm-assets/detonation_daemon.py). It listens on vsock port 5000 inside
// the MicroVM and executes host-approved commands in isolation.
//
// Default: AF_VSOCK on Linux (the real deployment, bridged by launch_vm.go to
// the host at 127.0.0.1:5000). Set DAEMON_TCP=host:port to serve over TCP
// instead, for host-side development and testing without a VM.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/t0ul/emaildrop/pkg/sandbox"
)

func main() {
	d := sandbox.NewDaemon()
	// Structured, correlated log line per exec — shares the host request's
	// trace_id. The command is logged (bounded); its output is never logged.
	d.Log = func(traceID, command string) {
		b, _ := json.Marshal(map[string]string{"trace_id": traceID, "span": "vm.exec", "command": command})
		fmt.Println(string(b))
	}

	ln, where, err := listen()
	if err != nil {
		log.Fatalf("detonationd: %v", err)
	}
	log.Printf("detonation daemon listening on %s", where)
	log.Fatal(d.ServeListener(ln))
}

func listen() (net.Listener, string, error) {
	if addr := os.Getenv("DAEMON_TCP"); addr != "" {
		ln, err := net.Listen("tcp", addr)
		return ln, "tcp " + addr, err
	}
	ln, err := sandbox.Listen(sandbox.DefaultPort)
	return ln, fmt.Sprintf("vsock port %d", sandbox.DefaultPort), err
}
