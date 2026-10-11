// Command sbom emits a lean AI build manifest: the Go modules in the binary, the
// model artifacts (name + size, optionally SHA-256), and the hashes of the
// agent's system prompts. Enough to answer "what is in this build?" without the
// full SLSA/attestation machinery (M10/M19-lite, not the enterprise M17).
//
//	sbom [-dir set-up/vm-assets] [-hash]
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/t0ul/emaildrop/pkg/agent/extractor"
	"github.com/t0ul/emaildrop/pkg/controlplane"
)

type module struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}
type model struct {
	File   string `json:"file"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256,omitempty"`
}
type prompt struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type manifest struct {
	GoVersion string   `json:"go_version"`
	Modules   []module `json:"modules"`
	Models    []model  `json:"models"`
	Prompts   []prompt `json:"prompts"`
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func main() {
	dir := flag.String("dir", "set-up/vm-assets", "model artifact directory")
	doHash := flag.Bool("hash", false, "also SHA-256 each model (slow for multi-GB files)")
	flag.Parse()

	m := manifest{
		Prompts: []prompt{
			{"planner_system", sha(controlplane.PlannerSystemPrompt)},
			{"coder_system", sha(controlplane.CoderSystemPrompt)},
			{"extraction", sha(extractor.ExtractionPrompt)},
		},
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		m.GoVersion = bi.GoVersion
		for _, d := range bi.Deps {
			m.Modules = append(m.Modules, module{d.Path, d.Version})
		}
	}
	if entries, err := os.ReadDir(*dir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".gguf") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			md := model{File: e.Name(), Bytes: info.Size()}
			if *doHash {
				md.SHA256 = hashFile(filepath.Join(*dir, e.Name()))
			}
			m.Models = append(m.Models, md)
		}
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	fmt.Println(string(out))
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
