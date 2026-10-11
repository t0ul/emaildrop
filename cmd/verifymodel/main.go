// Command verifymodel is the standalone M10 supply-chain control: fetch a GGUF
// model over HTTP, compute its SHA-256, and reject anything that is not a
// policy-compliant, magic-verified GGUF (optionally pinned to an expected hash).
//
//	verifymodel -url <.gguf URL> -dest <path> [-sha <hex>]
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/t0ul/emaildrop/internal/assets"
)

func main() {
	url := flag.String("url", "", "model URL (must end in .gguf)")
	dest := flag.String("dest", "set-up/vm-assets/model.gguf", "destination path")
	sha := flag.String("sha", "", "expected SHA-256 (hex); empty skips the hash check")
	flag.Parse()

	if *url == "" {
		log.Fatal("verifymodel: -url is required")
	}
	if err := assets.DownloadAndVerify(*url, *dest, *sha); err != nil {
		log.Fatalf("verifymodel: security check failed: %v", err)
	}
	fmt.Printf("verified: %s -> %s\n", *url, *dest)
}
