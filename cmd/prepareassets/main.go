// Command prepareassets provisions the MicroVM assets: the PUI PUI Linux kernel,
// the Alpine mini root filesystem, and the two GGUF models (Llama-3.2-3B planner,
// Qwen-1.5B coder). Models are fetched through the verified-download path
// (extension policy + GGUF magic check), the M10 supply-chain control.
//
//	prepareassets [-dir set-up/vm-assets]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/t0ul/emaildrop/internal/assets"
	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/emaildrop/pkg/datastore"
)

// The MicroVM kernel/rootfs stay consts here — they are VM provisioning assets, not
// models. The MODELS are no longer hardcoded: they come from the model catalog
// (datastore, falling back to modelcatalog.DefaultSeed), the single source of truth.
const (
	kernelURL = "https://github.com/Code-Hex/puipui-linux/releases/download/v1.0.3/puipui_linux_v1.0.3_aarch64.tar.gz"
	rootfsURL = "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/alpine-minirootfs-3.20.3-aarch64.tar.gz"
)

func main() {
	dir := flag.String("dir", "set-up/vm-assets", "asset output directory")
	db := flag.String("db", "", "inventory.db holding the model catalog (empty = use the built-in bootstrap seed)")
	flag.Parse()

	if runtime.GOARCH != "arm64" {
		log.Fatal("prepareassets: this lab requires Apple Silicon (arm64)")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatalf("prepareassets: %v", err)
	}

	catalog := resolveCatalog(*db)
	steps := []func(string) error{
		prepareKernel,
		prepareRootFS,
		func(dir string) error { return prepareModels(dir, catalog) },
		buildGuestBinaries,
	}
	for _, step := range steps {
		if err := step(*dir); err != nil {
			log.Fatalf("prepareassets: %v", err)
		}
	}
	fmt.Println("all MicroVM assets prepared.")
}

func prepareKernel(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "Image")); err == nil {
		fmt.Println("kernel: already present")
		return nil
	}
	fmt.Println("kernel: downloading PUI PUI Linux...")
	tarPath := filepath.Join(dir, "puipui.tar.gz")
	if err := assets.DownloadFile(kernelURL, tarPath); err != nil {
		return err
	}
	defer os.Remove(tarPath)
	if err := assets.ExtractTarGz(tarPath, dir); err != nil {
		return err
	}
	gz := filepath.Join(dir, "Image.gz")
	if _, err := os.Stat(gz); err == nil {
		if err := assets.GunzipFile(gz, filepath.Join(dir, "Image")); err != nil {
			return err
		}
		os.Remove(gz)
	}
	return nil
}

func prepareRootFS(dir string) error {
	alpineDir := filepath.Join(dir, "alpine-root")
	if _, err := os.Stat(alpineDir); err == nil {
		fmt.Println("rootfs: already present")
		return nil
	}
	fmt.Println("rootfs: downloading Alpine mini root filesystem...")
	if err := os.MkdirAll(alpineDir, 0o755); err != nil {
		return err
	}
	tarPath := filepath.Join(dir, "alpine-rootfs.tar.gz")
	if err := assets.DownloadFile(rootfsURL, tarPath); err != nil {
		return err
	}
	defer os.Remove(tarPath)
	// Alpine's rootfs tar carries device nodes and ownership the Go tar reader
	// cannot recreate without root, so shell out to the system tar here.
	cmd := exec.Command("tar", "-xzf", tarPath, "-C", alpineDir)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// buildGuestBinaries cross-compiles the in-guest Go tools into the shared assets
// dir. The VM is Alpine on Apple Silicon (linux/arm64); both are pure Go (CGO
// off), so they run as static binaries with no runtime deps: detonationd (serves
// the vsock detonation protocol) and vmfetch (the in-VM fetch tool that reaches
// the net only through the host egress broker).
func buildGuestBinaries(dir string) error {
	for _, bin := range []string{"detonationd", "vmfetch"} {
		dest := filepath.Join(dir, bin)
		fmt.Printf("guest: cross-compiling %s (linux/arm64, static)...\n", bin)
		cmd := exec.Command("go", "build", "-o", dest, "./cmd/"+bin)
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

// resolveCatalog returns the model catalog: from the inventory DB (seeded on first
// use) when a -db is given, else the built-in fail-closed bootstrap seed. Either way
// the model list is NOT hardcoded in this command.
func resolveCatalog(dbPath string) []modelcatalog.Entry {
	if dbPath == "" {
		return modelcatalog.DefaultSeed()
	}
	inv, err := datastore.Open(dbPath)
	if err != nil {
		log.Fatalf("prepareassets: open catalog db: %v", err)
	}
	defer inv.Close()
	cat, err := inv.SeedModelCatalogIfEmpty(modelcatalog.DefaultSeed())
	if err != nil {
		log.Fatalf("prepareassets: load catalog: %v", err)
	}
	return cat
}

func prepareModels(dir string, catalog []modelcatalog.Entry) error {
	for _, m := range catalog {
		dest := filepath.Join(dir, m.File)
		if fi, err := os.Stat(dest); err == nil && fi.Size() > 0 {
			fmt.Printf("model: %s already present\n", m.Name)
			continue
		}
		fmt.Printf("model: downloading %s (verified)...\n", m.Name)
		// SHA256 from the catalog pins the content (M10); empty = GGUF-magic verify only.
		if err := assets.DownloadAndVerify(m.URL, dest, m.SHA256); err != nil {
			return err
		}
	}
	return nil
}
