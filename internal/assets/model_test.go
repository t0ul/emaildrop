package assets_test

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/t0ul/emaildrop/internal/assets"
)

func TestCheckModelFormat(t *testing.T) {
	for _, ok := range []string{"model.gguf", "https://x/m.safetensors", "M.GGUF"} {
		if err := assets.CheckModelFormat(ok); err != nil {
			t.Errorf("%q should be allowed: %v", ok, err)
		}
	}
	for _, bad := range []string{"model.pkl", "weights.pt", "x.bin", "evil"} {
		if err := assets.CheckModelFormat(bad); !errors.Is(err, assets.ErrModelFormat) {
			t.Errorf("%q should be rejected, got %v", bad, err)
		}
	}
}

func TestVerifySafetensorsHeader(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "m.safetensors")
	hdr := []byte(`{"__metadata__":{}}`)
	f, _ := os.Create(good)
	binary.Write(f, binary.LittleEndian, uint64(len(hdr)))
	f.Write(hdr)
	f.Close()
	if err := assets.VerifySafetensorsHeader(good); err != nil {
		t.Fatalf("valid safetensors rejected: %v", err)
	}

	bad := filepath.Join(dir, "bad.safetensors")
	f2, _ := os.Create(bad)
	binary.Write(f2, binary.LittleEndian, uint64(999999)) // length beyond file
	f2.Write([]byte("xx"))
	f2.Close()
	if err := assets.VerifySafetensorsHeader(bad); !errors.Is(err, assets.ErrModelFormat) {
		t.Fatalf("malformed safetensors must be rejected, got %v", err)
	}
}
