package assets_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/t0ul/emaildrop/internal/assets"
)

func ggufBytes() []byte {
	b := append([]byte{}, assets.GGUFMagic...)
	return append(b, []byte("...model weights...")...)
}

func TestVerifyGGUFHeader(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.gguf")
	if err := os.WriteFile(good, ggufBytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := assets.VerifyGGUFHeader(good); err != nil {
		t.Fatalf("valid GGUF rejected: %v", err)
	}

	bad := filepath.Join(dir, "bad.gguf")
	if err := os.WriteFile(bad, []byte("XXXXnot a model"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := assets.VerifyGGUFHeader(bad); err == nil {
		t.Fatal("non-GGUF file passed header check")
	}
}

func serveGGUF(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body)
	}))
}

func TestDownloadAndVerifyHappyPath(t *testing.T) {
	body := ggufBytes()
	srv := serveGGUF(t, body)
	defer srv.Close()
	sum := sha256.Sum256(body)

	dest := filepath.Join(t.TempDir(), "model.gguf")
	// URL must end .gguf to satisfy the extension policy; the test server
	// ignores the path and serves the body regardless.
	if err := assets.DownloadAndVerify(srv.URL+"/model.gguf", dest, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("verified download failed: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if len(got) != len(body) {
		t.Fatalf("downloaded %d bytes, want %d", len(got), len(body))
	}
}

func TestDownloadAndVerifyRejectsNonGGUFURL(t *testing.T) {
	if err := assets.DownloadAndVerify("http://x/model.safetensors", "/tmp/x", ""); err == nil {
		t.Fatal("non-.gguf URL should be rejected by policy")
	}
}

func TestDownloadAndVerifyHashMismatchRemovesFile(t *testing.T) {
	srv := serveGGUF(t, ggufBytes())
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "model.gguf")
	err := assets.DownloadAndVerify(srv.URL+"/model.gguf", dest, "deadbeef")
	if err == nil {
		t.Fatal("hash mismatch should error")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("mismatched artifact was not removed")
	}
}

func TestDownloadAndVerifyBadMagicRemovesFile(t *testing.T) {
	srv := serveGGUF(t, []byte("XXXXnope"))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "model.gguf")
	if err := assets.DownloadAndVerify(srv.URL+"/model.gguf", dest, ""); err == nil {
		t.Fatal("bad magic should error")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("bad-magic artifact was not removed")
	}
}
