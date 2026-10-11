package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/emaildrop/pkg/datastore"
)

// TestModelCatalogDownload locks B5: the in-console download fetches a catalog entry's
// GGUF to the asset dir and verifies it (SHA-256 pin + GGUF magic); a mismatched hash is
// refused and the partial file removed. Real httptest origin + real SQLite catalog.
func TestModelCatalogDownload(t *testing.T) {
	body := append([]byte("GGUF"), make([]byte, 64)...) // valid GGUF magic
	sum := sha256.Sum256(body)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body)
	}))
	defer origin.Close()

	inv, err := datastore.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	assetDir := t.TempDir()
	_ = inv.UpsertModelCatalog(modelcatalog.Entry{Name: "good", URL: origin.URL + "/good.gguf", File: "good.gguf", SHA256: hex.EncodeToString(sum[:]), Port: 11001})
	_ = inv.UpsertModelCatalog(modelcatalog.Entry{Name: "tampered", URL: origin.URL + "/x.gguf", File: "tampered.gguf", SHA256: "deadbeef", Port: 11002})

	srv := httptest.NewServer(New(Config{ModelCatalog: inv, AssetsDir: assetDir}).Handler())
	defer srv.Close()

	dl := func(name string) map[string]any {
		resp, err := http.Post(srv.URL+"/api/modelcatalog/download", "application/json", strings.NewReader(`{"name":"`+name+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m
	}

	// Happy path: downloads + verifies, file on disk.
	if r := dl("good"); r["ok"] != true {
		t.Fatalf("good download should succeed, got %v", r)
	}
	if _, err := os.Stat(filepath.Join(assetDir, "good.gguf")); err != nil {
		t.Errorf("verified file must be on disk: %v", err)
	}

	// Tamper path: SHA mismatch refused, partial file removed (fail closed).
	r := dl("tampered")
	if r["ok"] == true {
		t.Fatalf("a SHA mismatch must be refused, got %v", r)
	}
	if _, err := os.Stat(filepath.Join(assetDir, "tampered.gguf")); !os.IsNotExist(err) {
		t.Error("a mismatched download must not leave a file on disk")
	}
}
