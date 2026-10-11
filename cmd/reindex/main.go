// Command reindex rebuilds the SQLite RAG corpus from the raw emails archived in
// processed/. Because the on-disk copies are the source of truth and the index
// is derived, a lost or corrupt corpus.db is fully recoverable: point reindex at
// the drop dir and it re-adds every archived email.
//
//	reindex [-dir .] [-db <dir>/corpus.db]
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/t0ul/emaildrop/pkg/rag"
	"github.com/t0ul/goflage"
)

func main() {
	dir := flag.String("dir", ".", "drop dir containing processed/")
	db := flag.String("db", "", "corpus db path (default <dir>/corpus.db)")
	flag.Parse()

	dbPath := *db
	if dbPath == "" {
		dbPath = filepath.Join(*dir, "corpus.db")
	}
	corpus, err := rag.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reindex:", err)
		os.Exit(1)
	}
	defer corpus.Close()

	processed := filepath.Join(*dir, "processed")
	entries, err := os.ReadDir(processed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reindex:", err)
		os.Exit(1)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".txt") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(processed, e.Name()))
		if err != nil {
			continue
		}
		// Scrub secrets/PII before (re)indexing — same guard as the live pipeline,
		// so a rebuild can't reintroduce credentials the processed/ backup holds.
		scrubbed, _ := goflage.New().Scrub(string(raw))
		if err := corpus.Add(rag.Doc{ID: e.Name(), Tenant: "", Text: scrubbed, Prov: rag.Untrusted}); err != nil {
			fmt.Fprintf(os.Stderr, "reindex: %s: %v\n", e.Name(), err)
			continue
		}
		n++
	}
	fmt.Printf("reindexed %d email(s) from %s into %s\n", n, processed, dbPath)
}
