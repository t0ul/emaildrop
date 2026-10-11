package main

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/rag"
	"github.com/t0ul/goflage"
)

// ingestHandbooks auto-ingests reference handbooks (files matching *handbook*.txt in the
// seed dir) straight into the RAG corpus (D1): they are standing REFERENCE documents, not
// bulletins, so they belong in the Ask corpus but must never be shredded onto the
// calendar. Each is PII-scrubbed on ingest (M3) and indexed as Untrusted provenance, the
// same spine as a fetched link. Idempotent — Add replaces by ID, so it keeps them fresh
// across boots. Returns the ids ingested.
func ingestHandbooks(corpus *rag.Store, seedDir string) []string {
	if corpus == nil || seedDir == "" {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(seedDir, "*handbook*.txt"))
	scrubber := goflage.New()
	var ids []string
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		scrubbed, _ := scrubber.Scrub(string(b))
		id := "handbook:" + filepath.Base(p)
		if corpus.Add(rag.Doc{ID: id, Text: scrubbed, Prov: rag.Untrusted}) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// gatewayReachable reports whether a model gateway is already listening at addr
// (host:port), so the webapp can reuse it instead of starting its own.
func gatewayReachable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// seedEmails ingests the example emails into the inbox on first run, so a fresh drop
// folder isn't empty and the operator doesn't have to re-drag emails every boot. The
// running watcher then processes them into persisted .ics in the outbox, which is the
// source of truth read on every request — so this happens exactly once per drop.
//
// Idempotent two ways: a DB marker ("emails_seeded") set after a successful seed, and
// a non-empty outbox (a drop already populated by prior manual drops is left alone).
// seedEmails drops example emails into the inbox for the watcher to process. It is
// INCREMENTAL and idempotent: on every boot it seeds only the example .txt files that are
// not already processed (no matching .ics in the outbox) and not already queued in the
// inbox — so adding new example files to the seed dir later (e.g. the NYC school calendar
// emails) gets them picked up, without re-processing the ones already done. Handbooks are
// reference docs, not emails, and are ingested into the corpus elsewhere (D1).
func seedEmails(inv *datastore.Store, inboxDir, outboxDir, seedDir string) {
	if seedDir == "" {
		return
	}
	files, _ := filepath.Glob(filepath.Join(seedDir, "*.txt"))
	if len(files) == 0 {
		return
	}
	if err := os.MkdirAll(inboxDir, 0o755); err != nil {
		log.Printf("webapp: seed inbox: %v", err)
		return
	}
	n := 0
	for _, f := range files {
		base := filepath.Base(f)
		if strings.Contains(strings.ToLower(base), "handbook") {
			continue // a knowledge-base doc, not a calendar email
		}
		stem := strings.TrimSuffix(base, filepath.Ext(base))
		if stemProcessed(outboxDir, stem) || fileExists(filepath.Join(inboxDir, base)) {
			continue // already extracted, or already waiting in the inbox
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if os.WriteFile(filepath.Join(inboxDir, base), data, 0o644) == nil {
			n++
		}
	}
	if n > 0 {
		log.Printf("webapp: seeded %d new example email(s) into the inbox; the watcher will process them into %s", n, outboxDir)
	}
}

// stemProcessed reports whether the outbox already holds an artifact for this email stem
// (e.g. "<stem>.events.ics"), i.e. the email was already extracted.
func stemProcessed(outboxDir, stem string) bool {
	matches, _ := filepath.Glob(filepath.Join(outboxDir, stem+".*"))
	return len(matches) > 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
