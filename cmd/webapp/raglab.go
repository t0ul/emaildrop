package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/t0ul/GoRag"
	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/rag"
	"github.com/t0ul/emaildrop/pkg/server"
	"github.com/t0ul/goflage"
)

// ragLab is the retrieval experimentation surface (server.RAGLab): it owns the
// writable corpus and the processed-email archive, persists the ingestion config in
// the datastore, applies it (chunker now; embedder/mode via hooks), and re-runs
// ingestion over the whole corpus on demand. The .txt archive in processed/ is the
// source of truth; the corpus is a derived index that can be rebuilt at will.
type ragLab struct {
	mu          sync.Mutex
	inv         *datastore.Store
	corpus      *rag.Store
	processed   string
	handbookDir string // seed dir holding reference handbooks, re-ingested on reindex
	cfg         server.RAGConfig
	embedders   []string
	// applyEmbed sets the corpus embedder (and chat mode) for a config — wired in the
	// embeddings slice; nil-safe so FTS works without it.
	applyEmbed func(server.RAGConfig)
}

const ragConfigKey = "rag_config"

// defaultRAGConfig is the default ingestion config: lexical FTS, PARAGRAPH chunking (so a
// retrieved hit is a coherent passage, not a whole document — a whole-chunked doc overflows
// the model window and makes retrieval coarse), no embedder.
func defaultRAGConfig() server.RAGConfig {
	return server.RAGConfig{Mode: "fts", Chunker: "paragraph", ChunkSize: 800, ChunkOverlap: 0, Embedder: "none"}
}

// loadRAGConfig returns the persisted ingestion config, or the default when none is
// stored. Exposed so the corpus chunker can be set at OPEN time — before any ingest —
// not only when the RAG lab is built (ingest at boot otherwise runs with a nil = whole
// chunker regardless of config).
func loadRAGConfig(inv *datastore.Store) server.RAGConfig {
	cfg := defaultRAGConfig()
	if inv != nil {
		if raw, ok, _ := inv.GetConfig(ragConfigKey); ok && raw != "" {
			var c server.RAGConfig
			if json.Unmarshal([]byte(raw), &c) == nil {
				cfg = c
			}
		}
	}
	return cfg
}

// chunkerFor builds the GoRag chunker for a config, so callers outside the lab (the boot
// ingest path) can set the corpus chunker before the first Add.
func chunkerFor(c server.RAGConfig) gorag.Chunker {
	return gorag.ChunkerByName(c.Chunker, c.ChunkSize, c.ChunkOverlap)
}

// newRAGLab builds the lab, rehydrates the persisted config, and applies it so the
// corpus is chunking per the operator's last choice from the first query.
func newRAGLab(inv *datastore.Store, corpus *rag.Store, processed, handbookDir string, embedders []string, applyEmbed func(server.RAGConfig)) *ragLab {
	l := &ragLab{inv: inv, corpus: corpus, processed: processed, handbookDir: handbookDir, cfg: loadRAGConfig(inv), embedders: embedders, applyEmbed: applyEmbed}
	// Apply the chunker synchronously (cheap). The embedder may need to boot a model
	// server (slow), so apply it in the background at startup — the corpus already
	// holds the vectors from the last reindex, so semantic queries work once it's up.
	l.applyChunker(l.cfg)
	if l.cfg.Mode == "semantic" && l.applyEmbed != nil {
		go l.applyEmbed(l.cfg)
	}
	return l
}

// applyChunker wires the chunking strategy into the live corpus (affects new Adds).
func (l *ragLab) applyChunker(c server.RAGConfig) {
	l.corpus.Chunker = gorag.ChunkerByName(c.Chunker, c.ChunkSize, c.ChunkOverlap)
}

func (l *ragLab) Config() server.RAGConfig {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cfg
}

func (l *ragLab) Embedders() []string { return l.embedders }

func (l *ragLab) Stats() server.RAGStats {
	docs, chunks := l.corpus.Stats()
	return server.RAGStats{Docs: docs, Chunks: chunks, Mode: l.Config().Mode}
}

// Save persists + applies a new config and reindexes (a config change only takes
// effect once the corpus is rebuilt with it).
func (l *ragLab) Save(c server.RAGConfig) (server.RAGStats, error) {
	if c.Mode == "" {
		c.Mode = "fts"
	}
	if c.Chunker == "" {
		c.Chunker = "whole"
	}
	l.mu.Lock()
	l.cfg = c
	if l.inv != nil {
		if b, err := json.Marshal(c); err == nil {
			_ = l.inv.SetConfig(ragConfigKey, string(b))
		}
	}
	l.applyChunker(c)
	l.mu.Unlock()
	// Apply the embedder SYNCHRONOUSLY on an operator save (they are waiting), so the
	// reindex below actually embeds the chunks for semantic retrieval.
	if l.applyEmbed != nil {
		l.applyEmbed(c)
	}
	return l.Reindex()
}

// Reindex rebuilds the corpus from the processed-email archive using the current
// config: clear, then re-add every archived email (scrubbed, chunked, embedded).
func (l *ragLab) Reindex() (server.RAGStats, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.corpus.Clear(); err != nil {
		return server.RAGStats{}, err
	}
	entries, err := os.ReadDir(l.processed)
	if err == nil {
		scrubber := goflage.New()
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".txt") {
				continue
			}
			raw, rerr := os.ReadFile(filepath.Join(l.processed, e.Name()))
			if rerr != nil {
				continue
			}
			scrubbed, _ := scrubber.Scrub(string(raw))
			_ = l.corpus.Add(rag.Doc{ID: originalName(e.Name()), Text: scrubbed, Prov: rag.Untrusted})
		}
	}
	// Reference handbooks are a separate ingest source, not emails — re-add them after
	// the Clear so a reindex (e.g. to apply a new chunker) does not drop them (D1).
	ingestHandbooks(l.corpus, l.handbookDir)
	docs, chunks := l.corpus.Stats()
	return server.RAGStats{Docs: docs, Chunks: chunks, Mode: l.cfg.Mode}, nil
}

// originalName strips the watcher's "20060102-150405." (or "...-N.") stamp prefix
// from a processed filename, so the corpus doc id matches the live-processing id.
func originalName(processed string) string {
	if i := strings.Index(processed, "."); i >= 0 && i+1 < len(processed) {
		return processed[i+1:]
	}
	return processed
}
