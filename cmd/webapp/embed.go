package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/emaildrop/internal/modelserve"
	"github.com/t0ul/emaildrop/pkg/rag"
	"github.com/t0ul/emaildrop/pkg/server"
)

// embedManager owns a single, dedicated llama.cpp embeddings server (separate from
// the chat models) and lazily (re)starts it for whichever catalog model the operator
// chose to embed with. One server at a time — switching the embedder swaps it.
type embedManager struct {
	ctx       context.Context
	bin       string
	assetsDir string
	catalog   map[string]modelcatalog.Entry
	port      int

	mu       sync.Mutex
	cur      string
	sup      *modelserve.Supervisor
	embedder rag.Embedder
}

func newEmbedManager(ctx context.Context, bin, assetsDir string, catalog []modelcatalog.Entry) *embedManager {
	m := map[string]modelcatalog.Entry{}
	for _, e := range catalog {
		m[e.Name] = e
	}
	return &embedManager{ctx: ctx, bin: bin, assetsDir: assetsDir, catalog: m, port: 11500}
}

// ensure (re)starts the embeddings server for the named catalog model (ready-gated)
// and returns an Embedder for it. Reuses the running server if it already serves that
// model.
func (m *embedManager) ensure(model string) (rag.Embedder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == model && m.embedder != nil {
		return m.embedder, nil
	}
	if m.sup != nil {
		m.sup.Shutdown()
		m.sup, m.embedder, m.cur = nil, nil, ""
	}
	e, ok := m.catalog[model]
	if !ok {
		return nil, fmt.Errorf("embed: model %q not in the catalog", model)
	}
	ctxSize := e.Ctx
	if ctxSize <= 0 {
		ctxSize = 2048
	}
	modelserve.ReclaimPort(m.port, os.Stdout)
	sup := &modelserve.Supervisor{Servers: []modelserve.Server{
		modelserve.EmbedServer("embed", m.bin, "127.0.0.1", filepath.Join(m.assetsDir, e.File), m.port, ctxSize),
	}}
	if err := sup.Start(m.ctx); err != nil {
		return nil, err
	}
	if err := sup.WaitHealthy(m.ctx, 180*time.Second); err != nil {
		sup.Shutdown()
		return nil, err
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/v1/embeddings", m.port)
	m.sup, m.cur, m.embedder = sup, model, rag.HTTPEmbedder(url, "embed")
	return m.embedder, nil
}

// stop shuts the embeddings server down (e.g. when switching back to FTS).
func (m *embedManager) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sup != nil {
		m.sup.Shutdown()
		m.sup, m.embedder, m.cur = nil, nil, ""
	}
}

// ragApplyEmbed returns the hook the RAG lab calls when its config changes: on
// semantic mode with a real embedder it brings the embeddings server up and points
// the (writable) corpus and the (read-only) reader at it, then flips the shared
// semantic flag the chat consults; on FTS/none it clears the embedder and the flag.
func ragApplyEmbed(corpus, reader *rag.Store, mgr *embedManager, semantic *atomic.Bool) func(server.RAGConfig) {
	return func(c server.RAGConfig) {
		if c.Mode == "semantic" && c.Embedder != "" && c.Embedder != "none" {
			emb, err := mgr.ensure(c.Embedder)
			if err != nil {
				log.Printf("webapp: embeddings server failed (%v) — staying on FTS", err)
				setEmbed(corpus, reader, nil)
				semantic.Store(false)
				return
			}
			setEmbed(corpus, reader, emb)
			semantic.Store(true)
			log.Printf("webapp: semantic retrieval ON (embedder=%s)", c.Embedder)
			return
		}
		setEmbed(corpus, reader, nil)
		semantic.Store(false)
		mgr.stop()
	}
}

func setEmbed(corpus, reader *rag.Store, e rag.Embedder) {
	if corpus != nil {
		corpus.Embed = e
	}
	if reader != nil {
		reader.Embed = e
	}
}
