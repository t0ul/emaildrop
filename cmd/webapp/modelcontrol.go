package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/emaildrop/internal/modelstack"
)

// modelController is the single owner of the local model stack's lifecycle (C3). Boot
// auto-start and the in-console Start/Stop buttons go through the SAME controller, so the
// stack is started at most once and always has exactly one owner to shut down — no
// orphaned llama processes, no double-start. Shutdown registers Stop as a cleanup.
type modelController struct {
	ctx       context.Context
	assetsDir string
	dial      string
	catalog   []modelcatalog.Entry
	ready     time.Duration

	mu    sync.Mutex
	stack *modelstack.Stack
}

func newModelController(ctx context.Context, assetsDir, dial string, catalog []modelcatalog.Entry) *modelController {
	return &modelController{ctx: ctx, assetsDir: assetsDir, dial: dial, catalog: catalog, ready: 180 * time.Second}
}

// StartModels brings the stack up if it is not already running. It is idempotent; a
// stack already up is a no-op. On success extraction switches to the LLM path.
func (m *modelController) StartModels() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stack != nil {
		return nil
	}
	if ok, reason := modelstack.Available(m.assetsDir, m.catalog); !ok {
		return errors.New(reason)
	}
	s, err := modelstack.Start(m.ctx, m.assetsDir, m.dial, m.catalog, m.ready)
	if err != nil {
		return err
	}
	m.stack = s
	os.Setenv("EXTRACT_MODE", "llm")
	return nil
}

// StopModels shuts the stack down (killing the llama process group) if it is running.
// Idempotent. Extraction falls back to the offline regex path.
func (m *modelController) StopModels() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stack == nil {
		return nil
	}
	m.stack.Close()
	m.stack = nil
	os.Setenv("EXTRACT_MODE", "regex")
	return nil
}

// ModelsRunning reports whether this controller currently owns a running stack. (An
// externally reachable gateway not started here is reported by the gateway health probe,
// not this flag.)
func (m *modelController) ModelsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stack != nil
}
