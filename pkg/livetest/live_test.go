//go:build live

// Package livetest runs the model-dependent checks against the REAL llama/qwen
// stack — the live counterpart to the offline suite. Build-tagged `live`, so the
// default `go test ./...` never compiles it; run it with:
//
//	go test -tags live ./pkg/livetest/ -v
//
// It boots the models + gouncer gateway once (TestMain), then exercises the live
// eval F1 gate and a live prompt-injection ADD case through the actual extractor.
// This suite is part of the gate (`make check`), not an optional extra: if the
// models aren't downloaded or startable, every test FAILS with guidance (run
// `go run ./cmd/preflight`). A test that skips is not testing anything.
package livetest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/t0ul/ai-security-engineering/internal/livemodel"
	"github.com/t0ul/ai-security-engineering/pkg/agent/eval"
)

var (
	harness  *livemodel.Harness
	startErr string
)

func TestMain(m *testing.M) {
	// Tests reference repo-root paths (set-up/vm-assets, testdata/...); the test
	// binary runs in ./livetest, so move to the module root first.
	if err := chdirToRoot(); err != nil {
		startErr = "cannot locate module root: " + err.Error()
	} else if ok, msg := livemodel.Available(); !ok {
		startErr = msg
	} else if h, err := livemodel.Start(context.Background(), 180*time.Second); err != nil {
		startErr = "live model start failed: " + err.Error()
	} else {
		harness = h
	}
	code := m.Run()
	if harness != nil {
		harness.Close()
	}
	os.Exit(code)
}

func requireLive(t *testing.T) {
	t.Helper()
	if harness == nil {
		t.Fatalf("live models unavailable, and the live suite is part of the gate: %s", startErr)
	}
}

// TestLiveEvalF1 is the live counterpart of cmd/livecheck: real extraction through
// llama, scored against the labeled emails.
func TestLiveEvalF1(t *testing.T) {
	requireLive(t)
	for _, g := range []struct {
		label string
		min   float64
	}{
		{"testdata/emaildrop/labels/3.json", 1.00},
		{"testdata/emaildrop/labels/1.json", 0.87},
	} {
		rep, err := eval.Score(g.label, true)
		if err != nil {
			t.Fatalf("%s: %v", g.label, err)
		}
		t.Logf("%s  f1=%.2f (gate>=%.2f) P=%.2f R=%.2f matched=%d/%d",
			rep.Source, rep.F1, g.min, rep.Precision, rep.Recall, rep.Matched, rep.Gold)
		if rep.F1 < g.min-1e-9 {
			t.Errorf("%s live F1 %.2f below gate %.2f", rep.Source, rep.F1, g.min)
		}
	}
}

// TestLivePassK quantifies the non-determinism a single eval run hides: it scores
// the richer label k times and reports pass@k (any run clears the gate) and
// pass^k (every run does). Gates leniently on pass@k so a flaky model doesn't
// fail CI, and logs pass^k as the reliability signal.
func TestLivePassK(t *testing.T) {
	requireLive(t)
	const (
		label = "testdata/emaildrop/labels/1.json"
		k     = 3
		gate  = 0.87
	)
	passAtK, passPowK, f1s, err := eval.PassK(label, k, gate, true)
	if err != nil {
		t.Fatalf("passK: %v", err)
	}
	t.Logf("pass@%d=%v  pass^%d=%v  per-run F1=%v (gate>=%.2f)", k, passAtK, k, passPowK, f1s, gate)
	if !passAtK {
		t.Errorf("no run of %d cleared the F1 gate %.2f: %v", k, gate, f1s)
	}
}

// chdirToRoot walks up from the test's working directory to the dir holding go.mod.
func chdirToRoot() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	for d := wd; ; {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return os.Chdir(d)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return fmt.Errorf("no go.mod above %s", wd)
		}
		d = parent
	}
}
