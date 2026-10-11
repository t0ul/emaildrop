package durable_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/durable"
)

// TestExactlyOnceOnSuccess: a repeated key returns the cached result and never
// re-fires the side effect.
func TestExactlyOnceOnSuccess(t *testing.T) {
	l, _ := durable.Open("")
	calls := 0
	fn := func() (string, error) { calls++; return "SENT", nil }

	out, replayed, err := l.Do("s", "tool", "refund-42", fn)
	if err != nil || replayed || out != "SENT" {
		t.Fatalf("first call: out=%q replayed=%v err=%v", out, replayed, err)
	}
	out, replayed, err = l.Do("s", "tool", "refund-42", fn)
	if err != nil || !replayed || out != "SENT" {
		t.Fatalf("replay: out=%q replayed=%v err=%v", out, replayed, err)
	}
	if calls != 1 {
		t.Fatalf("side effect must fire exactly once, fired %d", calls)
	}
}

// TestFailureIsRetryable: a failing fn is not recorded, so a retry can succeed.
func TestFailureIsRetryable(t *testing.T) {
	l, _ := durable.Open("")
	calls := 0
	fn := func() (string, error) {
		calls++
		if calls == 1 {
			return "", errors.New("transient")
		}
		return "OK", nil
	}
	if _, _, err := l.Do("s", "tool", "k", fn); err == nil {
		t.Fatal("first call should surface the error")
	}
	out, replayed, err := l.Do("s", "tool", "k", fn)
	if err != nil || replayed || out != "OK" {
		t.Fatalf("retry after failure: out=%q replayed=%v err=%v", out, replayed, err)
	}
}

// TestDurableResumeAcrossReopen: results survive a reopen (crash/restart) and a
// re-run replays cached steps instead of re-executing them.
func TestDurableResumeAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "steps.jsonl")
	l1, _ := durable.Open(path)
	if _, _, err := l1.Do("sess", "tool", "step-1", func() (string, error) { return "A", nil }); err != nil {
		t.Fatalf("record: %v", err)
	}

	l2, err := durable.Open(path) // "resume" after restart
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	calls := 0
	out, replayed, err := l2.Do("sess", "tool", "step-1", func() (string, error) { calls++; return "B", nil })
	if err != nil || !replayed || out != "A" || calls != 0 {
		t.Fatalf("resume should replay cached A without re-running: out=%q replayed=%v calls=%d err=%v", out, replayed, calls, err)
	}
}

// TestResumeVerifyRejectsTamperedCheckpoint: editing a persisted step's output
// must be caught on reopen (fail closed), not replayed as truth.
func TestResumeVerifyRejectsTamperedCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "steps.jsonl")
	l, _ := durable.Open(path)
	_, _, _ = l.Do("sess", "tool", "charge", func() (string, error) { return "charge=$5", nil })

	// Attacker edits the durable record in place, forging a bigger refund.
	raw, _ := os.ReadFile(path)
	tampered := strings.Replace(string(raw), "charge=$5", "refund=$5000", 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("tamper write: %v", err)
	}

	if _, err := durable.Open(path); !errors.Is(err, durable.ErrTampered) {
		t.Fatalf("reopen of a tampered log must fail closed, got %v", err)
	}
}
