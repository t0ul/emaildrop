package captoken_test

import (
	"errors"
	"testing"
	"time"

	"github.com/t0ul/emaildrop/pkg/captoken"
)

func TestScopedTokenVerifies(t *testing.T) {
	m := captoken.NewMinter([]byte("k"))
	tok := m.Mint("web_fetch", time.Minute)
	if err := m.Verify(tok, "web_fetch"); err != nil {
		t.Fatalf("fresh scoped token should verify: %v", err)
	}
}

func TestWrongScopeRejected(t *testing.T) {
	m := captoken.NewMinter([]byte("k"))
	tok := m.Mint("web_fetch", time.Minute)
	if err := m.Verify(tok, "shell_exec"); !errors.Is(err, captoken.ErrScope) {
		t.Fatalf("token must not work for another scope, got %v", err)
	}
}

func TestExpiredRejected(t *testing.T) {
	now := time.Unix(1000, 0)
	m := captoken.NewMinter([]byte("k"))
	m.Now = func() time.Time { return now }
	tok := m.Mint("web_fetch", time.Minute)
	now = now.Add(2 * time.Minute)
	if err := m.Verify(tok, "web_fetch"); !errors.Is(err, captoken.ErrExpired) {
		t.Fatalf("expired token must be rejected, got %v", err)
	}
}

func TestForgedRejected(t *testing.T) {
	m := captoken.NewMinter([]byte("k"))
	// A stolen/ambient-looking credential with no valid signature.
	if err := m.Verify("web_fetch|9999999999|abcd.deadbeef", "web_fetch"); !errors.Is(err, captoken.ErrBadToken) {
		t.Fatalf("forged token must be rejected, got %v", err)
	}
}
