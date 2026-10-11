// Package memory is the M20 agent-memory lifecycle: persistent memory is a
// poisoning sink and a PII hoard, so entries are per-subject scoped (no
// cross-scope recall), carry a TTL (expired entries are never recalled),
// support right-to-erasure (DSAR, M19), and — because recalled memory is
// untrusted content — are injection-neutralized when assembled for a prompt.
package memory

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/t0ul/emaildrop/pkg/agent/guard"
)

// Entry is one memory. Untrusted marks memory derived from attacker-influenced
// content (e.g. a summarized email), which must be sanitized on recall.
type Entry struct {
	Scope     string    `json:"scope"`
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Untrusted bool      `json:"untrusted"`
	ExpiresAt time.Time `json:"expires_at"` // zero = no expiry
}

// Store is scope-partitioned memory. With a path it persists to a JSON snapshot
// (single-user laptop scale; swap for bbolt if writes/concurrency grow).
type Store struct {
	mu      sync.Mutex
	byScope map[string]map[string]Entry
	path    string
	// Now overrides the clock for tests.
	Now func() time.Time
}

// New returns an empty in-memory store (no persistence).
func New() *Store { return &Store{byScope: map[string]map[string]Entry{}} }

// Open returns a store backed by a JSON snapshot at path, loading any existing
// state. Writes are persisted on each mutation.
func Open(path string) (*Store, error) {
	s := &Store{byScope: map[string]map[string]Entry{}, path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &s.byScope); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// persist writes a snapshot; caller must hold the lock. No-op without a path.
func (s *Store) persist() {
	if s.path == "" {
		return
	}
	b, err := json.Marshal(s.byScope)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.path) // atomic replace
	}
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Put stores value under (scope,key). ttl<=0 means no expiry.
func (s *Store) Put(scope, key, value string, ttl time.Duration, untrusted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := Entry{Scope: scope, Key: key, Value: value, Untrusted: untrusted}
	if ttl > 0 {
		e.ExpiresAt = s.now().Add(ttl)
	}
	if s.byScope[scope] == nil {
		s.byScope[scope] = map[string]Entry{}
	}
	s.byScope[scope][key] = e
	s.persist()
}

func (s *Store) live(e Entry) bool {
	return e.ExpiresAt.IsZero() || s.now().Before(e.ExpiresAt)
}

// Get returns a live entry from the caller's own scope only.
func (s *Store) Get(scope, key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byScope[scope][key]
	if !ok || !s.live(e) {
		return "", false
	}
	return e.Value, true
}

// Recall returns all live entries for a scope (recalled memory is untrusted).
func (s *Store) Recall(scope string) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Entry
	for _, e := range s.byScope[scope] {
		if s.live(e) {
			out = append(out, e)
		}
	}
	return out
}

// Erase removes every entry for a scope (DSAR / right to erasure) and returns
// the count removed.
func (s *Store) Erase(scope string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.byScope[scope])
	delete(s.byScope, scope)
	s.persist()
	return n
}

// Assemble renders recalled entries for a prompt, injection-neutralizing the
// untrusted ones so poisoned memory cannot act as instructions.
func Assemble(entries []Entry) string {
	var out string
	for _, e := range entries {
		v := e.Value
		if e.Untrusted {
			v, _ = guard.Sanitize(v)
		}
		out += "<memory key=\"" + e.Key + "\">\n" + v + "\n</memory>\n"
	}
	return out
}
