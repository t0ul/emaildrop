// Package cpstore is the control-plane console's durable inventory: an embedded
// SQLite store (pure-Go, no CGO) that persists the governed state the operator
// console shows across restarts — versioned prompts, four-eyes approvals, MCP
// manifest pins, eval scores, and the admin-action audit. The fleet libraries
// (goverlord, gustoms) stay pure/in-memory; the course records their decisions
// here as they happen, so history survives a restart and the console reads real
// data, not a mock.
//
// Tables are append-only history (an inventory of versioned artifacts and the
// decisions about them), distinct from gledger's runtime trace log.
package datastore

import (
	"database/sql"
	_ "embed"
	"strings"
	"time"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed inventory.
type Store struct{ db *sql.DB }

// schema is the full SQLite schema, kept as one auditable plain-SQL file
// (schema.sql) and embedded at build time — nothing creates a table elsewhere.
//
//go:embed schema.sql
var schema string

// Open creates/opens the inventory at path (":memory:" for ephemeral).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// Migration: add models_catalog.kind to DBs created before the column existed. The
	// CREATE above is IF NOT EXISTS, so it never alters an existing table; this ALTER
	// is idempotent (ignore the "duplicate column" error when the column is present).
	if _, err := db.Exec(`ALTER TABLE models_catalog ADD COLUMN kind TEXT DEFAULT ''`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`ALTER TABLE chat_turns ADD COLUMN unsafe INTEGER DEFAULT 0`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// RecordPrompt stores a versioned, hashed system-prompt artifact.
func (s *Store) RecordPrompt(name, version, hash, text string) error {
	_, err := s.db.Exec(`INSERT INTO prompts(name,version,hash,text) VALUES(?,?,?,?)`, name, version, hash, text)
	return err
}

// SetConfig upserts a single configuration value by key (JSON or scalar). The DB
// is the source of truth for all runtime config; shipped consts are only the
// fail-closed default when a key is absent.
func (s *Store) SetConfig(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, at=CURRENT_TIMESTAMP`, key, value)
	return err
}

// GetConfig reads a configuration value by key.
func (s *Store) GetConfig(key string) (string, bool, error) {
	row := s.db.QueryRow(`SELECT value FROM config WHERE key=?`, key)
	var v string
	switch err := row.Scan(&v); err {
	case nil:
		return v, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, err
	}
}

// RecordFeedback stores an operator accept/reject decision on an extracted item —
// the data-flywheel's ground-truth signal: real use teaches the system which
// extractions were right (M19 data governance / the improvement loop).
func (s *Store) RecordFeedback(source, title, decision string) error {
	_, err := s.db.Exec(`INSERT INTO feedback(source,title,decision) VALUES(?,?,?)`, source, title, decision)
	return err
}

// FeedbackStats returns the accept/reject tallies accumulated from real use.
func (s *Store) FeedbackStats() (accepts, rejects int, err error) {
	row := s.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN decision='accept' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN decision='reject' THEN 1 ELSE 0 END),0) FROM feedback`)
	err = row.Scan(&accepts, &rejects)
	return accepts, rejects, err
}

// FeedbackRow is one recorded feedback signal: where it came from, what it was about,
// the decision (accept/reject/neutral), and when — the raw ground truth the operator
// reviews in Studio to drive tuning.
type FeedbackRow struct {
	Source   string
	Label    string
	Decision string
	At       string
}

// RecentFeedback returns the most recent feedback signals, newest first — the actual
// examples (not just counts) so the operator can see WHAT was rated and act on it.
func (s *Store) RecentFeedback(limit int) ([]FeedbackRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT source,title,decision,at FROM feedback ORDER BY at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedbackRow
	for rows.Next() {
		var r FeedbackRow
		if err := rows.Scan(&r.Source, &r.Label, &r.Decision, &r.At); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EvalCase is one promoted regression case (a thumbs-down the operator promoted).
type EvalCase struct {
	ID     int64
	Source string
	Label  string
	Note   string
	At     string
}

// AddEvalCase promotes a feedback example into the regression watchlist.
func (s *Store) AddEvalCase(source, label, note string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO eval_cases(source,label,note) VALUES(?,?,?)`, source, label, note)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListEvalCases returns the promoted regression cases, newest first.
func (s *Store) ListEvalCases(limit int) ([]EvalCase, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id,source,label,note,at FROM eval_cases ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvalCase
	for rows.Next() {
		var c EvalCase
		if err := rows.Scan(&c.ID, &c.Source, &c.Label, &c.Note, &c.At); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteEvalCase removes a promoted regression case (resolved / no longer relevant).
func (s *Store) DeleteEvalCase(id int64) error {
	_, err := s.db.Exec(`DELETE FROM eval_cases WHERE id=?`, id)
	return err
}

// AuthoredSkill is one operator-authored skill (content only; it is signed at load).
type AuthoredSkill struct {
	Name         string
	Instructions string
	Tools        []string
}

// AddAuthoredSkill upserts an operator-authored skill's content (name is the key).
func (s *Store) AddAuthoredSkill(name, instructions string, tools []string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO authored_skills(name,instructions,tools) VALUES(?,?,?)`,
		name, instructions, strings.Join(tools, ","))
	return err
}

// ListAuthoredSkills returns every operator-authored skill, sorted by name.
func (s *Store) ListAuthoredSkills() ([]AuthoredSkill, error) {
	rows, err := s.db.Query(`SELECT name,instructions,tools FROM authored_skills ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthoredSkill
	for rows.Next() {
		var a AuthoredSkill
		var tools string
		if err := rows.Scan(&a.Name, &a.Instructions, &tools); err != nil {
			return nil, err
		}
		for _, t := range strings.Split(tools, ",") {
			if t = strings.TrimSpace(t); t != "" {
				a.Tools = append(a.Tools, t)
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAuthoredSkill removes an operator-authored skill by name.
func (s *Store) DeleteAuthoredSkill(name string) error {
	_, err := s.db.Exec(`DELETE FROM authored_skills WHERE name=?`, name)
	return err
}

// RecordBudget stores a versioned, hashed budget config (JSON) for a name.
func (s *Store) RecordBudget(name, version, hash, config string) error {
	_, err := s.db.Exec(`INSERT INTO budgets(name,version,hash,config) VALUES(?,?,?,?)`, name, version, hash, config)
	return err
}

// LatestBudget returns the most recent persisted budget config JSON for name, so
// the resolver can rehydrate on boot.
func (s *Store) LatestBudget(name string) (config string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT config FROM budgets WHERE name=? ORDER BY at DESC, rowid DESC LIMIT 1`, name)
	switch e := row.Scan(&config); e {
	case nil:
		return config, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, e
	}
}

// SaveBundle stores a known-good configuration snapshot (JSON) under a label — a
// point the whole governed plane can be rolled back to in one step (C10).
func (s *Store) SaveBundle(label, config string) error {
	_, err := s.db.Exec(`INSERT INTO bundles(label,config) VALUES(?,?)`, label, config)
	return err
}

// GetBundle returns the most recent snapshot stored under label.
func (s *Store) GetBundle(label string) (config string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT config FROM bundles WHERE label=? ORDER BY at DESC, rowid DESC LIMIT 1`, label)
	switch e := row.Scan(&config); e {
	case nil:
		return config, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, e
	}
}

// BundleRow is a stored snapshot's label + time (config omitted from the list).
type BundleRow struct {
	Label string
	At    time.Time
}

// ListBundles returns the most-recent snapshot per label, newest first. It selects
// the real `at` column (not MAX(at), which some drivers return as a string that
// won't scan into time.Time) via a per-label latest-row subquery.
func (s *Store) ListBundles(limit int) ([]BundleRow, error) {
	rows, err := s.db.Query(`SELECT label, at FROM bundles b WHERE at = (SELECT MAX(at) FROM bundles WHERE label = b.label) GROUP BY label ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BundleRow
	for rows.Next() {
		var b BundleRow
		if err := rows.Scan(&b.Label, &b.At); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// RecordSampling stores a versioned, hashed sampling config (JSON) for a model.
func (s *Store) RecordSampling(name, version, hash, config string) error {
	_, err := s.db.Exec(`INSERT INTO sampling(name,version,hash,config) VALUES(?,?,?,?)`, name, version, hash, config)
	return err
}

// LatestSampling returns the most recent persisted sampling config JSON for name,
// so the resolver can rehydrate the active sampling on boot.
func (s *Store) LatestSampling(name string) (config string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT config FROM sampling WHERE name=? ORDER BY at DESC, rowid DESC LIMIT 1`, name)
	switch e := row.Scan(&config); e {
	case nil:
		return config, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, e
	}
}

// RecordRetrieval persists a governed retrieval-config activation.
func (s *Store) RecordRetrieval(name, version, hash, config string) error {
	_, err := s.db.Exec(`INSERT INTO retrieval(name,version,hash,config) VALUES(?,?,?,?)`, name, version, hash, config)
	return err
}

// LatestRetrieval returns the most recent persisted retrieval config JSON for
// name, so the resolver can rehydrate the active retrieval on boot.
func (s *Store) LatestRetrieval(name string) (config string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT config FROM retrieval WHERE name=? ORDER BY at DESC, rowid DESC LIMIT 1`, name)
	switch e := row.Scan(&config); e {
	case nil:
		return config, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, e
	}
}

// LatestPromptText returns the most recent persisted prompt text for name, so the
// resolver can rehydrate the active prompt on boot (the DB is the source of truth).
func (s *Store) LatestPromptText(name string) (text string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT text FROM prompts WHERE name=? ORDER BY at DESC, rowid DESC LIMIT 1`, name)
	switch e := row.Scan(&text); e {
	case nil:
		return text, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, e
	}
}

// RecordGrammar persists a governed output-grammar activation.
func (s *Store) RecordGrammar(name, version, hash, text string) error {
	_, err := s.db.Exec(`INSERT INTO grammars(name,version,hash,text) VALUES(?,?,?,?)`, name, version, hash, text)
	return err
}

// LatestGrammarText returns the most recent persisted grammar text for name, so
// the resolver can rehydrate the active grammar on boot.
func (s *Store) LatestGrammarText(name string) (text string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT text FROM grammars WHERE name=? ORDER BY at DESC, rowid DESC LIMIT 1`, name)
	switch e := row.Scan(&text); e {
	case nil:
		return text, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, e
	}
}

// RecordModel persists a governed model-binding activation.
func (s *Store) RecordModel(name, version, hash, model string) error {
	_, err := s.db.Exec(`INSERT INTO models(name,version,hash,model) VALUES(?,?,?,?)`, name, version, hash, model)
	return err
}

// LatestModel returns the most recent persisted model name for a role, so the
// resolver can rehydrate the active binding on boot.
func (s *Store) LatestModel(name string) (model string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT model FROM models WHERE name=? ORDER BY at DESC, rowid DESC LIMIT 1`, name)
	switch e := row.Scan(&model); e {
	case nil:
		return model, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, e
	}
}

// RecordSkillPin persists a governed skill approval: the operator-approved content
// hash (the pin) for a skill name. The approved hash IS the pin — no hash-of-a-hash.
func (s *Store) RecordSkillPin(name, version, hash string) error {
	_, err := s.db.Exec(`INSERT INTO skill_pins(name,version,hash) VALUES(?,?,?)`, name, version, hash)
	return err
}

// LatestSkillPin returns the most recent approved content hash for a skill name, so
// the resolver can rehydrate the active pin on boot.
func (s *Store) LatestSkillPin(name string) (hash string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT hash FROM skill_pins WHERE name=? ORDER BY at DESC, rowid DESC LIMIT 1`, name)
	switch e := row.Scan(&hash); e {
	case nil:
		return hash, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, e
	}
}

// UpsertModelCatalog inserts or replaces a catalog entry (the model registry is a
// current-state table keyed by logical name, not append-only history).
func (s *Store) UpsertModelCatalog(e modelcatalog.Entry) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO models_catalog(name,url,sha256,file,port,ctx,host,kind) VALUES(?,?,?,?,?,?,?,?)`,
		e.Name, e.URL, e.SHA256, e.File, e.Port, e.Ctx, e.Host, e.Kind)
	return err
}

// ListModelCatalog returns the full model catalog, sorted by name.
func (s *Store) ListModelCatalog() ([]modelcatalog.Entry, error) {
	rows, err := s.db.Query(`SELECT name,url,sha256,file,port,ctx,host,COALESCE(kind,'') FROM models_catalog ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []modelcatalog.Entry
	for rows.Next() {
		var e modelcatalog.Entry
		if err := rows.Scan(&e.Name, &e.URL, &e.SHA256, &e.File, &e.Port, &e.Ctx, &e.Host, &e.Kind); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetModelCatalog returns one catalog entry by logical name.
func (s *Store) GetModelCatalog(name string) (e modelcatalog.Entry, ok bool, err error) {
	row := s.db.QueryRow(`SELECT name,url,sha256,file,port,ctx,host,COALESCE(kind,'') FROM models_catalog WHERE name=?`, name)
	switch e2 := row.Scan(&e.Name, &e.URL, &e.SHA256, &e.File, &e.Port, &e.Ctx, &e.Host, &e.Kind); e2 {
	case nil:
		return e, true, nil
	case sql.ErrNoRows:
		return modelcatalog.Entry{}, false, nil
	default:
		return modelcatalog.Entry{}, false, e2
	}
}

// DeleteModelCatalog removes a catalog entry by logical name.
func (s *Store) DeleteModelCatalog(name string) error {
	_, err := s.db.Exec(`DELETE FROM models_catalog WHERE name=?`, name)
	return err
}

// SeedModelCatalogIfEmpty inserts the fail-closed bootstrap catalog only when the
// table is empty, so operator edits are never clobbered on a later boot. Returns the
// resolved catalog (seeded or existing).
func (s *Store) SeedModelCatalogIfEmpty(seed []modelcatalog.Entry) ([]modelcatalog.Entry, error) {
	existing, err := s.ListModelCatalog()
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return existing, nil
	}
	for _, e := range seed {
		if err := s.UpsertModelCatalog(e); err != nil {
			return nil, err
		}
	}
	return s.ListModelCatalog()
}

// EventRow is one row of the calendar/events projection: a derived, deduped event
// parsed from the signed .ics outbox. The .ics stays the source of truth (it carries
// the M20 content credential); this table is what the calendar view serves and
// queries, rebuilt whenever the outbox changes.
type EventRow struct {
	Title       string
	Start       string
	End         string
	Location    string
	AllDay      bool
	HasReminder bool
	Signed      bool
	File        string
	Kind        string
	Due         string
	URL         string
}

// ReplaceEvents rebuilds the events projection in one transaction: it clears the
// table, inserts the deduped rows in order, and records the outbox fingerprint the
// projection was built from (so a reader can tell whether it is still fresh).
func (s *Store) ReplaceEvents(fingerprint string, rows []EventRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM events`); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO events(title,start_at,end_at,location,all_day,has_reminder,signed,file,kind,due_at,url) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.Title, r.Start, r.End, r.Location, b2i(r.AllDay), b2i(r.HasReminder), b2i(r.Signed), r.File, r.Kind, r.Due, r.URL); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO config(key,value) VALUES('events_fingerprint',?)`, fingerprint); err != nil {
		return err
	}
	return tx.Commit()
}

// LoadEvents returns the events projection (in insertion order) and the outbox
// fingerprint it was built from.
func (s *Store) LoadEvents() (fingerprint string, rows []EventRow, err error) {
	fingerprint, _, _ = s.GetConfig("events_fingerprint")
	r, err := s.db.Query(`SELECT title,start_at,end_at,location,all_day,has_reminder,signed,file,kind,due_at,url FROM events ORDER BY rowid`)
	if err != nil {
		return "", nil, err
	}
	defer r.Close()
	for r.Next() {
		var e EventRow
		var allDay, reminder, signed int
		if err := r.Scan(&e.Title, &e.Start, &e.End, &e.Location, &allDay, &reminder, &signed, &e.File, &e.Kind, &e.Due, &e.URL); err != nil {
			return "", nil, err
		}
		e.AllDay, e.HasReminder, e.Signed = allDay != 0, reminder != 0, signed != 0
		rows = append(rows, e)
	}
	return fingerprint, rows, r.Err()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ChatTurn is one persisted conversation turn.
type ChatTurn struct {
	ID               int64  `json:"id"`
	Role             string `json:"role"` // "user" | "assistant"
	Content          string `json:"content"`
	Sources          string `json:"sources"` // newline-joined doc ids (assistant turns)
	Model            string `json:"model"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	Rating           string `json:"rating"` // up | down | neutral | ""
	Unsafe           bool   `json:"unsafe"` // produced on the controls-off demo path
	At               string `json:"at"`
}

// AppendChatTurn stores one conversation turn and returns its id.
func (s *Store) AppendChatTurn(t ChatTurn) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO chat_turns(role,content,sources,model,prompt_tokens,completion_tokens,rating,unsafe) VALUES(?,?,?,?,?,?,?,?)`,
		t.Role, t.Content, t.Sources, t.Model, t.PromptTokens, t.CompletionTokens, t.Rating, boolToInt(t.Unsafe))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// LoadChatTurns returns the most recent `limit` turns in chronological order (oldest
// first), so the UI renders the thread and the model replays recent context.
func (s *Store) LoadChatTurns(limit int) ([]ChatTurn, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id,role,content,sources,model,prompt_tokens,completion_tokens,rating,COALESCE(unsafe,0),at FROM chat_turns ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChatTurn
	for rows.Next() {
		var t ChatTurn
		var unsafe int
		if err := rows.Scan(&t.ID, &t.Role, &t.Content, &t.Sources, &t.Model, &t.PromptTokens, &t.CompletionTokens, &t.Rating, &unsafe, &t.At); err != nil {
			return nil, err
		}
		t.Unsafe = unsafe != 0
		out = append(out, t)
	}
	// reverse to chronological order
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}

// SetChatRating records a thumbs up/down/neutral on an assistant turn.
func (s *Store) SetChatRating(id int64, rating string) error {
	_, err := s.db.Exec(`UPDATE chat_turns SET rating=? WHERE id=?`, rating, id)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ClearChatTurns wipes the conversation history.
func (s *Store) ClearChatTurns() error {
	_, err := s.db.Exec(`DELETE FROM chat_turns`)
	return err
}

// HideEvent records a calendar event as deleted by its content fingerprint; it is then
// filtered out of the calendar projection without touching the source .ics.
func (s *Store) HideEvent(key string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO hidden_events(key) VALUES(?)`, key)
	return err
}

// MarkExported records calendar events (by content fingerprint) as already downloaded in an
// .ics export, so the next "download new" export skips them (no duplicate calendar entries).
func (s *Store) MarkExported(keys []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO exported_events(key) VALUES(?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, k := range keys {
		if _, err := stmt.Exec(k); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// LoadExported returns the set of already-exported event fingerprints.
func (s *Store) LoadExported() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT key FROM exported_events`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// ResetExported clears the exported overlay so a subsequent export includes everything again.
func (s *Store) ResetExported() error {
	_, err := s.db.Exec(`DELETE FROM exported_events`)
	return err
}

// LoadHiddenEvents returns the set of deleted-event fingerprints.
func (s *Store) LoadHiddenEvents() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT key FROM hidden_events`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// ItemStatus is the mutable status overlay for one projected item, keyed by a content
// fingerprint stable across projection rebuilds.
type ItemStatus struct {
	Status      string // active | done | dismissed | snoozed
	SnoozeUntil string // ISO date the item stays hidden until (snoozed only)
}

// SetItemStatus upserts an item's status. status=="active" clears any override (the item
// returns to the default list), so toggling done→active is a delete, not a dead row.
func (s *Store) SetItemStatus(key, status, snoozeUntil string) error {
	if status == "active" || status == "" {
		_, err := s.db.Exec(`DELETE FROM item_status WHERE key=?`, key)
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO item_status(key,status,snooze_until,at) VALUES(?,?,?,CURRENT_TIMESTAMP)
		 ON CONFLICT(key) DO UPDATE SET status=excluded.status, snooze_until=excluded.snooze_until, at=CURRENT_TIMESTAMP`,
		key, status, snoozeUntil)
	return err
}

// LoadItemStatuses returns the current status overlay keyed by item fingerprint.
func (s *Store) LoadItemStatuses() (map[string]ItemStatus, error) {
	rows, err := s.db.Query(`SELECT key,status,snooze_until FROM item_status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ItemStatus{}
	for rows.Next() {
		var k, st, su string
		if err := rows.Scan(&k, &st, &su); err != nil {
			return nil, err
		}
		out[k] = ItemStatus{Status: st, SnoozeUntil: su}
	}
	return out, rows.Err()
}

// PersistedItem is one row of the deduped item projection: the item's source file +
// index (so an accept can resolve it) and the item itself as JSON.
type PersistedItem struct {
	File  string
	Index int
	JSON  string
}

// ReplaceItems rebuilds the deduped item projection in one transaction and records
// the fingerprint it was built from.
func (s *Store) ReplaceItems(fingerprint string, rows []PersistedItem) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM items`); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO items(file,idx,json) VALUES(?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.File, r.Index, r.JSON); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO config(key,value) VALUES('items_fingerprint',?)`, fingerprint); err != nil {
		return err
	}
	return tx.Commit()
}

// LoadItems returns the deduped item projection (in insertion order) and the
// fingerprint it was built from.
func (s *Store) LoadItems() (fingerprint string, rows []PersistedItem, err error) {
	fingerprint, _, _ = s.GetConfig("items_fingerprint")
	r, err := s.db.Query(`SELECT file,idx,json FROM items ORDER BY rowid`)
	if err != nil {
		return "", nil, err
	}
	defer r.Close()
	for r.Next() {
		var it PersistedItem
		if err := r.Scan(&it.File, &it.Index, &it.JSON); err != nil {
			return "", nil, err
		}
		rows = append(rows, it)
	}
	return fingerprint, rows, r.Err()
}

// SummaryRow is one row of the summaries projection: a per-email sidecar (the parsed
// EmailSummary, carried as its JSON) keyed by file name.
type SummaryRow struct {
	File string
	JSON string
}

// ReplaceSummaries rebuilds the summaries projection in one transaction and records
// the outbox fingerprint it was built from.
func (s *Store) ReplaceSummaries(fingerprint string, rows []SummaryRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM summaries`); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO summaries(file,json) VALUES(?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.File, r.JSON); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO config(key,value) VALUES('summaries_fingerprint',?)`, fingerprint); err != nil {
		return err
	}
	return tx.Commit()
}

// LoadSummaries returns the summaries projection (ordered by file) and the outbox
// fingerprint it was built from.
func (s *Store) LoadSummaries() (fingerprint string, rows []SummaryRow, err error) {
	fingerprint, _, _ = s.GetConfig("summaries_fingerprint")
	r, err := s.db.Query(`SELECT file,json FROM summaries ORDER BY file`)
	if err != nil {
		return "", nil, err
	}
	defer r.Close()
	for r.Next() {
		var row SummaryRow
		if err := r.Scan(&row.File, &row.JSON); err != nil {
			return "", nil, err
		}
		rows = append(rows, row)
	}
	return fingerprint, rows, r.Err()
}

// LatestPolicyItems returns the most recent persisted allowlist for name (stored
// newline-joined), so the resolver can rehydrate an active policy on boot.
func (s *Store) LatestPolicyItems(name string) (items []string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT items FROM policies WHERE name=? ORDER BY at DESC, rowid DESC LIMIT 1`, name)
	var joined string
	switch e := row.Scan(&joined); e {
	case nil:
		for _, it := range strings.Split(joined, "\n") {
			if it != "" {
				items = append(items, it)
			}
		}
		return items, true, nil
	case sql.ErrNoRows:
		return nil, false, nil
	default:
		return nil, false, e
	}
}

// RecordPolicy stores a versioned, hashed policy-allowlist artifact (items is the
// newline-joined allowlist: egress hosts, exec argv[0]s, guardrail topics, ...).
func (s *Store) RecordPolicy(name, version, hash, items string) error {
	_, err := s.db.Exec(`INSERT INTO policies(name,version,hash,items) VALUES(?,?,?,?)`, name, version, hash, items)
	return err
}

// RecordApproval stores a committed four-eyes decision.
func (s *Store) RecordApproval(id, proposer, approver, perm, note string, version int) error {
	_, err := s.db.Exec(`INSERT INTO approvals(id,proposer,approver,perm,note,version) VALUES(?,?,?,?,?,?)`,
		id, proposer, approver, perm, note, version)
	return err
}

// RecordPin stores an approved MCP manifest pin.
func (s *Store) RecordPin(server, hash, approvedBy string) error {
	_, err := s.db.Exec(`INSERT INTO mcp_pins(server,hash,approved_by) VALUES(?,?,?)`, server, hash, approvedBy)
	return err
}

// LatestPin returns the most recent approved manifest pin for a server.
func (s *Store) LatestPin(server string) (hash string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT hash FROM mcp_pins WHERE server=? ORDER BY at DESC, rowid DESC LIMIT 1`, server)
	switch err = row.Scan(&hash); err {
	case nil:
		return hash, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, err
	}
}

// MCPServerRow is one operator-registered tool server (manifest = declared tool names).
type MCPServerRow struct {
	Name  string
	URL   string
	Tools []string
}

// AddMCPServer upserts a registered tool server (name is the key).
func (s *Store) AddMCPServer(name, url string, tools []string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO mcp_servers(name,url,tools) VALUES(?,?,?)`,
		name, url, strings.Join(tools, ","))
	return err
}

// ListMCPServers returns every registered tool server, sorted by name.
func (s *Store) ListMCPServers() ([]MCPServerRow, error) {
	rows, err := s.db.Query(`SELECT name,url,tools FROM mcp_servers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPServerRow
	for rows.Next() {
		var r MCPServerRow
		var tools string
		if err := rows.Scan(&r.Name, &r.URL, &tools); err != nil {
			return nil, err
		}
		for _, t := range strings.Split(tools, ",") {
			if t = strings.TrimSpace(t); t != "" {
				r.Tools = append(r.Tools, t)
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteMCPServer removes a registered tool server and its pins.
func (s *Store) DeleteMCPServer(name string) error {
	if _, err := s.db.Exec(`DELETE FROM mcp_servers WHERE name=?`, name); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM mcp_pins WHERE server=?`, name)
	return err
}

// RecordEval stores an eval score (feeds the MLOps promotion gate).
func (s *Store) RecordEval(label string, f1 float64) error {
	_, err := s.db.Exec(`INSERT INTO eval_scores(label,f1) VALUES(?,?)`, label, f1)
	return err
}

// RecordAdmin stores an operator-action audit row.
func (s *Store) RecordAdmin(actor, action, detail string) error {
	_, err := s.db.Exec(`INSERT INTO admin_audit(actor,action,detail) VALUES(?,?,?)`, actor, action, detail)
	return err
}

// EvalScore is one recorded score.
type EvalScore struct {
	Label string
	F1    float64
	At    time.Time
}

// LatestEval returns the most recent score for a label. A promotion gate can
// read this so "ship to prod" is backed by a persisted, auditable score.
func (s *Store) LatestEval(label string) (EvalScore, bool, error) {
	row := s.db.QueryRow(`SELECT label,f1,at FROM eval_scores WHERE label=? ORDER BY at DESC, rowid DESC LIMIT 1`, label)
	var e EvalScore
	switch err := row.Scan(&e.Label, &e.F1, &e.At); err {
	case nil:
		return e, true, nil
	case sql.ErrNoRows:
		return EvalScore{}, false, nil
	default:
		return EvalScore{}, false, err
	}
}

// ListEvals returns recent eval scores (newest first) — the F1 trend for the
// console's Eval card.
func (s *Store) ListEvals(limit int) ([]EvalScore, error) {
	rows, err := s.db.Query(`SELECT label,f1,at FROM eval_scores ORDER BY at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvalScore
	for rows.Next() {
		var e EvalScore
		if err := rows.Scan(&e.Label, &e.F1, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PromptRow is a recorded prompt activation (text omitted from the list view).
type PromptRow struct {
	Name    string
	Version string
	Hash    string
	At      time.Time
}

// ListPrompts returns recent prompt activations, newest first.
func (s *Store) ListPrompts(limit int) ([]PromptRow, error) {
	rows, err := s.db.Query(`SELECT name,version,hash,at FROM prompts ORDER BY at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PromptRow
	for rows.Next() {
		var p PromptRow
		if err := rows.Scan(&p.Name, &p.Version, &p.Hash, &p.At); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PolicyRow is a recorded policy activation (items omitted from the list view).
type PolicyRow struct {
	Name    string
	Version string
	Hash    string
	At      time.Time
}

// ListPolicies returns recent policy activations, newest first.
func (s *Store) ListPolicies(limit int) ([]PolicyRow, error) {
	rows, err := s.db.Query(`SELECT name,version,hash,at FROM policies ORDER BY at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyRow
	for rows.Next() {
		var p PolicyRow
		if err := rows.Scan(&p.Name, &p.Version, &p.Hash, &p.At); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PinRow is a recorded MCP manifest pin.
type PinRow struct {
	Server     string
	Hash       string
	ApprovedBy string
	At         time.Time
}

// ListPins returns recent MCP manifest pins, newest first.
func (s *Store) ListPins(limit int) ([]PinRow, error) {
	rows, err := s.db.Query(`SELECT server,hash,approved_by,at FROM mcp_pins ORDER BY at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PinRow
	for rows.Next() {
		var p PinRow
		if err := rows.Scan(&p.Server, &p.Hash, &p.ApprovedBy, &p.At); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Approval is one recorded decision.
type Approval struct {
	ID       string
	Proposer string
	Approver string
	Perm     string
	Note     string
	Version  int
	At       time.Time
}

// ListApprovals returns recent approvals, newest first.
func (s *Store) ListApprovals(limit int) ([]Approval, error) {
	rows, err := s.db.Query(`SELECT id,proposer,approver,perm,note,version,at FROM approvals ORDER BY at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.Proposer, &a.Approver, &a.Perm, &a.Note, &a.Version, &a.At); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
