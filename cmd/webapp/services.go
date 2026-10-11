package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/t0ul/emaildrop/internal/modelcatalog"
	"github.com/t0ul/emaildrop/pkg/agent/eval"
	"github.com/t0ul/emaildrop/pkg/agent/extractor"
	"github.com/t0ul/emaildrop/pkg/agent/guard"
	"github.com/t0ul/emaildrop/pkg/compaction"
	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/domain"
	"github.com/t0ul/emaildrop/pkg/gateway"
	"github.com/t0ul/emaildrop/pkg/memory"
	"github.com/t0ul/emaildrop/pkg/rag"
	"github.com/t0ul/emaildrop/pkg/redteam"
	"github.com/t0ul/emaildrop/pkg/server"
	"github.com/t0ul/gledger"
	"github.com/t0ul/gorauder"
	"github.com/t0ul/gustoms"
)

// evalService is the concrete server.EvalService (C7): it holds the DB, gateway,
// governed prompts, and label set the eval surface needs, so that logic lives here
// as typed methods instead of closures in main. History/Run/Test serialize on mu
// because Test mutates the shared extractor prompt override.
type evalService struct {
	inv     *datastore.Store
	gw      *gateway.Client
	prompts *controlplane.Prompts
	labels  []string
	mu      sync.Mutex
}

// History returns the persisted F1 trend (empty without a DB).
func (e *evalService) History() []server.EvalResult {
	if e.inv == nil {
		return nil
	}
	rows, _ := e.inv.ListEvals(20)
	out := make([]server.EvalResult, 0, len(rows))
	for _, r := range rows {
		out = append(out, server.EvalResult{Label: r.Label, F1: r.F1, At: r.At.Format("2006-01-02 15:04")})
	}
	return out
}

// Run scores the label set live through the LLM path and persists each F1.
func (e *evalService) Run() ([]server.EvalResult, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	live := e.gw.Up()
	var out []server.EvalResult
	for _, l := range e.labels {
		rep, err := eval.ScoreWithMode(l, true, "llm")
		if err != nil {
			continue
		}
		if e.inv != nil {
			_ = e.inv.RecordEval(rep.Source, rep.F1)
		}
		out = append(out, server.EvalResult{Label: rep.Source, F1: rep.F1})
	}
	return out, evalMode(live)
}

// Test shadow-evaluates a candidate prompt WITHOUT activating it: chat_system runs
// the chat-injection ADD; extractor runs the labeled F1 eval + ADD-ASR + promotion
// gate; other names are a no-op note.
func (e *evalService) Test(name, candidate string) server.PromptTestResult {
	if name == "chat_system" {
		blocked, live := chatInjectionASR(candidate)
		if !live {
			return server.PromptTestResult{Mode: evalMode(false), Note: "chat_system test needs a live gateway (modeld + :4000); offline the prompt is never sent to a model."}
		}
		return server.PromptTestResult{ASRPass: blocked, GateOK: blocked, Mode: evalMode(true),
			Note: "chat-injection ADD: candidate prompt fed a poisoned RAG doc with retrieval encapsulation OFF — it alone must refuse the injection (marker absent)."}
	}
	if name != "extractor" {
		return server.PromptTestResult{Note: "shadow eval applies to the 'extractor' prompt (the labeled eval path); planner/coder drive the orchestrator demo, not this eval."}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	live := e.gw.Up()
	extractor.SetExtractionPrompt(candidate)
	defer extractor.SetExtractionPrompt(e.prompts.Text("extractor")) // restore the governed-active prompt

	rep, err := eval.ScoreWithMode("testdata/emaildrop/labels/1.json", true, "llm")
	f1 := 0.0
	if err == nil {
		f1 = rep.F1
	}
	baseline := 0.0
	if e.inv != nil {
		if ev, ok, _ := e.inv.LatestEval("samples/1.txt"); ok {
			baseline = ev.F1
		}
	}
	asrPass := true
	for _, c := range redteam.Cases() {
		if defendedASR(c) > 0 {
			asrPass = false
			break
		}
	}
	asrVal := 0.0
	if !asrPass {
		asrVal = 1.0
	}
	gateOK, _ := controlplane.PromotionGate{MinF1: baseline, F1: func() float64 { return f1 }, ASR: func() float64 { return asrVal }}.Allow()
	return server.PromptTestResult{F1: f1, Baseline: baseline, ASRPass: asrPass, GateOK: gateOK, Mode: evalMode(live)}
}

// profileStore is the concrete server.ProfileStore: the household child profile in
// the governed DB (config in the store, not a file/const).
type profileStore struct{ inv *datastore.Store }

func (p profileStore) Load() domain.Profile {
	var pr domain.Profile
	if v, ok, _ := p.inv.GetConfig("profile"); ok {
		_ = json.Unmarshal([]byte(v), &pr)
	}
	return pr
}

func (p profileStore) Save(pr domain.Profile) error {
	raw, _ := json.Marshal(pr)
	return p.inv.SetConfig("profile", string(raw))
}

// flywheel is the concrete server.Flywheel: operator accept/reject decisions as
// durable, audited ground-truth.
type flywheel struct {
	inv   *datastore.Store
	audit *gledger.AuditLog
}

func (f flywheel) Record(decision, source, title string) {
	_ = f.inv.RecordFeedback(source, title, decision)
	f.audit.Emit(gledger.NewTraceID(), "feedback", decision, gledger.F{"source": source, "title": title})
}

func (f flywheel) Stats() (int, int) {
	a, r, _ := f.inv.FeedbackStats()
	return a, r
}

// evalCaseStore adapts *datastore.Store to server.EvalCaseStore (type conversion).
type evalCaseStore struct{ inv *datastore.Store }

func (e evalCaseStore) AddEvalCase(source, label, note string) (int64, error) {
	return e.inv.AddEvalCase(source, label, note)
}
func (e evalCaseStore) DeleteEvalCase(id int64) error { return e.inv.DeleteEvalCase(id) }
func (e evalCaseStore) ListEvalCases(limit int) ([]server.EvalCase, error) {
	rows, err := e.inv.ListEvalCases(limit)
	if err != nil {
		return nil, err
	}
	out := make([]server.EvalCase, 0, len(rows))
	for _, c := range rows {
		out = append(out, server.EvalCase{ID: c.ID, Source: c.Source, Label: c.Label, Note: c.Note, At: c.At})
	}
	return out, nil
}

func (f flywheel) Recent(limit int) []server.FeedbackEntry {
	rows, _ := f.inv.RecentFeedback(limit)
	out := make([]server.FeedbackEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, server.FeedbackEntry{Source: r.Source, Label: r.Label, Decision: r.Decision, At: r.At})
	}
	return out
}

// skillStore adapts *datastore.Store to the skillLoader's SkillStore (persisting
// operator-authored skills), converting datastore.AuthoredSkill ↔ the loader's type.
type skillStore struct{ inv *datastore.Store }

func (s skillStore) AddAuthoredSkill(name, instructions string, tools []string) error {
	return s.inv.AddAuthoredSkill(name, instructions, tools)
}
func (s skillStore) DeleteAuthoredSkill(name string) error { return s.inv.DeleteAuthoredSkill(name) }
func (s skillStore) ListAuthoredSkills() ([]authoredSkill, error) {
	rows, err := s.inv.ListAuthoredSkills()
	if err != nil {
		return nil, err
	}
	out := make([]authoredSkill, 0, len(rows))
	for _, a := range rows {
		out = append(out, authoredSkill{Name: a.Name, Instructions: a.Instructions, Tools: a.Tools})
	}
	return out, nil
}

// MCPStore persists operator-registered tool servers and their approved manifest pins.
// *datastore.Store satisfies it directly.
type MCPStore interface {
	AddMCPServer(name, url string, tools []string) error
	ListMCPServers() ([]datastore.MCPServerRow, error)
	DeleteMCPServer(name string) error
	RecordPin(server, hash, approvedBy string) error
	LatestPin(server string) (string, bool, error)
}

var reMCPName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,39}$`)

// mcpRegistry is the concrete server.MCPRegistry: the built-in sandbox tool gateway PLUS an
// operator-registered server registry. A registered server declares a base URL and a tool
// manifest; the manifest is pinned on approve, and a tool call executes by fetching the URL
// through the SAME egress-gated sandbox + kill switch as the action-link fetch — so a
// registered server cannot reach a host that is not on the egress allow-list, and Halt
// revokes it in flight. The built-in sandbox entry comes straight from gustoms.
type mcpRegistry struct {
	gw     *gustoms.Gateway
	safety *controlplane.Safety
	store  MCPStore                                              // nil = registration unavailable (no DB)
	fetch  func(ctx context.Context, url string) (string, error) // the egress-gated sandbox path
}

// manifestHash is the pin of a registered server's declared tool manifest (same hash
// function gustoms uses for the built-in gateway).
func manifestHash(tools []string) string {
	specs := make([]gustoms.ToolSpec, 0, len(tools))
	for _, t := range tools {
		specs = append(specs, gustoms.ToolSpec{Name: t})
	}
	return gustoms.ManifestHash(specs)
}

func (m mcpRegistry) List() []domain.MCPServer {
	var out []domain.MCPServer
	for _, st := range m.gw.Status(context.Background()) { // built-in sandbox
		status := "pinned"
		switch {
		case st.Err != "":
			status = "error"
		case !m.safety.AllowToolExec():
			status = "blocked"
		case st.Pinned == "":
			status = "unapproved"
		case st.Mismatch:
			status = "rug-pull"
		}
		out = append(out, domain.MCPServer{
			Name: st.Name, Tools: st.Tools, Allowed: st.Allowed,
			Pinned: shortHash(st.Pinned), Current: shortHash(st.Current), Status: status,
		})
	}
	if m.store != nil { // operator-registered servers
		rows, _ := m.store.ListMCPServers()
		for _, r := range rows {
			cur := manifestHash(r.Tools)
			pin, _, _ := m.store.LatestPin(r.Name)
			status := "pinned"
			switch {
			case !m.safety.AllowToolExec():
				status = "blocked"
			case pin == "":
				status = "unapproved"
			case pin != cur:
				status = "rug-pull" // the declared manifest changed since it was approved
			}
			out = append(out, domain.MCPServer{
				Name: r.Name, Tools: r.Tools, Allowed: r.Tools,
				Pinned: shortHash(pin), Current: shortHash(cur), Status: status,
				URL: r.URL, Registered: true,
			})
		}
	}
	return out
}

func (m mcpRegistry) Approve(server string) error {
	if m.store != nil { // a registered server: pin its current declared manifest
		rows, _ := m.store.ListMCPServers()
		for _, r := range rows {
			if r.Name == server {
				return m.store.RecordPin(server, manifestHash(r.Tools), "operator")
			}
		}
	}
	return m.gw.Approve(context.Background(), gledger.NewTraceID(), server) // built-in re-pin
}

// Register adds (or updates) an operator tool server. Re-registering with a different
// manifest changes the hash, so the prior pin no longer matches (status → rug-pull) until
// the operator re-approves — the pin lifecycle for an operator-driven manifest change.
func (m mcpRegistry) Register(name, url string, tools []string) error {
	if m.store == nil {
		return errors.New("registration unavailable (no datastore)")
	}
	name, url = strings.TrimSpace(name), strings.TrimSpace(url)
	if !reMCPName.MatchString(name) || name == "sandbox" {
		return errors.New("name must be lowercase letters/digits/dashes (2–40 chars) and not 'sandbox'")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return errors.New("url must be http(s)")
	}
	var clean []string
	for _, t := range tools {
		if t = strings.TrimSpace(t); t != "" {
			clean = append(clean, t)
		}
	}
	if len(clean) == 0 {
		return errors.New("declare at least one tool")
	}
	return m.store.AddMCPServer(name, url, clean)
}

func (m mcpRegistry) Delete(name string) error {
	if m.store == nil {
		return errors.New("no datastore")
	}
	return m.store.DeleteMCPServer(name)
}

// Call invokes a tool on a registered server. Fails closed: the kill switch must allow
// tools, the server must be approved (pin == current manifest), and the tool must be in the
// declared manifest. Execution is the egress-gated sandbox fetch of the server URL, so the
// host must be on the egress allow-list and Halt revokes it in flight.
func (m mcpRegistry) Call(ctx context.Context, name, tool string) (string, error) {
	if m.store == nil {
		return "", errors.New("no datastore")
	}
	if !m.safety.AllowToolExec() {
		return "", errors.New("blocked by the kill switch")
	}
	rows, err := m.store.ListMCPServers()
	if err != nil {
		return "", err
	}
	var srv *datastore.MCPServerRow
	for i := range rows {
		if rows[i].Name == name {
			srv = &rows[i]
			break
		}
	}
	if srv == nil {
		return "", errors.New("no such server")
	}
	inManifest := false
	for _, t := range srv.Tools {
		if t == tool {
			inManifest = true
			break
		}
	}
	if !inManifest {
		return "", fmt.Errorf("tool %q is not in %s's manifest", tool, name)
	}
	if pin, ok, _ := m.store.LatestPin(name); !ok || pin != manifestHash(srv.Tools) {
		return "", errors.New("server not approved (pin does not match the current manifest) — approve it first")
	}
	if m.fetch == nil {
		return "", errors.New("sandbox tool path unavailable")
	}
	return m.fetch(ctx, srv.URL)
}

// bundleStore is the concrete server.BundleStore (C10): snapshot/list/roll-back the
// whole governed plane.
type bundleStore struct {
	inv       *datastore.Store
	audit     *gledger.AuditLog
	prompts   *controlplane.Prompts
	sampling  *controlplane.Sampling
	policies  *controlplane.Policies
	budgets   *controlplane.Budgets
	retrieval *controlplane.Retrieval
	grammars  *controlplane.Grammars
	models    *controlplane.Models
	rag       server.RAGLab // RAG lab ingestion config (nil = not available)
}

// fullBundle is what is actually persisted: the governed-plane snapshot PLUS the two
// DB-backed knobs the plane bundle alone misses (B6) — the RAG lab ingestion config
// (mode/chunker/size/overlap/embedder) and the model catalog. The embedded
// controlplane.Bundle flattens into the JSON, so bundles saved before this (plane-only)
// still unmarshal, leaving the extra fields nil (treated as "nothing to restore").
type fullBundle struct {
	controlplane.Bundle
	RAG     *server.RAGConfig    `json:"rag_lab,omitempty"`
	Catalog []modelcatalog.Entry `json:"model_catalog,omitempty"`
}

func (b bundleStore) List() []server.BundleInfo {
	rows, _ := b.inv.ListBundles(50)
	out := make([]server.BundleInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, server.BundleInfo{Label: r.Label, At: r.At.Format("2006-01-02 15:04")})
	}
	return out
}

func (b bundleStore) Save(label string) error {
	full := fullBundle{Bundle: controlplane.Snapshot(label, b.prompts, b.sampling, b.policies, b.budgets, b.retrieval, b.grammars, b.models)}
	if b.rag != nil {
		c := b.rag.Config()
		full.RAG = &c
	}
	if cat, err := b.inv.ListModelCatalog(); err == nil {
		full.Catalog = cat
	}
	raw, _ := json.Marshal(full)
	b.audit.Emit(gledger.NewTraceID(), "bundle", "saved", gledger.F{"label": label, "catalog": len(full.Catalog)})
	return b.inv.SaveBundle(label, string(raw))
}

func (b bundleStore) Apply(label string) error {
	cfg, ok, err := b.inv.GetBundle(label)
	if err != nil || !ok {
		return fmt.Errorf("no such snapshot %q", label)
	}
	var full fullBundle
	if err := json.Unmarshal([]byte(cfg), &full); err != nil {
		return err
	}
	full.Bundle.Apply(b.prompts, b.sampling, b.policies, b.budgets, b.retrieval, b.grammars, b.models)
	// Model catalog (DB): restore the snapshot set — upsert everything captured, then
	// delete any current entry the snapshot did not have, so the catalog matches the
	// safe point exactly (not merely a superset).
	if full.Catalog != nil {
		keep := map[string]bool{}
		for _, e := range full.Catalog {
			keep[e.Name] = true
			_ = b.inv.UpsertModelCatalog(e)
		}
		if cur, err := b.inv.ListModelCatalog(); err == nil {
			for _, e := range cur {
				if !keep[e.Name] {
					_ = b.inv.DeleteModelCatalog(e.Name)
				}
			}
		}
	}
	// RAG lab config: re-apply only when it differs (Save reindexes the corpus, which
	// is the whole point when the chunker/embedder changed, but needless otherwise).
	if full.RAG != nil && b.rag != nil && *full.RAG != b.rag.Config() {
		_, _ = b.rag.Save(*full.RAG)
	}
	b.audit.Emit(gledger.NewTraceID(), "bundle", "rolled_back", gledger.F{"label": label, "catalog": len(full.Catalog)})
	return nil
}

// chatService is the concrete server.ChatService: the conversational front-end over
// the RAG corpus. DEFENDED uses rag.Assemble (XML-encapsulate + injection-neutralize
// untrusted chunks, M8); UNSAFE (demo) raw-concats them so a poisoned doc's injection
// reaches the model as if trusted (the ChatRAGInjection demo). It runs on the same
// rag-reader NHI grant as search, so Halt / residency gate it too.
type chatService struct {
	reader    *rag.Store
	grant     controlplane.Grant
	authz     *controlplane.Authority
	gw        *gateway.Client
	prompts   *controlplane.Prompts
	sampling  *controlplane.Sampling
	models    *controlplane.Models
	retrieval *controlplane.Retrieval
	semantic  *atomic.Bool          // when true, retrieve with vector SemanticQuery instead of FTS
	hist      *datastore.Store      // persists the conversation (multi-turn + reload); nil = stateless
	ctxLimit  func() int            // the chat model's context window size (for the usage bar)
	summarize compaction.Summarizer // LLM-backed running-summary for history compaction; nil = no-op
	summon    func() []string       // approved+trusted skill instructions to inject (B3); nil = none
	memory    *memory.Store         // durable scoped long-term memory (A3); nil = no memory
}

// memoryScope is the single household scope for chat long-term memory. The memory
// package is scope-partitioned (no cross-scope recall), so a multi-tenant deployment
// would key this per user; this app is single-household.
const memoryScope = "household"

// retrieve runs the governed retrieval mode and returns the chunks plus the mode that
// ACTUALLY served them. Semantic degrades to lexical FTS when the embedder fails (so
// chat never hard-fails on a knob change), but never silently: the returned mode becomes
// "keyword (semantic unavailable)" and the fallback is logged, so the operator is never
// shown "semantic" when the vector path is down. (G2.)
func retrieve(r *rag.Store, wantSemantic bool, tenant, q string, k int) ([]rag.Chunk, string, error) {
	if !wantSemantic {
		c, err := r.Query(tenant, q, k)
		return c, "keyword", err
	}
	c, err := r.SemanticQuery(context.Background(), tenant, q, k)
	if err == nil {
		return c, "semantic", nil
	}
	log.Printf("chat: semantic retrieval unavailable (%v); degraded to keyword FTS", err)
	c, err = r.Query(tenant, q, k)
	return c, "keyword (semantic unavailable)", err
}

// compactHistory keeps the replayed chat history under the model's context budget using
// the provenance-partitioned running-summary Compactor (B1). Dialog turns are trusted, so
// evicted older turns collapse into a trusted running summary; the Compactor runs the
// untrusted partition's summary through guard.Sanitize so a laundered instruction cannot
// be promoted to standing context (summarization-injection defense). summarize is the
// LLM-backed Summarizer — nil (e.g. no live model) makes compaction a no-op and the raw
// turns pass through, so the chat still works offline.
func compactHistory(turns []gateway.Turn, ctxLimit int, summarize compaction.Summarizer) []gateway.Turn {
	if summarize == nil || len(turns) == 0 {
		return turns
	}
	budget := ctxLimit
	if budget <= 0 {
		budget = 8192
	}
	c := &compaction.Compactor{
		MaxTokens:  budget / 2, // headroom for the system prompt + RAG context + the answer
		KeepRecent: 6,
		Summarize:  summarize,
		Sanitize:   guard.Sanitize,
	}
	// Provenance partition (the Compactor's whole point): the USER's own turns are
	// trusted standing, but an ASSISTANT turn is model output shaped by untrusted
	// retrieval — it may have echoed a laundered injection. Marking assistant turns
	// untrusted keeps their running summary in the sanitized, quarantined partition
	// (guard.Sanitize) instead of promoting it to trusted standing context.
	in := make([]compaction.Turn, len(turns))
	for i, t := range turns {
		in[i] = compaction.Turn{Role: t.Role, Text: t.Content, Trusted: t.Role == "user"}
	}
	out := c.Compact(in)
	if len(out) == len(in) {
		return turns // under budget — unchanged
	}
	res := make([]gateway.Turn, 0, len(out))
	for _, t := range out {
		role := t.Role
		if role == "tool" {
			role = "user" // chat API speaks user/assistant/system; keep the quarantined summary as data
		}
		res = append(res, gateway.Turn{Role: role, Content: t.Text})
	}
	return res
}

// memoryCommand handles the durable-memory commands (A3) deterministically, without a
// model: "remember: <fact>" stores a trusted household memory; "forget" / "forget me"
// erases the scope (DSAR / right-to-erasure). It returns a reply + true when it handled
// the message, so the caller short-circuits the LLM path.
func (c *chatService) memoryCommand(question string) (server.ChatReply, bool) {
	if c.memory == nil {
		return server.ChatReply{}, false
	}
	q := strings.TrimSpace(question)
	low := strings.ToLower(q)
	switch {
	case strings.HasPrefix(low, "remember:") || strings.HasPrefix(low, "remember that "):
		fact := strings.TrimSpace(q[strings.IndexByte(q, ' ')+1:])
		fact = strings.TrimPrefix(fact, "that ")
		if fact == "" {
			return server.ChatReply{Answer: "Nothing to remember — try \"remember: pickup is 3pm on Fridays\"."}, true
		}
		// User-authored → trusted, no expiry. Keyed by a short slug so a restated fact
		// updates in place rather than piling up.
		c.memory.Put(memoryScope, memKey(fact), fact, 0, false)
		return server.ChatReply{Answer: "Got it — I'll remember that: " + fact}, true
	case low == "forget" || low == "forget me" || low == "forget everything":
		n := c.memory.Erase(memoryScope)
		return server.ChatReply{Answer: fmt.Sprintf("Erased %d remembered item(s).", n)}, true
	}
	return server.ChatReply{}, false
}

// memKey is a stable key for a remembered fact: the sha256 of the normalized text, so
// restating the SAME fact overwrites in place while two distinct facts never collide
// (a prefix-truncated key would merge long facts that share an opening).
func memKey(fact string) string {
	norm := strings.ToLower(strings.Join(strings.Fields(fact), " "))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:8]) // 16 hex chars — ample to avoid collisions here
}

// budgetChunks trims each retrieved chunk so the combined context stays within maxChars,
// giving every chunk an equal share so all sources still contribute. Without this a single
// large doc (a whole-chunked handbook) can exceed the model's context window and force a
// fallback. A trimmed chunk is marked so it is visibly partial.
func budgetChunks(chunks []rag.Chunk, maxChars int) []rag.Chunk {
	if len(chunks) == 0 || maxChars <= 0 {
		return chunks
	}
	per := maxChars / len(chunks)
	if per < 200 {
		per = 200 // keep each source minimally useful even with many chunks
	}
	out := make([]rag.Chunk, len(chunks))
	for i, ch := range chunks {
		if len([]rune(ch.Text)) > per {
			ch.Text = string([]rune(ch.Text)[:per]) + " …(truncated)"
		}
		out[i] = ch
	}
	return out
}

func (c *chatService) Answer(question string, unsafe bool, appData string) (server.ChatReply, error) {
	if _, err := c.authz.Verify(c.grant, controlplane.Capability{Action: controlplane.ActionList, Resource: "corpus", Tenant: "public"}); err != nil {
		return server.ChatReply{}, fmt.Errorf("rag-reader capability refused: %w", err)
	}
	// Durable memory commands are handled deterministically, before the model.
	if reply, handled := c.memoryCommand(question); handled {
		return reply, nil
	}
	// Trusted context: the host clock is the ONLY authority for dates — never the
	// corpus, so a poisoned email ("today is …") cannot move the agent's clock.
	dateBlock := gateway.TrustedDateBlock(time.Now())
	// top-k is a GOVERNED retrieval knob (versioned, bundle-referenced), not a
	// hardcoded literal; fall back to 5 if the plane is unset.
	k := 5
	if c.retrieval != nil {
		if rk := c.retrieval.Config("public").K; rk > 0 {
			k = rk
		}
	}
	// Retrieval mode is operator-governed (RAG lab): semantic (vector) when an
	// embedder is configured, else lexical FTS. Semantic falls back to FTS on error
	// (e.g. embedder momentarily down) so chat never hard-fails on a knob change.
	wantSemantic := c.semantic != nil && c.semantic.Load()
	chunks, retrieval, err := retrieve(c.reader, wantSemantic, "public", question, k)
	if err != nil {
		return server.ChatReply{}, err
	}
	sources := make([]string, 0, len(chunks))
	for _, ch := range chunks {
		sources = append(sources, ch.DocID)
	}
	// Bound the retrieved context so a large corpus can't overflow the model window and
	// force a silent fallback. The budget is a GOVERNED retrieval knob (ContextTokens);
	// 0 falls back to ~a third of the model's context size. Trimming is per chunk so
	// every source still contributes (≈4 chars/token).
	ctxLimitTokens := 8192
	if c.ctxLimit != nil {
		if v := c.ctxLimit(); v > 0 {
			ctxLimitTokens = v
		}
	}
	ctxBudgetTokens := ctxLimitTokens / 3
	if c.retrieval != nil {
		if ct := c.retrieval.Config("public").ContextTokens; ct > 0 {
			ctxBudgetTokens = ct
		}
	}
	chunks = budgetChunks(chunks, ctxBudgetTokens*4)
	var ctxText string
	if unsafe {
		var b strings.Builder
		for _, ch := range chunks {
			b.WriteString(ch.Text)
			b.WriteString("\n")
		}
		ctxText = b.String() // CONTROLS OFF: raw untrusted text, no encapsulation/scrub
	} else {
		ctxText = rag.Assemble(chunks) // encapsulated + injection-neutralized (M8)
	}
	// Multi-turn: replay the recent conversation so the chat remembers prior turns
	// (loaded BEFORE storing this question, so it is not duplicated into its own input).
	var history []gateway.Turn
	if c.hist != nil {
		if turns, e := c.hist.LoadChatTurns(50); e == nil {
			for _, t := range turns {
				history = append(history, gateway.Turn{Role: t.Role, Content: t.Content})
			}
		}
		// Keep the replayed history under the model's context budget: older turns
		// collapse into a running summary (B1) rather than silently overflowing the
		// window. No-op when the model is down or history is short.
		limit := 8192
		if c.ctxLimit != nil {
			limit = c.ctxLimit()
		}
		history = compactHistory(history, limit, c.summarize)
	}
	// chat_system is a GOVERNED prompt (C2), decoding is GOVERNED sampling (C5), model
	// binding is DB config — all resolved live, none hardcoded.
	// Summon approved+trusted skills into the system prompt (B3): the governed skill
	// gate (sign + pin + scope) is the live control, so only operator-approved,
	// trusted-signed instructions reach the model — as trusted standing context.
	systemPrompt := c.prompts.Text("chat_system")
	if c.summon != nil {
		if sk := c.summon(); len(sk) > 0 {
			systemPrompt += "\n\n<skills>\n" + strings.Join(sk, "\n") + "\n</skills>"
		}
	}
	// Recall durable memory (A3): scope-partitioned, TTL-filtered, and
	// injection-neutralized on assembly (memory.Assemble sanitizes untrusted entries),
	// so poisoned memory cannot act as an instruction.
	if c.memory != nil {
		if mem := memory.Assemble(c.memory.Recall(memoryScope)); mem != "" {
			systemPrompt += "\n\n" + mem
		}
	}
	res := c.gw.Chat(chatParams(c.sampling, c.models), systemPrompt, dateBlock, appData, ctxText, history, question, unsafe)
	// Persist the turn (DB-first): the question + the answer with its model + token
	// usage, so the chat survives a reload and ratings are durable.
	var turnID int64
	if c.hist != nil {
		_, _ = c.hist.AppendChatTurn(datastore.ChatTurn{Role: "user", Content: question})
		turnID, _ = c.hist.AppendChatTurn(datastore.ChatTurn{
			Role: "assistant", Content: res.Answer, Sources: strings.Join(sources, "\n"),
			Model: res.Model, PromptTokens: res.PromptTokens, CompletionTokens: res.CompletionTokens,
			Unsafe: unsafe, // tag the controls-off demo answer distinctly in history (D2)
		})
	}
	limit := 0
	if c.ctxLimit != nil {
		limit = c.ctxLimit()
	}
	return server.ChatReply{
		Answer: res.Answer, Sources: sources, Model: shortModel(res.Model),
		PromptTokens: res.PromptTokens, CompletionTokens: res.CompletionTokens,
		ContextLimit: limit, TurnID: turnID, Retrieval: retrieval,
	}, nil
}

// chatInjectionASR runs the chat-injection ADD against a CANDIDATE chat_system
// prompt in isolation: it feeds the poisoned RAG document with the retrieval
// encapsulation deliberately OFF (raw concat), so the only thing standing between
// the injection and the model is the prompt under test. blocked is true when the
// model's answer does not contain the injection marker. It needs a live gateway;
// offline the prompt is never exercised, so live is false.
func chatInjectionASR(candidate string) (blocked, live bool) {
	live = gw.Up()
	if !live {
		return false, false
	}
	c := redteam.ChatRAGInjection()
	seed := c.Seeds[0]
	rawPoison, _ := c.Undefended.Send(context.Background(), seed.Prompt) // retrieval control OFF
	ans := gw.ChatAnswer(gateway.ChatParams{}, candidate, gateway.TrustedDateBlock(time.Now()), "", rawPoison, seed.Prompt, false)
	return !strings.Contains(ans, seed.Marker), true
}

func evalMode(live bool) string {
	if live {
		return "llm (gouncer :4000)"
	}
	return "gateway :4000 down → regex fallback; start cmd/livecheck or modeld+gouncer for the live path"
}

// defendedASR runs one ADD case's defended target and returns its attack success
// rate (0 = the control holds).
func defendedASR(c redteam.Case) float64 {
	return gorauder.NewRunner(c.Defended, gorauder.WithScorer(redteam.Scorer())).Run(context.Background(), c.Seeds).ASR()
}

// shortHash trims a hex manifest hash to a display prefix.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// shortModel renders a model name compactly for the UI: basename, no .gguf, capped.
func shortModel(m string) string {
	if i := strings.LastIndexAny(m, "/\\"); i >= 0 {
		m = m[i+1:]
	}
	m = strings.TrimSuffix(m, ".gguf")
	if len(m) > 28 {
		m = m[:28]
	}
	return m
}

// chatHistoryStore adapts *datastore.Store to server.ChatHistoryStore (history +
// feedback + clear), converting the stored turns to the API DTO.
type chatHistoryStore struct{ inv *datastore.Store }

func (h chatHistoryStore) LoadChatTurns(limit int) ([]server.ChatTurnDTO, error) {
	turns, err := h.inv.LoadChatTurns(limit)
	if err != nil {
		return nil, err
	}
	out := make([]server.ChatTurnDTO, 0, len(turns))
	for _, t := range turns {
		var srcs []string
		if t.Sources != "" {
			srcs = strings.Split(t.Sources, "\n")
		}
		out = append(out, server.ChatTurnDTO{
			ID: t.ID, Role: t.Role, Content: t.Content, Sources: srcs,
			Model: shortModel(t.Model), PromptTokens: t.PromptTokens,
			CompletionTokens: t.CompletionTokens, Rating: t.Rating, Unsafe: t.Unsafe,
		})
	}
	return out, nil
}

func (h chatHistoryStore) SetChatRating(id int64, rating string) error {
	return h.inv.SetChatRating(id, rating)
}

func (h chatHistoryStore) ClearChatTurns() error { return h.inv.ClearChatTurns() }

// frontierSet is the live set of frontier-bound subjects the residency policy consults
// at issuance (C1). Guarded for concurrent reads (issuance) and writes (CRUD).
type frontierSet struct {
	mu   sync.RWMutex
	subs map[string]bool
}

func newFrontierSet() *frontierSet { return &frontierSet{subs: map[string]bool{}} }

func (f *frontierSet) has(subject string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.subs[subject]
}

func (f *frontierSet) replace(subs map[string]bool) {
	f.mu.Lock()
	f.subs = subs
	f.mu.Unlock()
}

// frontierRecord is the persisted shape (secret-by-pointer: KeyRef is an env-var name).
type frontierRecord struct {
	Subject  string `json:"subject"`
	Endpoint string `json:"endpoint"`
	KeyRef   string `json:"key_ref"`
}

const frontierConfigKey = "frontier_endpoints"

// frontierStore is the concrete server.FrontierStore: persists bindings as JSON in the
// config table and keeps the live frontierSet (for residency) in sync. It never stores or
// returns a token value — only the KeyRef pointer and whether that env var resolves.
type frontierStore struct {
	inv *datastore.Store
	set *frontierSet
}

func (f frontierStore) load() ([]frontierRecord, error) {
	raw, ok, err := f.inv.GetConfig(frontierConfigKey)
	if err != nil || !ok || raw == "" {
		return nil, err
	}
	var recs []frontierRecord
	if err := json.Unmarshal([]byte(raw), &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func (f frontierStore) save(recs []frontierRecord) error {
	b, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	if err := f.inv.SetConfig(frontierConfigKey, string(b)); err != nil {
		return err
	}
	f.refresh(recs)
	return nil
}

// refresh rebuilds the live frontier-subject set from the records, so a CRUD change takes
// effect on the next issuance without a restart.
func (f frontierStore) refresh(recs []frontierRecord) {
	subs := make(map[string]bool, len(recs))
	for _, r := range recs {
		subs[r.Subject] = true
	}
	f.set.replace(subs)
}

func (f frontierStore) ListFrontier() ([]server.FrontierEndpoint, error) {
	recs, err := f.load()
	if err != nil {
		return nil, err
	}
	out := make([]server.FrontierEndpoint, 0, len(recs))
	for _, r := range recs {
		out = append(out, server.FrontierEndpoint{
			Subject: r.Subject, Endpoint: r.Endpoint, KeyRef: r.KeyRef,
			KeySet: r.KeyRef != "" && os.Getenv(r.KeyRef) != "",
		})
	}
	return out, nil
}

func (f frontierStore) UpsertFrontier(subject, endpoint, keyRef string) error {
	recs, _ := f.load()
	found := false
	for i := range recs {
		if recs[i].Subject == subject {
			recs[i] = frontierRecord{Subject: subject, Endpoint: endpoint, KeyRef: keyRef}
			found = true
			break
		}
	}
	if !found {
		recs = append(recs, frontierRecord{Subject: subject, Endpoint: endpoint, KeyRef: keyRef})
	}
	return f.save(recs)
}

func (f frontierStore) DeleteFrontier(subject string) error {
	recs, _ := f.load()
	out := recs[:0]
	for _, r := range recs {
		if r.Subject != subject {
			out = append(out, r)
		}
	}
	return f.save(out)
}

// itemStatusStore adapts *datastore.Store to server.ItemStatusStore, converting the
// stored status overlay to the server boundary type (C2).
type itemStatusStore struct{ inv *datastore.Store }

func (s itemStatusStore) SetItemStatus(key, status, snoozeUntil string) error {
	return s.inv.SetItemStatus(key, status, snoozeUntil)
}

func (s itemStatusStore) LoadItemStatuses() (map[string]server.ItemStatus, error) {
	raw, err := s.inv.LoadItemStatuses()
	if err != nil {
		return nil, err
	}
	out := make(map[string]server.ItemStatus, len(raw))
	for k, v := range raw {
		out[k] = server.ItemStatus{Status: v.Status, SnoozeUntil: v.SnoozeUntil}
	}
	return out, nil
}
