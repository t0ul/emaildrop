// Package webapp is the local operator web app for managing the agent: run the
// security scorecard from the UI, and browse + replay incidents from the
// chain-verified audit log. It reuses the same Go components the agent runs on
// (redteam, ir), so the console and the system under test are one binary.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/t0ul/emaildrop/pkg/controlplane"
	"github.com/t0ul/emaildrop/pkg/domain"
	"github.com/t0ul/emaildrop/pkg/ir"
	"github.com/t0ul/emaildrop/pkg/netpolicy"
	"github.com/t0ul/emaildrop/pkg/provenance"
	"github.com/t0ul/emaildrop/pkg/redteam"
	"github.com/t0ul/emaildrop/ui"
	"github.com/t0ul/gledger"
	"github.com/t0ul/gorauder"
)

// Model/DTO boundary (MVC): the shared domain nouns live in pkg/domain
// (Profile/Child/SearchHit/MCPServer); the calendar event's model is
// pkg/agent/schema.Event. The response shapes defined in THIS package
// (PromptRow, PolicyRow, SamplingRow, BudgetRow, BundleInfo, EvalResult,
// PromptTestResult, Anchor, Event) are Controller-owned presentation DTOs by
// deliberate choice — they are the JSON wire format of specific handlers, not
// reusable domain types, so they stay next to the handler that serves them.

// Config holds the Server's dependencies — the collaborators main wires in. A nil
// optional dependency disables its feature (and its route/tab). Internal runtime
// state (mutexes, caches) lives on Server, not here. Build the Server with New.
type Config struct {
	AuditPath string // gledger log to read incidents from
	OutboxDir string // accepted .ics artifacts to render + offer for download
	InboxPath string // where the user drops .txt emails (shown in the UI)
	// Progress, when set, is fed by the watcher's hooks and served at /api/progress.
	Progress *Progress

	// Egress is the action-link allowlist (deny-by-default). Fetch performs the
	// vetted fetch — in production controlplane.SandboxFetchTool (in the MicroVM).
	// Both unset = action links are refused.
	Egress netpolicy.Policy
	Fetch  Fetcher
	// Quorum, when set, is the multi-party sign-off gate for an egress action (A4/A5):
	// the exact action string must carry attestations from a threshold of distinct
	// trusted agents (a2a signatures) or the fetch is refused. Nil = no quorum.
	Quorum func(action string) error
	// Verifier, when set, checks each .ics against its .sig content credential so
	// the UI can show whether the agent provably produced it unaltered (M20).
	Verifier *provenance.Verifier
	// Safety, when set, is the layered kill switch (M18): Pause refuses new
	// processing/drops; BlockTools refuses accept/action side effects.
	Safety *controlplane.Safety
	// Search, when set, answers Ask-School queries over the (PII-scrubbed)
	// retrieval corpus. Nil = the Ask tab returns nothing.
	Search func(query string, k int) ([]domain.SearchHit, error)
	// Index, when set with Fetch, powers safe handbook link enrichment (R6): it
	// adds fetched (untrusted, PII-scrubbed) text to the retrieval corpus.
	Index func(source, text string) error
	// Flywheel, when set, captures operator accept/reject decisions as durable
	// ground-truth (the data-flywheel) and reports the running tallies.
	Flywheel Flywheel
	// Chat, when set, answers a question grounded in the corpus. Nil = no chat.
	Chat ChatService

	// ChatHistory, when set, persists the conversation (history/feedback/clear API),
	// so the chat survives a reload and ratings are durable. Nil = no history/feedback.
	ChatHistory ChatHistoryStore

	// Authz, when set, turns the console into an authZ'd API: every mutating or
	// data-listing endpoint requires a capability Grant (C4b). The operator
	// holds one broad grant (OperatorToken); the agent and tools get narrower
	// ones. Nil = the gate is a no-op, so the loopback household app runs
	// unauthenticated. Verify is fail-closed and the kill switch (Authority.
	// Halted) revokes every grant, so Halt kills in-flight side effects too.
	Authz *controlplane.Authority
	// OperatorToken is the base64url(JSON) operator Grant injected into the Studio
	// page so the browser presents it on every /api and /ics request. Empty = none.
	OperatorToken string
	// AppToken is the NARROW household grant injected into the App page — it covers
	// only the consumer scopes (list corpus, write calendar/inbox/profile, export
	// link) and NOTHING on the governed control plane, so the App is cryptographically
	// unable to reach a governance endpoint. Empty = fall back to OperatorToken.
	AppToken string
	// Audit, when set, records every refused capability for the admin trail.
	Audit *gledger.AuditLog

	// Detect, when set, receives security-relevant signals the controller observes at
	// runtime (currently a burst of capability denials — a capability-probing signal).
	// main feeds these to the aidr engine, which auto-escalates the kill switch, so a
	// detection becomes automatic containment, not just a log line (A7). Nil = no AIDR.
	Detect func(span, event string, fields map[string]any)

	// MCP, when set, lists the MCP servers the agent reaches through the gustoms
	// gateway with their pin status and re-pins one on rug-pull recovery (C6).
	// Nil = no MCP tab.
	MCP MCPRegistry

	// Prompts, when set, is the governed prompt resolver (C2): the console lists
	// each model's active/default system prompt, activates a new versioned+hashed
	// version, and rolls back to the shipped default. Nil = no Prompts tab.
	Prompts *controlplane.Prompts

	// Budgets, when set, is the governed budgets/limits resolver (C9): rate/token/
	// concurrency/spend ceilings + key POINTERS (env-var names, never values). The
	// "api" budget's RatePerMin and MaxConcurrency are enforced on the console API
	// here; per-model token/spend caps are enforced gateway-side (and labeled so in the
	// Budgets tab). Nil = no Budgets tab, no rate/concurrency limit.
	Budgets *controlplane.Budgets

	// Sampling, when set, is the governed decoding-params resolver (C5):
	// temperature/max_tokens/seed per model as versioned, hashed, rollback-able
	// artifacts. Nil = no Sampling tab.
	Sampling *controlplane.Sampling

	// Retrieval, when set, is the governed RAG read-knob resolver (top-k per corpus)
	// as versioned, hashed, rollback-able artifacts. Nil = no Retrieval tab.
	Retrieval *controlplane.Retrieval

	// Grammars, when set, is the governed output-grammar resolver (the GBNF the
	// extractor constrains output with) as versioned, hashed, rollback-able
	// artifacts. Nil = no Grammar tab.
	Grammars *controlplane.Grammars

	// Models, when set, is the governed model-binding resolver (the logical model
	// each role routes to) as versioned, hashed, rollback-able artifacts. Nil = no
	// Models tab.
	Models *controlplane.Models

	// ModelCatalog, when set, reads and writes the DB-backed model catalog (single
	// source of truth for which models exist: verified URL/SHA, file, serve port/ctx).
	// Shown in the Models tab with add/edit/delete. Nil = no catalog card.
	ModelCatalog ModelCatalogStore

	// Events, when set, is the DB-backed calendar/events projection: the calendar
	// view serves deduped events from here (not a per-request .ics scan), rebuilt
	// from the signed .ics outbox whenever it changes. Nil = read straight from .ics.
	Events EventStore

	// Summaries, when set, is the DB-backed projection of the per-email summary
	// sidecars: the Tasks/digest/Directory/Review views serve from here instead of
	// re-scanning + re-parsing every .summary.json per request. Nil = read from JSON.
	Summaries SummaryStore

	// Items, when set, is the DB-backed DEDUPED item projection: the Tasks tab and
	// mini-calendar serve deduped items from here, built (dupes removed) once and
	// stored rather than re-deduped per request. Nil = dedup at read, not persisted.
	Items ItemStore

	// ItemStatus, when set, is the mutable status overlay for projected items
	// (done/dismiss/snooze), keyed by a rebuild-stable content fingerprint. Nil = the
	// Tasks tab shows items but cannot durably complete or dismiss them.
	ItemStatus ItemStatusStore

	// Frontier, when set, is the frontier endpoint binding store (C1): point a subject
	// at an off-host model with a secret-by-pointer KeyRef. Binding a subject here marks
	// it frontier-bound for the residency policy. Nil = no Frontier card.
	Frontier FrontierStore

	// HiddenEvents, when set, is the calendar delete overlay: a deleted event is hidden
	// by fingerprint without mutating the source .ics. Nil = events cannot be deleted.
	HiddenEvents HiddenEventStore

	// Exported, when set, records which events have been downloaded in an .ics export, so
	// "download new" skips them (no duplicates on the real calendar). Nil = no incremental.
	Exported ExportedStore

	// RAG, when set, is the retrieval experimentation surface (RAG tab): tune the
	// ingestion config (mode/chunker/size/overlap/embedder) and reindex. Nil = no tab.
	RAG RAGLab

	// Runtime health inputs (the Runtime tab / cmd/preflight-in-console): the asset
	// dir holding GGUFs, the gateway URL (display), and a gateway health probe.
	AssetsDir  string
	GatewayURL string
	GatewayUp  func() bool
	// VMURL / VMUp report the MicroVM sandbox fetcher used by enrich (handbook links).
	// The Runtime panel shows it so an operator sees the VM is down BEFORE trying to
	// enrich — the webapp auto-starts the models but NOT the VM (it is launched out of
	// band with `launchvm`), so enrich degrades with a clear message when it is absent.
	VMURL string
	VMUp  func() bool
	// Runtime, when set, is the in-console model-stack start/stop control (C3). Nil =
	// the Runtime panel is health-only.
	Runtime RuntimeControl
	// IdentityEphemeral is true when the agent is running on a throwaway in-memory
	// signing key (the persistent seed could not be loaded/persisted). Surfaced red in
	// the Runtime panel: previously signed .ics will not verify and the key dies on
	// restart. The boot path refuses to start in this state unless explicitly opted in.
	IdentityEphemeral bool

	// Skills, when set, is the governed skill-approval resolver (the pin side of the
	// skills supply-chain control): which skill versions an operator has approved.
	// Fail-closed — an unapproved skill is never loadable. Nil = no Skills tab.
	Skills *controlplane.Skills

	// SkillCatalog, when set, is the live consumer of Skills: it loads a named skill
	// through the governed sign+pin+scope gate and lists the supply for the Studio.
	SkillCatalog SkillLoader

	// Policies, when set, is the governed policy-allowlist resolver (C8): egress /
	// exec / guardrail allowlists as versioned, hashed, rollback-able artifacts.
	// The action egress check resolves its allowlist from here at request time, so
	// a governed change takes effect with no redeploy. Nil = no Policies tab and
	// the static Egress is used.
	Policies *controlplane.Policies

	// Profile, when set, reads/writes the household child profile (R1) in the
	// governed DB — config lives in the store, not a file or a const. Operator-set,
	// host-only, never from an email. Enables the My Week tab.
	Profile ProfileStore

	// Bundles, when set, is the known-good snapshot surface (C10): list saved
	// snapshots, snapshot the whole governed plane, roll it all back. Nil = no card.
	Bundles BundleStore

	// Eval backs the Eval tab + Test button (C7). Nil = no Eval tab / Test button.
	Eval EvalService

	// EvalCases, when set, is the promoted-regression watchlist (feedback→eval loop):
	// the operator promotes a thumbs-down example into a durable case. Nil = no promote.
	EvalCases EvalCaseStore
}

// EvalService is the Controller's view of the eval surface (C7): persisted F1
// history (the trend card), a live eval run that scores + persists, and a shadow
// prompt test (F1 + ADD-ASR + promotion-gate verdict) that never activates the
// candidate. The concrete implementation and its model/DB/gateway dependencies
// live in cmd/webapp, out of the handlers.
type EvalService interface {
	History() []EvalResult
	Run() (results []EvalResult, mode string)
	Test(name, candidate string) PromptTestResult
}

// ChatReply is a chat answer plus its observability: the sources it grounded on, the
// model that answered, the token usage (prompt tokens ≈ context window in use), the
// model's context limit, and the persisted turn id (so the UI can rate it).
type ChatReply struct {
	Answer           string   `json:"answer"`
	Sources          []string `json:"sources"`
	Model            string   `json:"model"`
	PromptTokens     int      `json:"prompt_tokens"`
	CompletionTokens int      `json:"completion_tokens"`
	ContextLimit     int      `json:"context_limit"`
	TurnID           int64    `json:"turn_id"`
	// Retrieval is the mode that actually served this answer: "semantic", "keyword",
	// or "keyword (semantic unavailable)" when the vector path was requested but the
	// embedder failed and it fell back to FTS. Surfaced so the operator is never told
	// retrieval is semantic when it silently degraded to lexical.
	Retrieval string `json:"retrieval,omitempty"`
}

// ChatService answers a natural-language question grounded in the corpus, carrying the
// conversation history so it is multi-turn, and persisting the turn. unsafe=true runs
// the UNDEFENDED path (raw-concat retrieval) — the live attack demo. appData is the
// server-supplied trusted app context (the calendar). Impl + deps live in cmd/webapp.
type ChatService interface {
	Answer(question string, unsafe bool, appData string) (ChatReply, error)
}

// ChatHistoryStore persists the conversation (DB-backed), so the chat survives a
// reload and ratings are durable. The concrete impl lives in cmd/webapp.
type ChatHistoryStore interface {
	LoadChatTurns(limit int) ([]ChatTurnDTO, error)
	SetChatRating(id int64, rating string) error
	ClearChatTurns() error
}

// ChatTurnDTO is one persisted conversation turn for the history/feedback API.
type ChatTurnDTO struct {
	ID               int64    `json:"id"`
	Role             string   `json:"role"`
	Content          string   `json:"content"`
	Sources          []string `json:"sources"`
	Model            string   `json:"model"`
	PromptTokens     int      `json:"prompt_tokens"`
	CompletionTokens int      `json:"completion_tokens"`
	Rating           string   `json:"rating"`
	Unsafe           bool     `json:"unsafe,omitempty"` // controls-off demo turn
}

// Flywheel captures operator accept/reject decisions as durable ground-truth and
// reports the running tallies (the data-flywheel). Recent returns the raw examples so
// Studio can surface WHAT was rated (the signal the operator tunes against).
type Flywheel interface {
	Record(decision, source, title string)
	Stats() (accepts, rejects int)
	Recent(limit int) []FeedbackEntry
}

// FeedbackEntry is one recorded feedback signal surfaced to the operator in Studio.
type FeedbackEntry struct {
	Source   string `json:"source"`
	Label    string `json:"label"`
	Decision string `json:"decision"`
	At       string `json:"at"`
}

// MCPRegistry lists the governed MCP servers with pin status and re-pins one on
// rug-pull recovery (C6).
type MCPRegistry interface {
	List() []domain.MCPServer
	Approve(server string) error
	// Register adds/updates an operator tool server (name + URL + declared tool manifest);
	// Delete removes one; Call invokes a declared tool through the egress-gated sandbox.
	Register(name, url string, tools []string) error
	Delete(name string) error
	Call(ctx context.Context, name, tool string) (string, error)
}

// ProfileStore reads/writes the household child profile (R1) in the governed DB.
type ProfileStore interface {
	Load() domain.Profile
	Save(domain.Profile) error
}

// BundleStore is the known-good snapshot surface (C10): list, snapshot, roll back.
type BundleStore interface {
	List() []BundleInfo
	Save(label string) error
	Apply(label string) error
}

// Server serves the dashboard and its API. Build it with New — the zero value is
// not ready (its maps are nil). Dependencies live in the embedded Config; the
// fields below are internal runtime state.
type Server struct {
	Config

	// api rate-limit window (the Budgets "api" ceiling, enforced in authz).
	rlMu     sync.Mutex
	rlCount  int
	rlWindow time.Time
	inflight atomic.Int64 // in-flight console API requests (governed MaxConcurrency budget)

	denyMu     sync.Mutex
	denyCount  int // capability denials in the current window (AIDR deny-storm detector)
	denyWindow time.Time
	denyFired  bool // deny-storm already reported this window (fire once)

	// pending holds issued-but-unconfirmed HITL approvals, keyed by nonce (ASI09:
	// evidence-first, single-use, clickjack/forgery-resistant confirm).
	mu   sync.Mutex
	pend map[string]pending

	// event cache (events.go): the parsed outbox, keyed by a fingerprint of the
	// .ics/.sig entries so repeated reads don't re-parse+re-verify every file. Any
	// add/remove/in-place edit changes the fingerprint and invalidates it.
	evMu    sync.Mutex
	evCache []Event
	evFP    string

	// summary cache (items.go): the parsed .summary.json sidecars, keyed by a
	// fingerprint of those files, so the Tasks/digest/Directory/Review views don't
	// re-read+re-parse every sidecar per request.
	smMu    sync.Mutex
	smCache []namedSummary
	smFP    string

	// item cache (items.go): the deduped item projection, keyed by the summaries
	// fingerprint, so the Tasks/mini-cal views serve a deduped list without re-deduping.
	itMu    sync.Mutex
	itCache []itemRow
	itFP    string
}

// New builds a ready Server from its dependencies. It initializes internal state
// (the HITL pending map) so there is one valid construction path instead of a raw
// struct literal with lazy map init. Dependencies are optional by design — a nil
// one disables its feature — so New only warns on obvious mis-wirings rather than
// failing.
func New(c Config) *Server {
	if c.Index != nil && c.Fetch == nil {
		log.Print("server.New: Index set without Fetch; link enrichment is disabled")
	}
	return &Server{Config: c, pend: map[string]pending{}}
}

// verifySig reports whether <name>.sig is a valid content credential over the
// given .ics bytes from a trusted agent key.
func (s *Server) verifySig(name string, content []byte) bool {
	if s.Verifier == nil {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(s.OutboxDir, name+".sig"))
	if err != nil {
		return false
	}
	var m provenance.Mark
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	return s.Verifier.Verify(content, m) == nil
}

// Handler returns the app routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Reads are capability-gated in two tiers so the App token (list/corpus) can read
	// the HOUSEHOLD views it needs but NOT operator/governance state or its PII, and a
	// foreign/no token reads nothing. Operator reads require list/"operator", which only
	// the operator (wildcard) grant covers. (Household mode = Authz nil = all no-ops.)
	op := func(h http.HandlerFunc) http.HandlerFunc { return s.authz(controlplane.ActionList, "operator", h) }
	consumer := func(h http.HandlerFunc) http.HandlerFunc { return s.authz(controlplane.ActionList, "corpus", h) }
	mux.HandleFunc("/api/scorecard", op(s.scorecard))
	mux.HandleFunc("/api/incidents", op(s.incidents))
	mux.HandleFunc("/api/incident", op(s.incident))
	mux.HandleFunc("/api/activity", op(s.activity))
	mux.HandleFunc("/api/commands", op(s.commands))
	mux.HandleFunc("/api/safety", op(s.safetyState))
	mux.HandleFunc("/api/events", consumer(s.events))
	mux.HandleFunc("/api/progress", consumer(s.progress))
	mux.HandleFunc("/api/calendar.ics", consumer(s.calendarExport))                                                 // the whole calendar as .ics
	mux.HandleFunc("POST /api/calendar/export", csrf(s.authz(controlplane.ActionWrite, "calendar", s.calendarExportNew)))       // only new, marks exported
	mux.HandleFunc("POST /api/calendar/reset-exported", csrf(s.authz(controlplane.ActionWrite, "calendar", s.calendarResetExported)))
	mux.HandleFunc("/api/items", consumer(s.items))
	mux.HandleFunc("/api/summary", consumer(s.summary))
	mux.HandleFunc("/api/review", consumer(s.review))
	// The kill switch is break-glass gated (authzGlass): scope is enforced (the App
	// token cannot toggle it), but the Halt/revocation and rate checks are bypassed so
	// an operator can always DISENGAGE a halt that revoked every grant.
	mux.HandleFunc("POST /api/killswitch", csrf(s.authzGlass(controlplane.ActionWrite, "safety", s.killswitch)))
	// Ask lists the retrieval corpus — ActionList, the data-residency-sensitive
	// endpoint (a frontier reader must not harvest it).
	mux.HandleFunc("/api/ask", s.authz(controlplane.ActionList, "corpus", s.ask))
	if s.Chat != nil {
		mux.HandleFunc("POST /api/chat", csrf(s.authz(controlplane.ActionList, "corpus", s.chat)))
	}
	if s.ChatHistory != nil {
		mux.HandleFunc("/api/chat/history", s.authz(controlplane.ActionList, "corpus", s.chatHistory))
		mux.HandleFunc("POST /api/chat/feedback", csrf(s.authz(controlplane.ActionList, "corpus", s.chatFeedback)))
		mux.HandleFunc("POST /api/chat/clear", csrf(s.authz(controlplane.ActionList, "corpus", s.chatClear)))
	}
	if s.MCP != nil {
		mux.HandleFunc("/api/mcp", op(s.mcpList))
		mux.HandleFunc("POST /api/mcp/approve", csrf(s.authz(controlplane.ActionWrite, "mcp", s.mcpApprove)))
		mux.HandleFunc("POST /api/mcp/register", csrf(s.authz(controlplane.ActionWrite, "mcp", s.mcpRegister)))
		mux.HandleFunc("POST /api/mcp/delete", csrf(s.authz(controlplane.ActionWrite, "mcp", s.mcpDelete)))
		mux.HandleFunc("POST /api/mcp/call", csrf(s.authz(controlplane.ActionWrite, "mcp", s.mcpCall)))
	}
	if s.Prompts != nil {
		mux.HandleFunc("/api/prompts", op(s.promptsList))
		mux.HandleFunc("POST /api/prompts/activate", csrf(s.authz(controlplane.ActionWrite, "prompts", s.promptsActivate)))
		mux.HandleFunc("POST /api/prompts/reset", csrf(s.authz(controlplane.ActionWrite, "prompts", s.promptsReset)))
	}
	if s.Budgets != nil {
		mux.HandleFunc("/api/budgets", op(s.budgetsList))
		mux.HandleFunc("POST /api/budgets/activate", csrf(s.authz(controlplane.ActionWrite, "budget", s.budgetsActivate)))
		mux.HandleFunc("POST /api/budgets/reset", csrf(s.authz(controlplane.ActionWrite, "budget", s.budgetsReset)))
	}
	if s.Sampling != nil {
		mux.HandleFunc("/api/sampling", op(s.samplingList))
		mux.HandleFunc("POST /api/sampling/activate", csrf(s.authz(controlplane.ActionWrite, "sampling", s.samplingActivate)))
		mux.HandleFunc("POST /api/sampling/reset", csrf(s.authz(controlplane.ActionWrite, "sampling", s.samplingReset)))
	}
	if s.Retrieval != nil {
		mux.HandleFunc("/api/retrieval", op(s.retrievalList))
		mux.HandleFunc("POST /api/retrieval/activate", csrf(s.authz(controlplane.ActionWrite, "retrieval", s.retrievalActivate)))
		mux.HandleFunc("POST /api/retrieval/reset", csrf(s.authz(controlplane.ActionWrite, "retrieval", s.retrievalReset)))
	}
	if s.Grammars != nil {
		mux.HandleFunc("/api/grammar", op(s.grammarList))
		mux.HandleFunc("POST /api/grammar/activate", csrf(s.authz(controlplane.ActionWrite, "grammar", s.grammarActivate)))
		mux.HandleFunc("POST /api/grammar/reset", csrf(s.authz(controlplane.ActionWrite, "grammar", s.grammarReset)))
	}
	if s.Models != nil {
		mux.HandleFunc("/api/models", op(s.modelsList))
		mux.HandleFunc("POST /api/models/activate", csrf(s.authz(controlplane.ActionWrite, "model", s.modelsActivate)))
		mux.HandleFunc("POST /api/models/reset", csrf(s.authz(controlplane.ActionWrite, "model", s.modelsReset)))
	}
	if s.ModelCatalog != nil {
		mux.HandleFunc("/api/modelcatalog", op(s.modelCatalogList))
		mux.HandleFunc("POST /api/modelcatalog/upsert", csrf(s.authz(controlplane.ActionWrite, "model", s.modelCatalogUpsert)))
		mux.HandleFunc("POST /api/modelcatalog/delete", csrf(s.authz(controlplane.ActionWrite, "model", s.modelCatalogDelete)))
		mux.HandleFunc("POST /api/modelcatalog/download", csrf(s.authz(controlplane.ActionWrite, "model", s.modelCatalogDownload)))
	}
	if s.Runtime != nil {
		mux.HandleFunc("POST /api/runtime/start", csrf(s.authz(controlplane.ActionWrite, "model", s.runtimeStart)))
		mux.HandleFunc("POST /api/runtime/stop", csrf(s.authz(controlplane.ActionWrite, "model", s.runtimeStop)))
	}
	if s.Frontier != nil {
		mux.HandleFunc("/api/frontier", op(s.frontierList))
		mux.HandleFunc("POST /api/frontier/upsert", csrf(s.authz(controlplane.ActionWrite, "model", s.frontierUpsert)))
		mux.HandleFunc("POST /api/frontier/delete", csrf(s.authz(controlplane.ActionWrite, "model", s.frontierDelete)))
	}
	// Runtime health/status is always available (it shows gateway + identity + sandbox
	// even with no catalog); the start/stop controls above gate on Runtime.
	mux.HandleFunc("/api/runtime", op(s.runtimeStatus))
	if s.RAG != nil {
		mux.HandleFunc("/api/rag", op(s.ragGet))
		mux.HandleFunc("POST /api/rag/save", csrf(s.authz(controlplane.ActionWrite, "rag", s.ragSave)))
		mux.HandleFunc("POST /api/rag/reindex", csrf(s.authz(controlplane.ActionWrite, "rag", s.ragReindex)))
	}
	if s.Skills != nil {
		mux.HandleFunc("/api/skills", op(s.skillsList))
		mux.HandleFunc("POST /api/skills/approve", csrf(s.authz(controlplane.ActionWrite, "skill", s.skillsApprove)))
		mux.HandleFunc("POST /api/skills/reset", csrf(s.authz(controlplane.ActionWrite, "skill", s.skillsReset)))
		mux.HandleFunc("POST /api/skills/load", csrf(s.authz(controlplane.ActionWrite, "skill", s.skillsLoad)))
		mux.HandleFunc("POST /api/skills/author", csrf(s.authz(controlplane.ActionWrite, "skill", s.skillsAuthor)))
		mux.HandleFunc("POST /api/skills/delete", csrf(s.authz(controlplane.ActionWrite, "skill", s.skillsDelete)))
	}
	if s.Policies != nil {
		mux.HandleFunc("/api/policies", op(s.policiesList))
		mux.HandleFunc("POST /api/policies/activate", csrf(s.authz(controlplane.ActionWrite, "policy", s.policiesActivate)))
		mux.HandleFunc("POST /api/policies/reset", csrf(s.authz(controlplane.ActionWrite, "policy", s.policiesReset)))
	}
	if s.Flywheel != nil {
		mux.HandleFunc("/api/flywheel", op(s.flywheel))
	}
	if s.Eval != nil {
		mux.HandleFunc("/api/eval", op(s.evalList))
		mux.HandleFunc("POST /api/eval/run", csrf(s.authz(controlplane.ActionWrite, "eval", s.evalRunHandler)))
		mux.HandleFunc("POST /api/prompts/test", csrf(s.authz(controlplane.ActionWrite, "prompts", s.promptsTest)))
	}
	if s.EvalCases != nil {
		mux.HandleFunc("/api/eval/cases", op(s.evalCasesList))
		mux.HandleFunc("POST /api/eval/cases/promote", csrf(s.authz(controlplane.ActionWrite, "eval", s.evalCasePromote)))
		mux.HandleFunc("POST /api/eval/cases/delete", csrf(s.authz(controlplane.ActionWrite, "eval", s.evalCaseDelete)))
	}
	if s.Bundles != nil {
		mux.HandleFunc("/api/bundles", op(s.bundlesList))
		mux.HandleFunc("POST /api/bundles/save", csrf(s.authz(controlplane.ActionWrite, "bundle", s.bundlesSave)))
		mux.HandleFunc("POST /api/bundles/apply", csrf(s.authz(controlplane.ActionWrite, "bundle", s.bundlesApply)))
	}
	if s.Profile != nil {
		mux.HandleFunc("/api/timeline", consumer(s.timeline))
		mux.HandleFunc("/api/week", consumer(s.week))
		mux.HandleFunc("/api/profile", consumer(s.profileGet))
		mux.HandleFunc("POST /api/profile/save", csrf(s.authz(controlplane.ActionWrite, "profile", s.profileSave)))
	}
	if s.InboxPath != "" {
		mux.HandleFunc("POST /api/drop", csrf(s.authz(controlplane.ActionWrite, "inbox", s.drop)))
	}
	if s.OutboxDir != "" {
		mux.HandleFunc("POST /api/accept", csrf(s.authz(controlplane.ActionWrite, "calendar", s.accept)))
		mux.HandleFunc("POST /api/reject", csrf(s.authz(controlplane.ActionWrite, "calendar", s.reject)))
		mux.HandleFunc("POST /api/items/status", csrf(s.authz(controlplane.ActionWrite, "calendar", s.itemStatus)))
		mux.HandleFunc("POST /api/events/create", csrf(s.authz(controlplane.ActionWrite, "calendar", s.eventCreate)))
		mux.HandleFunc("POST /api/events/delete", csrf(s.authz(controlplane.ActionWrite, "calendar", s.eventDelete)))
		mux.HandleFunc("POST /api/feedback", csrf(s.authz(controlplane.ActionList, "corpus", s.feedback)))
		mux.HandleFunc("POST /api/action", csrf(s.authz(controlplane.ActionExport, "link", s.action))) // egress
	}
	if s.Fetch != nil && s.Index != nil {
		mux.HandleFunc("POST /api/enrich", csrf(s.authz(controlplane.ActionExport, "link", s.enrich))) // egress → corpus
	}
	if s.OutboxDir != "" {
		mux.HandleFunc("/ics/", consumer(s.serveICS))           // .ics only — NOT the whole outbox (sidecars hold PII)
		mux.HandleFunc("/api/directory", consumer(s.directory)) // consolidated contacts (R5)
	}
	mux.Handle("/static/", staticHandler())
	mux.HandleFunc("/studio", s.studio)
	mux.HandleFunc("/", s.index)
	return mux
}

// serveICS serves ONLY .ics artifacts from the outbox by bare basename. The
// outbox also holds <stem>.summary.json sidecars (contacts/digest/PII), so a
// blanket file server would leak them.
func (s *Server) serveICS(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/ics/")
	if name == "" || filepath.Base(name) != name || !strings.HasSuffix(strings.ToLower(name), ".ics") {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.OutboxDir, name))
}

// csrf rejects cross-site POSTs. The app binds loopback, but that does NOT stop
// CSRF — any site the browser visits can POST to 127.0.0.1. A foreign Origin is
// refused; same-origin fetches (loopback Origin, or no Origin) pass.
// maxBodyBytes caps a request body so a single large POST cannot force unbounded
// allocation. Every mutating endpoint flows through csrf, so bounding it here
// covers them all.
const maxBodyBytes = 1 << 20 // 1 MiB

func csrf(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			if err != nil || !isLoopbackHost(u.Hostname()) {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		h(w, r)
	}
}

func isLoopbackHost(h string) bool {
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

// egressPolicy resolves the action-link allowlist live from the governed Policies
// (C8) when set, keeping every other netpolicy field (DNS pinning, the
// private/IMDS deny-by-default) intact — a governed widening still cannot reach
// link-local/RFC1918. Falls back to the static Egress.
func (s *Server) egressPolicy() netpolicy.Policy {
	p := s.Egress
	if s.Policies != nil {
		p.Allow = s.Policies.Items("egress")
	}
	return p
}

// authz gates a handler on a capability Grant scoped to {action, resource,
// tenant "public"}. When Authz is unset the gate is a no-op (the household
// loopback app runs unauthenticated). The caller presents the Grant as
// "Authorization: Bearer <base64url(JSON)>". Fail-closed: a missing, malformed,
// unsigned, expired, out-of-scope, or revoked Grant is refused, and Authority.
// Halted (the kill switch) revokes all grants so Halt stops in-flight work.
func (s *Server) authz(action, resource string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Authz == nil {
			h(w, r)
			return
		}
		g, ok := bearerGrant(r)
		if !ok {
			s.capabilityRefused(action, resource, "missing capability")
			http.Error(w, "missing capability", http.StatusUnauthorized)
			return
		}
		if _, err := s.Authz.Verify(g, controlplane.Capability{Action: action, Resource: resource, Tenant: "public"}); err != nil {
			s.capabilityRefused(action, resource, err.Error())
			http.Error(w, "capability refused: "+err.Error(), http.StatusForbidden)
			return
		}
		if s.overBudget() { // governed per-minute API budget (C9)
			s.denyAudit(action, resource, "rate budget exceeded")
			http.Error(w, "rate budget exceeded", http.StatusTooManyRequests)
			return
		}
		release, ok := s.apiSlot() // governed max-concurrency budget (C9)
		if !ok {
			s.denyAudit(action, resource, "concurrency budget exceeded")
			http.Error(w, "concurrency budget exceeded", http.StatusTooManyRequests)
			return
		}
		defer release()
		h(w, r)
	}
}

// authzGlass gates the kill-switch endpoint: break-glass authz (VerifyGlass bypasses
// the Halt/revocation check so the operator can DISENGAGE a halt that revoked every
// grant), and no rate-budget gate (halting must always be reachable). Scope is still
// enforced, so a narrow token (e.g. the App token) cannot toggle the switch.
func (s *Server) authzGlass(action, resource string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Authz == nil {
			h(w, r)
			return
		}
		g, ok := bearerGrant(r)
		if !ok {
			s.capabilityRefused(action, resource, "missing capability")
			http.Error(w, "missing capability", http.StatusUnauthorized)
			return
		}
		if _, err := s.Authz.VerifyGlass(g, controlplane.Capability{Action: action, Resource: resource, Tenant: "public"}); err != nil {
			s.capabilityRefused(action, resource, err.Error())
			http.Error(w, "capability refused: "+err.Error(), http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// denyStormThreshold is the number of capability denials within one minute that trips
// the AIDR deny-storm detector (capability probing / brute force). One request fails at
// most a handful of times legitimately; a burst is an attack signal.
const denyStormThreshold = 10

// denyAudit records a refused/throttled request to the admin trail. It does NOT feed the
// AIDR deny-storm detector — only genuine capability refusals do (capabilityRefused), so
// normal rate/concurrency backpressure (429) can never auto-escalate the kill switch.
func (s *Server) denyAudit(action, resource, reason string) {
	if s.Audit != nil {
		s.Audit.Emit(gledger.NewTraceID(), "authz", "deny", gledger.F{"action": action, "resource": resource, "reason": reason})
	}
}

// capabilityRefused records a CAPABILITY refusal (missing / scope-refused grant) — a
// probing signal, distinct from budget throttling — and feeds the AIDR deny-storm
// detector (A7). On crossing the threshold in a one-minute window it raises a
// capability_violation once so the aidr engine can auto-contain. Rate/concurrency 429s
// call denyAudit instead, so legitimate backpressure never trips containment.
func (s *Server) capabilityRefused(action, resource, reason string) {
	s.denyAudit(action, resource, reason)
	if s.Detect == nil {
		return
	}
	s.denyMu.Lock()
	now := time.Now()
	if now.Sub(s.denyWindow) >= time.Minute {
		s.denyWindow, s.denyCount, s.denyFired = now, 0, false
	}
	s.denyCount++
	fire := s.denyCount >= denyStormThreshold && !s.denyFired
	if fire {
		s.denyFired = true
	}
	count := s.denyCount
	s.denyMu.Unlock()
	if fire {
		s.Detect("authz", "capability_violation", map[string]any{"reason": "deny storm", "count": count})
	}
}

// bearerGrant extracts a capability Grant from the Authorization: Bearer header.
func bearerGrant(r *http.Request) (controlplane.Grant, bool) {
	h := r.Header.Get("Authorization")
	raw, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return controlplane.Grant{}, false
	}
	b, err := base64.URLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return controlplane.Grant{}, false
	}
	var g controlplane.Grant
	if json.Unmarshal(b, &g) != nil {
		return controlplane.Grant{}, false
	}
	return g, true
}

// EncodeToken renders a Grant as the base64url(JSON) bearer token the page and
// API clients present. Used by the host to mint the operator token.
func EncodeToken(g controlplane.Grant) string {
	b, _ := json.Marshal(g)
	return base64.URLEncoding.EncodeToString(b)
}

type scoreRow struct {
	Name      string  `json:"name"`
	Technique string  `json:"technique"`
	Before    float64 `json:"before"`
	After     float64 `json:"after"`
	Pass      bool    `json:"pass"`
}

func asr(target gorauder.Target, seeds []gorauder.Seed) float64 {
	return gorauder.NewRunner(target, gorauder.WithScorer(redteam.Scorer())).Run(context.Background(), seeds).ASR()
}

func (s *Server) scorecard(w http.ResponseWriter, _ *http.Request) {
	var rows []scoreRow
	allPass := true
	for _, c := range redteam.Cases() {
		before := asr(c.Undefended, c.Seeds) * 100
		after := asr(c.Defended, c.Seeds) * 100
		pass := after == 0
		if !pass {
			allPass = false
		}
		rows = append(rows, scoreRow{c.Name, c.Technique, before, after, pass})
	}
	writeJSON(w, map[string]any{"results": rows, "all_pass": allPass})
}

func (s *Server) incidents(w http.ResponseWriter, _ *http.Request) {
	events, _ := ir.Load(s.AuditPath)
	type row struct {
		ID string `json:"id"`
		N  int    `json:"n"`
	}
	var out []row
	for _, id := range ir.Traces(events) {
		out = append(out, row{id, len(ir.Timeline(events, id))})
	}
	writeJSON(w, map[string]any{"traces": out})
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request) {
	trace := r.URL.Query().Get("trace")
	events, _ := ir.Load(s.AuditPath)
	writeJSON(w, map[string]any{"timeline": ir.Timeline(events, trace)})
}

// index serves the App surface (consumer: Calendar/Week/Tasks/Chat/Ask/Review —
// zero control knobs). "1 view, 1 job": the governance/tuning plane is a separate
// surface at /studio.
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	token := s.AppToken
	if token == "" {
		token = s.OperatorToken // fall back when no narrow grant was minted
	}
	s.renderSurface(w, "app", token)
}

// studio serves the Studio surface (operator: the governed control/tuning plane —
// prompts, sampling, policies, budgets, eval, security, incidents). Co-resident
// with the App for now; the App page gets the same token, so the capability
// boundary here is the per-route authz on the governance /api endpoints (a narrow
// App-scoped grant that can't reach them is the follow-on hardening).
func (s *Server) studio(w http.ResponseWriter, r *http.Request) {
	s.renderSurface(w, "studio", s.OperatorToken)
}

func (s *Server) renderSurface(w http.ResponseWriter, surface, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.RenderDashboard(w, token, surface); err != nil {
		log.Printf("render %s surface: %v", surface, err)
	}
}

// staticHandler serves the embedded CSS/JS under /static/. The assets are embedded
// and not content-hashed, so a max-age cache serves stale JS for its whole window
// after any rebuild/deploy (and breaks QA). no-cache forces revalidation every load;
// the files are tiny and local, so the cost is negligible.
func staticHandler() http.Handler {
	fs := http.FileServer(http.FS(ui.Static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		fs.ServeHTTP(w, r)
	})
}

// safetyState reports the current kill-switch level.
func (s *Server) safetyState(w http.ResponseWriter, _ *http.Request) {
	lvl := "none"
	allowReq, allowTools := true, true
	if s.Safety != nil {
		lvl = s.Safety.Level().String()
		allowReq, allowTools = s.Safety.AllowRequest(), s.Safety.AllowToolExec()
	}
	writeJSON(w, map[string]any{"level": lvl, "allow_request": allowReq, "allow_tools": allowTools})
}

// killswitch sets the kill level (0 none, 1 block-tools, 2 pause, 3 halt).
func (s *Server) killswitch(w http.ResponseWriter, r *http.Request) {
	if s.Safety == nil {
		http.Error(w, "no kill switch configured", http.StatusNotFound)
		return
	}
	var req struct {
		Level int `json:"level"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Level < 0 || req.Level > 3 {
		http.Error(w, "bad level", http.StatusBadRequest)
		return
	}
	s.Safety.Set("operator", controlplane.KillLevel(req.Level))
	writeJSON(w, map[string]any{"ok": true, "level": s.Safety.Level().String()})
}

// paused reports whether new processing/drops are refused.
func (s *Server) paused() bool { return s.Safety != nil && !s.Safety.AllowRequest() }

// toolsBlocked reports whether side-effect actions (accept/fetch) are refused.
func (s *Server) toolsBlocked() bool { return s.Safety != nil && !s.Safety.AllowToolExec() }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: encode failed: %v", err)
	}
}
