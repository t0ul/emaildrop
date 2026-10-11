package pipeline_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/emaildrop/pkg/agent/extractor"
	"github.com/t0ul/emaildrop/pkg/agent/pipeline"
	"github.com/t0ul/emaildrop/pkg/agent/roster"
	"github.com/t0ul/emaildrop/pkg/agent/tool"
	"github.com/t0ul/emaildrop/pkg/provenance"
	"github.com/t0ul/gledger"
)

const email = `PS 123 Newsletter

Back to School Night: Thursday, September 29th at 6:00 PM in the auditorium

Days Off / No School:
Monday, October 12th - Italian Heritage Day
`

func TestRosterWritesSummarySidecar(t *testing.T) {
	reg := tool.NewRegistry()
	roster.Register(reg)
	p, dir, _ := newPipe(t, reg)
	p.ToolNames = roster.Names()

	body := "PS 123 Newsletter\n" +
		"Please buy popcorn to support the school by October 2.\n" +
		"Back to School Night: Thursday, September 29th at 6:00 PM\n" +
		"teacher@school.org\n"
	src := filepath.Join(dir, "wk.txt")
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ProcessEmail(src); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(p.OutboxDir, "wk.summary.json"))
	if err != nil {
		t.Fatalf("summary sidecar not written: %v", err)
	}
	var s pipeline.EmailSummary
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(s.Tools["digest"]) == "" {
		t.Errorf("digest missing from sidecar: %+v", s.Tools)
	}
	if !strings.Contains(s.Tools["contacts"], "teacher@school.org") {
		t.Errorf("contacts missing: %q", s.Tools["contacts"])
	}
	foundTask := false
	for _, it := range s.Items {
		if it.Kind == "task" && strings.Contains(strings.ToLower(it.Title), "popcorn") {
			foundTask = true
		}
	}
	if !foundTask {
		t.Errorf("popcorn task not in sidecar items: %+v", s.Items)
	}
}

func TestSidecarDedupsAcrossTools(t *testing.T) {
	reg := tool.NewRegistry()
	roster.Register(reg)
	p, dir, _ := newPipe(t, reg)
	p.ToolNames = roster.Names()

	// "Guest author visiting on October 13" is emitted by BOTH the event
	// extractor (dated line) and the item extractor (heads-up cue).
	src := filepath.Join(dir, "wk.txt")
	os.WriteFile(src, []byte("PS 51 Update\nGuest author visiting on October 13.\n"), 0o644)
	if _, err := p.ProcessEmail(src); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(p.OutboxDir, "wk.summary.json"))
	var s pipeline.EmailSummary
	json.Unmarshal(raw, &s)

	n := 0
	for _, it := range s.Items {
		if strings.Contains(strings.ToLower(it.Title), "guest author") {
			n++
			if it.Kind != "heads_up" {
				t.Errorf("deduped item should keep the more specific kind, got %q", it.Kind)
			}
		}
	}
	if n != 1 {
		t.Fatalf("guest author should appear once after dedup, got %d: %+v", n, s.Items)
	}
}

func TestCorpusIndexIsScrubbed(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(extractor.New())
	p, dir, _ := newPipe(t, reg)
	var indexed string
	p.Index = func(_, _, text string) error { indexed = text; return nil }

	body := "Newsletter\nAPI_KEY=sk-DEADBEEFcafef00d1234\nPassword: super-secret-pw\nteacher@school.org\n"
	src := filepath.Join(dir, "e.txt")
	os.WriteFile(src, []byte(body), 0o644)
	if _, err := p.ProcessEmail(src); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"sk-DEADBEEFcafef00d1234", "super-secret-pw", "teacher@school.org"} {
		if strings.Contains(indexed, leak) {
			t.Fatalf("secret/PII reached the corpus unscrubbed: %q in %q", leak, indexed)
		}
	}
}

func TestHaltedPipelineSkips(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(extractor.New())
	p, dir, _ := newPipe(t, reg)
	p.Halted = func() bool { return true } // kill switch engaged

	src := filepath.Join(dir, "e.txt")
	os.WriteFile(src, []byte("PTA Meeting on September 24th at 8:30 AM.\n"), 0o644)
	sum, err := p.ProcessEmail(src)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Rejected != "halted" {
		t.Fatalf("expected halted, got %+v", sum)
	}
	if len(sum.Artifacts) != 0 {
		t.Fatalf("a halted pipeline must write nothing, got %v", sum.Artifacts)
	}
}

// rogueTool declares READ_ONLY but tries to write an artifact (capability test).
type rogueTool struct{}

func (rogueTool) Name() string                { return "rogue" }
func (rogueTool) Capability() tool.Capability { return tool.ReadOnly }
func (rogueTool) Run(_ string, _ tool.Ctx) tool.Result {
	return tool.Result{Tool: "rogue", Capability: tool.ReadOnly,
		Artifacts: map[string]string{"evil.ics": "x"}}
}

func newPipe(t *testing.T, reg *tool.Registry) (*pipeline.Pipeline, string, func() (bool, int)) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	a, err := gledger.Open(logPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	p := &pipeline.Pipeline{Registry: reg, Audit: a, OutboxDir: filepath.Join(dir, "outbox"), DefaultYear: 2026}
	return p, dir, func() (bool, int) { return gledger.VerifyFile(logPath) }
}

func writeEmail(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProcessEmailWritesICSAndAuditsChain(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(extractor.New())
	p, dir, verify := newPipe(t, reg)
	t.Setenv("EXTRACT_MODE", "regex") // no model needed

	src := writeEmail(t, dir, "3.txt", email)
	sum, err := p.ProcessEmail(src)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Events < 2 {
		t.Fatalf("expected >=2 events, got %d", sum.Events)
	}
	if len(sum.Artifacts) != 1 || !strings.HasSuffix(sum.Artifacts[0], "3.events.ics") {
		t.Fatalf("expected outbox artifact 3.events.ics, got %v", sum.Artifacts)
	}
	ics, _ := os.ReadFile(sum.Artifacts[0])
	if !strings.Contains(string(ics), "BEGIN:VCALENDAR") {
		t.Error("artifact is not a valid .ics")
	}
	if ok, n := verify(); !ok || n == 0 {
		t.Fatalf("audit chain failed to verify: ok=%v n=%d", ok, n)
	}
}

// TestArtifactUnsignableIsQuarantined locks the fail-closed provenance fix: when a
// signer is configured but the .sig cannot be written, the pipeline must NOT leave an
// unsigned .ics on disk (a silent integrity downgrade). It removes the artifact and
// audits the failure. The .sig write is forced to fail by pre-creating a DIRECTORY at
// its path — a real filesystem failure, no mocks.
func TestArtifactUnsignableIsQuarantined(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(extractor.New())
	p, dir, verify := newPipe(t, reg)
	t.Setenv("EXTRACT_MODE", "regex")
	signer, _, err := provenance.NewSigner("agent")
	if err != nil {
		t.Fatal(err)
	}
	p.Signer = signer

	// Block the .sig path with a directory so WriteFile("<ics>.sig") fails while the
	// .ics write succeeds. The artifact for 3.txt is 3.events.ics.
	icsPath := filepath.Join(p.OutboxDir, "3.events.ics")
	if err := os.MkdirAll(icsPath+".sig", 0o755); err != nil {
		t.Fatal(err)
	}

	src := writeEmail(t, dir, "3.txt", email)
	sum, err := p.ProcessEmail(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Artifacts) != 0 {
		t.Fatalf("an unsignable artifact must NOT be shipped, got %v", sum.Artifacts)
	}
	if _, err := os.Stat(icsPath); !os.IsNotExist(err) {
		t.Fatalf("unsigned .ics must be removed (quarantined), stat err=%v", err)
	}
	// The failure is audited (loud, not silent) and the chain still verifies.
	log, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if !strings.Contains(string(log), "artifact_sign_error") {
		t.Error("sign failure must be audited as artifact_sign_error")
	}
	if ok, _ := verify(); !ok {
		t.Error("audit chain must still verify after a quarantined artifact")
	}
}

func TestIndexHookReceivesRawEmail(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(extractor.New())
	p, dir, _ := newPipe(t, reg)
	t.Setenv("EXTRACT_MODE", "regex")

	var indexedSource, indexedText string
	p.Index = func(_, source, rawText string) error {
		indexedSource, indexedText = source, rawText
		return nil
	}
	src := writeEmail(t, dir, "3.txt", email)
	if _, err := p.ProcessEmail(src); err != nil {
		t.Fatal(err)
	}
	if indexedSource != "3.txt" || !strings.Contains(indexedText, "Back to School Night") {
		t.Fatalf("index hook got source=%q text=%q", indexedSource, indexedText)
	}
}

func TestArtifactSignedAndVerifies(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(extractor.New())
	p, dir, _ := newPipe(t, reg)
	t.Setenv("EXTRACT_MODE", "regex")
	signer, pub, err := provenance.NewSigner("agent")
	if err != nil {
		t.Fatal(err)
	}
	p.Signer = signer

	src := writeEmail(t, dir, "3.txt", email)
	sum, err := p.ProcessEmail(src)
	if err != nil || len(sum.Artifacts) == 0 {
		t.Fatalf("expected an artifact: %v err=%v", sum.Artifacts, err)
	}
	sigBytes, err := os.ReadFile(sum.Artifacts[0] + ".sig")
	if err != nil {
		t.Fatalf("no signature sidecar written: %v", err)
	}
	var mark provenance.Mark
	if err := json.Unmarshal(sigBytes, &mark); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(sum.Artifacts[0])
	if err := provenance.NewVerifier().Trust("agent", pub).Verify(content, mark); err != nil {
		t.Fatalf("emitted artifact signature must verify: %v", err)
	}
}

func TestOversizedRejected(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(extractor.New())
	p, dir, _ := newPipe(t, reg)
	big := strings.Repeat("A", pipeline.MaxBytes+1)
	src := writeEmail(t, dir, "big.txt", big)
	sum, err := p.ProcessEmail(src)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Rejected != "oversized" || len(sum.Artifacts) != 0 {
		t.Fatalf("oversized email not rejected: %+v", sum)
	}
}

func TestCapabilityEnforcement(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Register(rogueTool{})
	p, dir, verify := newPipe(t, reg)
	p.ToolNames = []string{"rogue"}

	src := writeEmail(t, dir, "x.txt", "nothing dated here")
	sum, err := p.ProcessEmail(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Artifacts) != 0 {
		t.Fatalf("read-only tool was allowed to write: %v", sum.Artifacts)
	}
	// No capability-gated artifact (.ics) may be written by a read-only tool. The
	// pipeline's own derived sidecar (classification/items metadata, R2) is not a
	// tool artifact and may be present.
	entries, _ := os.ReadDir(p.OutboxDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ics") {
			t.Errorf("a read-only tool wrote a capability-gated .ics: %s", e.Name())
		}
	}
	if ok, _ := verify(); !ok {
		t.Error("audit chain should still verify after a capability violation")
	}
}
