// Package eval scores the event extractor against hand-labeled ground truth.
// It is the regression metric for the extraction slice: precision/recall/F1 by
// (date, fuzzy-title) match, plus start/end/location field accuracy over the
// matched pairs. The F1 gate (1.00 on 3.txt, >= 0.87 on 1.txt) guards parity
// with the Python extractor as the pipeline evolves.
//
// Scoring is split from IO so the match logic is unit-testable without a model:
// ScoreEvents is pure; Score reads a label file and runs the real extractor
// (honoring EXTRACT_MODE via the tool path when useTool is set).
package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/t0ul/ai-security-engineering/pkg/agent/extractor"
	"github.com/t0ul/ai-security-engineering/pkg/agent/schema"
	"github.com/t0ul/ai-security-engineering/pkg/agent/tool"
)

// Label is one hand-labeled ground-truth file.
type Label struct {
	SourceEmail string      `json:"source_email"`
	DefaultYear int         `json:"default_year"`
	Events      []GoldEvent `json:"events"`
}

// GoldEvent is one labeled calendar entry. End and Location decode to "" when
// the JSON value is null, matching the extractor's empty-means-absent contract.
type GoldEvent struct {
	Title    string `json:"title"`
	Start    string `json:"start"`
	End      string `json:"end"`
	AllDay   bool   `json:"all_day"`
	Location string `json:"location"`
}

// Row is the per-matched-pair field comparison.
type Row struct {
	Title     string
	PredStart string
	GoldStart string
	PredEnd   string
	GoldEnd   string
	StartOK   bool
	EndOK     bool
	LocOK     bool
}

// Report is the full scoring result for one label file.
type Report struct {
	Source    string
	Gold      int
	Pred      int
	Matched   int
	Precision float64
	Recall    float64
	F1        float64
	StartOK   int
	EndOK     int
	LocOK     int
	Rows      []Row
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func norm(t string) string {
	return strings.TrimSpace(nonAlnum.ReplaceAllString(strings.ToLower(t), " "))
}

func tokenSet(t string) map[string]bool {
	s := map[string]bool{}
	for _, w := range strings.Fields(norm(t)) {
		s[w] = true
	}
	return s
}

func subset(a, b map[string]bool) bool {
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func intersect(a, b map[string]bool) int {
	n := 0
	for k := range a {
		if b[k] {
			n++
		}
	}
	return n
}

// titlesMatch is true when one title's tokens subsume the other's, or they share
// at least 60% of the smaller token set.
func titlesMatch(a, b string) bool {
	na, nb := tokenSet(a), tokenSet(b)
	if len(na) == 0 || len(nb) == 0 {
		return false
	}
	if subset(na, nb) || subset(nb, na) {
		return true
	}
	min := len(na)
	if len(nb) < min {
		min = len(nb)
	}
	return float64(intersect(na, nb)) >= 0.6*float64(min)
}

func day(iso string) string {
	if len(iso) >= 10 {
		return iso[:10]
	}
	return iso
}

// ScoreEvents is the pure scorer: greedy one-to-one match of gold to pred by
// (same day, fuzzy title), then precision/recall/F1 and field accuracy.
func ScoreEvents(source string, gold []GoldEvent, pred []schema.Event) Report {
	used := make([]bool, len(pred))
	r := Report{Source: source, Gold: len(gold), Pred: len(pred)}
	for _, g := range gold {
		for i, p := range pred {
			if used[i] {
				continue
			}
			if day(p.Start) == day(g.Start) && titlesMatch(p.Title, g.Title) {
				used[i] = true
				r.Matched++
				sOK := p.Start == g.Start
				eOK := p.End == g.End
				lOK := g.Location != "" && p.Location != "" &&
					strings.Contains(norm(p.Location), norm(g.Location))
				if sOK {
					r.StartOK++
				}
				if eOK {
					r.EndOK++
				}
				if lOK {
					r.LocOK++
				}
				r.Rows = append(r.Rows, Row{
					Title: g.Title, PredStart: p.Start, GoldStart: g.Start,
					PredEnd: p.End, GoldEnd: g.End, StartOK: sOK, EndOK: eOK, LocOK: lOK,
				})
				break
			}
		}
	}
	tp := r.Matched
	fp := r.Pred - tp
	fn := r.Gold - tp
	if tp+fp > 0 {
		r.Precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		r.Recall = float64(tp) / float64(tp+fn)
	}
	if r.Precision+r.Recall > 0 {
		r.F1 = 2 * r.Precision * r.Recall / (r.Precision + r.Recall)
	}
	return r
}

// Score reads a label file, runs the extractor over its source email, and
// returns the Report. useTool runs the registered tool (honoring EXTRACT_MODE);
// otherwise it calls ExtractEvents directly (the Python default path).
func Score(labelPath string, useTool bool) (Report, error) {
	return ScoreWithMode(labelPath, useTool, "")
}

// ScoreWithMode is Score with an explicit extraction mode ("llm"/"regex"/"auto")
// passed through tool.Ctx.Mode, instead of the process-global EXTRACT_MODE env.
// mode "" keeps the env fallback (what Score does). This lets a caller run an LLM
// eval without mutating global state that a concurrent extractor shares.
func ScoreWithMode(labelPath string, useTool bool, mode string) (Report, error) {
	raw, err := os.ReadFile(labelPath)
	if err != nil {
		return Report{}, err
	}
	var label Label
	if err := json.Unmarshal(raw, &label); err != nil {
		return Report{}, fmt.Errorf("parse label %s: %w", labelPath, err)
	}
	// source_email is authored relative to the drop root. Labels commonly live in
	// a labels/ subdir while the email sits in a sibling samples/ dir, so resolve
	// against the label's directory first, then fall back one level to its parent
	// (the original eval.py resolved against the script dir, the drop root).
	src := filepath.Join(filepath.Dir(labelPath), label.SourceEmail)
	if _, statErr := os.Stat(src); statErr != nil {
		if alt := filepath.Join(filepath.Dir(filepath.Dir(labelPath)), label.SourceEmail); alt != src {
			if _, altErr := os.Stat(alt); altErr == nil {
				src = alt
			}
		}
	}
	text, err := os.ReadFile(src)
	if err != nil {
		return Report{}, err
	}
	year := label.DefaultYear
	if year == 0 {
		year = 2026
	}
	var pred []schema.Event
	if useTool {
		res := extractor.New().Run(string(text), tool.Ctx{Source: label.SourceEmail, DefaultYear: year, Mode: mode})
		pred = res.Events
	} else {
		pred = extractor.ExtractEvents(string(text), label.SourceEmail, year)
	}
	return ScoreEvents(label.SourceEmail, label.Events, pred), nil
}

// PassK scores a label k times and reports reliability under non-determinism (a
// single run is not a number when the extractor path calls an LLM): passAtK is
// true if ANY run clears min F1 (best case), passPowK is true only if ALL k runs
// clear it (the one you actually ship on), and f1s are the per-run scores. Use
// useTool=true for the LLM path.
func PassK(labelPath string, k int, min float64, useTool bool) (passAtK, passPowK bool, f1s []float64, err error) {
	if k < 1 {
		k = 1
	}
	passPowK = true
	for i := 0; i < k; i++ {
		rep, serr := Score(labelPath, useTool)
		if serr != nil {
			return false, false, f1s, serr
		}
		f1s = append(f1s, rep.F1)
		ok := rep.F1 >= min-1e-9
		passAtK = passAtK || ok
		passPowK = passPowK && ok
	}
	return passAtK, passPowK, f1s, nil
}

// String renders the Report the way eval.py printed it.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== eval: %s ===\n", r.Source)
	fmt.Fprintf(&b, "gold=%d pred=%d matched=%d\n", r.Gold, r.Pred, r.Matched)
	fmt.Fprintf(&b, "precision=%.2f recall=%.2f f1=%.2f\n", r.Precision, r.Recall, r.F1)
	for _, row := range r.Rows {
		flag := "ok"
		if !(row.StartOK && row.EndOK) {
			flag = "CHECK"
		}
		fmt.Fprintf(&b, "  [%s] %-22s start %s==%s:%t  end %s==%s:%t  loc:%t\n",
			flag, row.Title, row.PredStart, row.GoldStart, row.StartOK,
			emptyDash(row.PredEnd), emptyDash(row.GoldEnd), row.EndOK, row.LocOK)
	}
	if r.Matched > 0 {
		fmt.Fprintf(&b, "field accuracy: start %d/%d  end %d/%d  location %d/%d",
			r.StartOK, r.Matched, r.EndOK, r.Matched, r.LocOK, r.Matched)
	}
	return b.String()
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
