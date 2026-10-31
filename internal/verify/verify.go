// Package verify is test impact (DES §9.2): select tests for changed files,
// decide when only a full run will do, run through an adapter, and compute the
// "two facts" that close a task.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/globs"
)

// Adapters is every built-in adapter.
func Adapters() []core.VerifyAdapter {
	return []core.VerifyAdapter{PHPUnit{}, Node{Tool: "jest"}, Node{Tool: "vitest"}, Pytest{}, Golang{}}
}

var lockfiles = map[string]bool{
	"composer.lock": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"poetry.lock": true, "uv.lock": true, "Pipfile.lock": true, "go.sum": true, "go.mod": true, "Cargo.lock": true,
}

// FullRunRequired applies spec.FullRunWhen. Tokens: lockfile, mode>=full, close, uncovered_file
// (the last two are floors that hold even when omitted); anything else is a glob over the changed files.
func FullRunRequired(spec core.VerifySpec, changed, uncovered []string, mode core.Mode, closing bool) (bool, string) {
	if closing {
		return true, "close"
	}
	if len(uncovered) > 0 { // hard floor: no test maps to it, whatever the policy says
		return true, "uncovered_file: " + uncovered[0]
	}
	for _, rule := range spec.FullRunWhen {
		switch rule {
		case "close":
		case "mode>=full":
			if mode.Rank() >= core.ModeFull.Rank() {
				return true, rule
			}
		case "uncovered_file": // enforced above
		case "lockfile":
			for _, f := range changed {
				if lockfiles[path.Base(f)] {
					return true, rule + ": " + f
				}
			}
		default:
			for _, f := range changed {
				if globs.Match(rule, f) {
					return true, rule + ": " + f
				}
			}
		}
	}
	return false, ""
}

// ErrSuiteBudget: the task already used its full runs; the next one is the human's.
var ErrSuiteBudget = errors.New("verify: suite_budget exhausted; the next full run is the human's")

// Input of Run.
type Input struct {
	Root    string
	Task    string
	Changed []string
	Spec    core.VerifySpec
	Mode    core.Mode
	Closing bool
	Tree    func(context.Context) (string, error) // tree fingerprint, taken before and after the run (see TreeFingerprint); nil: none
	Journal core.Journal                          // nil: nothing is recorded and suite_budget is not enforced
	Actors  []core.VerifyAdapter
}

// Report is the outcome of Run.
type Report struct {
	Full      bool                       `json:"full"`
	Reason    string                     `json:"reason,omitempty"`
	Passed    bool                       `json:"passed"`
	Uncovered []string                   `json:"uncovered,omitempty"`
	Results   map[string]core.TestResult `json:"results"`
}

// RunData is the data of a verify_run event.
type RunData struct {
	Adapters []string `json:"adapters"`
	Full     bool     `json:"full"`
	Reason   string   `json:"reason,omitempty"`
	Passed   bool     `json:"passed"`
	Ran      int      `json:"ran"`
	Tree     string   `json:"tree,omitempty"`
}

// Item is one configured adapter with the tests selected for it.
type Item struct {
	Adapter core.VerifyAdapter
	Spec    core.VerifyAdapterSpec
	Tests   []string
}

// Selection is what Run would execute.
type Selection struct {
	Items     []Item
	Uncovered []string
	Full      bool
	Reason    string
}

// Select maps the changes through every configured adapter and applies the
// full-run rules. Policy adapters with no built-in adapter (e.g. lint) are skipped.
func Select(ctx context.Context, in Input) (Selection, error) {
	actors := in.Actors
	if actors == nil {
		actors = Adapters()
	}
	var sel Selection
	for _, spec := range in.Spec.Adapters {
		for _, a := range actors {
			if a.Name() != spec.Name {
				continue
			}
			tests, unc, err := a.Map(ctx, in.Root, in.Changed)
			if err != nil {
				return Selection{}, fmt.Errorf("verify: map %s: %w", spec.Name, err)
			}
			sel.Items = append(sel.Items, Item{a, spec, tests})
			sel.Uncovered = append(sel.Uncovered, unc...)
		}
	}
	if len(sel.Items) == 0 {
		return Selection{}, errors.New("verify: no configured adapter is available")
	}
	sel.Uncovered = uniq(sel.Uncovered)
	sel.Full, sel.Reason = FullRunRequired(in.Spec, in.Changed, sel.Uncovered, in.Mode, in.Closing)
	return sel, nil
}

// Run selects, enforces suite_budget, runs every configured adapter, and
// journals verify_run (and selection_misses).
func Run(ctx context.Context, in Input) (Report, error) {
	sel, err := Select(ctx, in)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Full: sel.Full, Reason: sel.Reason, Uncovered: sel.Uncovered, Results: map[string]core.TestResult{}}
	sels := sel.Items

	var prior []core.Event
	if in.Journal != nil {
		var err error
		if prior, err = in.Journal.Events(ctx, in.Task); err != nil {
			return rep, fmt.Errorf("verify: journal: %w", err)
		}
		if rep.Full && in.Spec.SuiteBudget != nil && countFull(prior) >= *in.Spec.SuiteBudget {
			return rep, ErrSuiteBudget
		}
	}
	tree, err := fingerprint(ctx, in)
	if err != nil {
		return rep, err
	}
	rep.Passed = true
	var names []string
	ran := 0
	for _, s := range sels {
		res, err := s.Adapter.Run(ctx, in.Root, s.Spec, s.Tests, rep.Full)
		if err != nil {
			return rep, err
		}
		rep.Results[s.Spec.Name] = res
		rep.Passed = rep.Passed && res.Passed
		names = append(names, s.Spec.Name)
		ran += len(res.Ran)
	}
	after, err := fingerprint(ctx, in)
	if err != nil {
		return rep, err
	}
	if after != tree {
		rep.Passed = false // the tree changed during the run: the result is about no tree
	}
	if in.Journal == nil {
		return rep, nil
	}
	if err := appendEvent(ctx, in, "verify_run", RunData{Adapters: names, Full: rep.Full, Reason: rep.Reason, Passed: rep.Passed, Ran: ran, Tree: tree}); err != nil {
		return rep, err
	}
	if rep.Full && !rep.Passed && metricOn(in.Spec) && lastRunGreenAffected(prior) {
		err := appendEvent(ctx, in, "selection_misses", map[string]any{"changed": in.Changed, "adapters": names})
		if err != nil {
			return rep, err
		}
	}
	return rep, nil
}

func fingerprint(ctx context.Context, in Input) (string, error) {
	if in.Tree == nil {
		return "", nil
	}
	t, err := in.Tree(ctx)
	if err != nil {
		return "", fmt.Errorf("verify: fingerprint: %w", err)
	}
	return t, nil
}

func metricOn(spec core.VerifySpec) bool {
	return spec.SelectionMissesMetric != nil && *spec.SelectionMissesMetric
}

func appendEvent(ctx context.Context, in Input, typ string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = in.Journal.Append(ctx, core.Event{Schema: 1, Type: typ, Task: in.Task, Actor: core.ActorAgent, Via: "cli", Data: b})
	return err
}

func runs(events []core.Event) []RunData {
	var out []RunData
	for _, e := range events {
		var d RunData
		if e.Type == "verify_run" && json.Unmarshal(e.Data, &d) == nil {
			out = append(out, d)
		}
	}
	return out
}

func countFull(events []core.Event) int {
	n := 0
	for _, r := range runs(events) {
		if r.Full {
			n++
		}
	}
	return n
}

// lastRunGreenAffected: the most recent run was affected-only and green, so a
// red full run now means the selection missed something.
func lastRunGreenAffected(events []core.Event) bool {
	r := runs(events)
	return len(r) > 0 && !r[len(r)-1].Full && r[len(r)-1].Passed
}

// Facts are the two close conditions (DES §2.3): the tree is green now, and
// the changes stay inside the task scope.
type Facts struct {
	GreenNow   bool     `json:"green_now"`
	InScope    bool     `json:"in_scope"`
	OutOfScope []string `json:"out_of_scope,omitempty"`
}

// ComputeFacts: GreenNow needs the latest FULL verify_run to be passed and recorded for exactly
// the current tree fingerprint (any later edit invalidates it); InScope needs
// every changed file to match a scope glob.
func ComputeFacts(events []core.Event, tree string, changed, scope []string) Facts {
	f := Facts{InScope: true}
	r := runs(events)
	for i := len(r) - 1; i >= 0; i-- {
		if r[i].Full {
			f.GreenNow = r[i].Passed && r[i].Tree != "" && r[i].Tree == tree
			break
		}
	}
	for _, c := range changed {
		ok := false
		for _, g := range scope {
			ok = ok || globs.Match(g, c)
		}
		if !ok {
			f.InScope = false
			f.OutOfScope = append(f.OutOfScope, c)
		}
	}
	sort.Strings(f.OutOfScope)
	return f
}

// Ok reports whether both facts hold.
func (f Facts) Ok() bool { return f.GreenNow && f.InScope }

// ScopeFromEvents returns the task scope globs recorded by task_started or
// plan_accepted (data field "scope"); the last one wins. nil if none carries it.
func ScopeFromEvents(events []core.Event) []string {
	var scope []string
	for _, e := range events {
		var d struct {
			Scope []string `json:"scope"`
		}
		if (e.Type == "task_started" || e.Type == "plan_accepted") && json.Unmarshal(e.Data, &d) == nil && d.Scope != nil {
			scope = d.Scope
		}
	}
	return scope
}
