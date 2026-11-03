// Package flow is the task flow of DES §2.3: start (triage, baseline, journal),
// amend (re-measure all six axes, mode only grows), close (rescore, the two
// facts from a host-side full run, cost, archive), and what the guard hook
// learns from a task in flight. It only wires the real modules together.
package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/globs"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
	"github.com/vanssata/agentic-risk-rails/internal/models"
	"github.com/vanssata/agentic-risk-rails/internal/triage"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// Env is what every flow step needs besides its own input: the checkout and its
// resolved policy (resolved by the caller, so a resolve error never reaches here
// as a default).
type Env struct {
	Root string // the checkout: git, tree, verify
	// StateRoot holds the journal and .rr/run/<task>.baseline.json; empty = Root.
	// The caller builds Journal with journal.New(StateRoot).
	StateRoot string
	Policy    core.EffectivePolicy
	Tree      []string // git ls-files ∪ default branch tree
	Journal   core.Journal
	Home      string // for transcript roots and cost
	// Via is the journal "via" of every event; empty = StartIn.Via for task_started, else "cli".
	Via string
	// Enforcement and InContainer feed the task level; empty/false = hook_only, no container.
	Enforcement core.Enforcement
	InContainer bool
}

// StartIn is the input of Start.
type StartIn struct {
	Goal     string
	Files    []string // task scope: repo-relative paths or globs
	Declared map[core.Axis]int
	Spec     bool
	Sessions int
	Tiers    core.EffectiveTiers // from the committed lock; no BALANCED ⇒ NO_TIER
	Actor    core.Actor
	ID       string // empty = generated
	Via      string // fallback when Env.Via is empty; empty = "cli"
}

// state is where the journal and the baseline live.
func (e Env) state() string {
	if e.StateRoot != "" {
		return e.StateRoot
	}
	return e.Root
}

// Started is the result of Start.
type Started struct {
	Task   string
	Weight core.Weight
	Level  core.Level
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func taskID(now time.Time, goal string) string {
	s := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(goal), "-"), "-")
	if len(s) > 24 {
		s = strings.Trim(s[:24], "-")
	}
	id := now.UTC().Format("20060102-150405")
	if s != "" {
		id += "-" + s
	}
	return id
}

// cleanScope refuses absolute and parent-relative paths: scope is repo-relative.
func cleanScope(files []string) ([]string, error) {
	var out []string
	for _, f := range files {
		c := filepath.ToSlash(filepath.Clean(f))
		if f == "" || filepath.IsAbs(f) || c == ".." || strings.HasPrefix(c, "../") || c == "." {
			return nil, fmt.Errorf("scope entry %q must be a repo-relative path inside the checkout", f)
		}
		out = append(out, c)
	}
	return out, nil
}

func isGlob(p string) bool { return strings.ContainsAny(p, "*?[{") }

// Expand turns scope entries into files: a glob becomes the tree files it
// matches (itself if none), a path stays as it is (it may not exist yet).
func Expand(scope, tree []string) []string {
	var out []string
	for _, s := range scope {
		if !isGlob(s) {
			out = append(out, s)
			continue
		}
		n := len(out)
		for _, t := range tree {
			if globs.Match(s, t) {
				out = append(out, t)
			}
		}
		if len(out) == n {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

type scoreIn struct {
	goal     string
	files    []string
	declared map[core.Axis]int
	spec     bool
	sessions int
}

func (e Env) triageInput(s scoreIn) triage.Input {
	// rr's own state (journal, baseline) names the scope files and would count as references to them.
	tree := slices.DeleteFunc(slices.Clone(e.Tree), func(p string) bool { return strings.HasPrefix(p, ".rr/") })
	refs, content, unreadable := triage.Load(e.Root, s.files, tree, e.Policy.Policy.Risk.Axes[core.AxisCoverage].TestGlobs)
	del := map[string]bool{}
	for _, f := range s.files {
		if _, err := os.Lstat(filepath.Join(e.Root, f)); errors.Is(err, fs.ErrNotExist) && slices.Contains(e.Tree, f) {
			del[f] = true
		}
	}
	return triage.Input{Files: s.files, Goal: s.goal, Declared: s.declared, Refs: refs, Unreadable: unreadable, Deleted: del,
		Tree: tree, Content: content, Spec: s.spec, Sessions: s.sessions}
}

func (e Env) via(fallback string) string {
	if e.Via != "" {
		return e.Via
	}
	if fallback != "" {
		return fallback
	}
	return "cli"
}

// level is TaskLevel for this host, one level lower (not below L0) when the
// tiers lack STRONG (DES §4.4). clamped says whether that clamp applied.
func (e Env) level(mode core.Mode, irreversible bool, tiers map[core.Tier]string) (lvl core.Level, why string, clamped bool) {
	enf := e.Enforcement
	if enf == "" {
		enf = core.EnforcementHookOnly
	}
	lvl, why = autonomy.TaskLevel(autonomy.LevelInput{Policy: e.Policy.Policy, Mode: mode, Irreversible: irreversible, Enforcement: enf, InContainer: e.InContainer})
	for _, d := range models.Degradations(core.EffectiveTiers{Models: tiers}) {
		if d.ClampAutonomy && lvl > core.L0 {
			return lvl - 1, why, true
		}
	}
	return lvl, why, false
}

func (e Env) append(ctx context.Context, task, typ string, actor core.Actor, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = e.Journal.Append(ctx, core.Event{Schema: 1, Type: typ, Task: task, Actor: actor, Via: e.via(""), PolicySHA: e.Policy.PolicySHA, Data: raw})
	return err
}

// Start opens a task (DES §2.3 step 1): triage, the baseline manifest, base_sha,
// level, and task_started. A second open task is REFUSE {TASK_IN_FLIGHT}; no
// BALANCED model is REFUSE {NO_TIER}.
func (e Env) Start(ctx context.Context, in StartIn) (Started, error) {
	scope, err := cleanScope(in.Files)
	if err != nil {
		return Started{}, err
	}
	if len(scope) == 0 {
		return Started{}, errors.New("a task needs at least one file in its scope")
	}
	if in.Tiers.Models[core.TierBalanced] == "" {
		return Started{}, &core.Refusal{Code: "NO_TIER", Detail: "no BALANCED model in the tiers lock (run rr models probe)"}
	}
	open, err := e.Journal.Open(ctx)
	if err != nil {
		return Started{}, err
	}
	if len(open) > 0 {
		return Started{}, &core.Refusal{Code: "TASK_IN_FLIGHT", Detail: open[0]}
	}
	w := triage.Score(e.Policy.Policy, e.triageInput(scoreIn{in.Goal, Expand(scope, e.Tree), in.Declared, in.Spec, in.Sessions}))
	level, why, clamped := e.level(w.Mode, w.Irreversible, in.Tiers.Models)
	manifest, sum, err := verify.Baseline(ctx, e.Root)
	if err != nil {
		return Started{}, err
	}
	base, err := verify.HeadSHA(ctx, e.Root)
	if err != nil {
		return Started{}, err
	}
	task, via := in.ID, e.via(in.Via)
	if task == "" {
		task = taskID(time.Now(), in.Goal)
	}
	if err := os.MkdirAll(journal.RunDir(e.state()), 0o755); err != nil {
		return Started{}, err
	}
	bpath := filepath.Join(journal.RunDir(e.state()), task+".baseline.json")
	if err := writeNew(bpath, manifest); err != nil {
		return Started{}, err
	}
	raw, err := json.Marshal(map[string]any{"goal": in.Goal, "scope": scope, "base_sha": base, "baseline": sum, "mode": w.Mode,
		"weight": w, "declared": in.Declared, "level": level, "level_reason": why, "ceiling_sha": e.Policy.CeilingSHA})
	if err == nil {
		_, err = e.Journal.Append(ctx, core.Event{Schema: 1, Type: "task_started", Task: task, Actor: in.Actor, Via: via,
			PolicySHA: e.Policy.PolicySHA, TiersEffective: in.Tiers.Models, Data: raw})
	}
	if err != nil {
		_ = os.Remove(bpath)
		return Started{}, err
	}
	if err := e.startNotes(ctx, task, in, level, clamped); err != nil {
		return Started{}, err
	}
	return Started{Task: task, Weight: w, Level: level}, nil
}

// startNotes journals what Start learned besides the task itself: policy fields
// cut or ignored (DES §3.3) and the §4.4 consequences of missing tiers.
func (e Env) startNotes(ctx context.Context, task string, in StartIn, level core.Level, clamped bool) error {
	if f := e.Policy.Clamped; len(f) > 0 {
		if err := e.append(ctx, task, "policy_clamped", in.Actor, map[string]any{"fields": f}); err != nil {
			return err
		}
	}
	if f := e.Policy.Ignored; len(f) > 0 {
		if err := e.append(ctx, task, "policy_loosening_ignored", in.Actor, map[string]any{"fields": f}); err != nil {
			return err
		}
	}
	degs := models.Degradations(in.Tiers)
	if len(degs) == 0 {
		return nil
	}
	if err := e.append(ctx, task, "tiers_resolved", in.Actor, map[string]any{"runtime": in.Tiers.Runtime, "effective": in.Tiers.Models,
		"ladder": in.Tiers.Ladder, "catalogue_sha": in.Tiers.CatalogueSHA, "probed_at": in.Tiers.ProbedAt}); err != nil {
		return err
	}
	for _, d := range degs {
		data := map[string]any{"runtime": in.Tiers.Runtime, "tier": d.Tier, "to": d.To}
		if d.Event == "autonomy_clamped" {
			data["applied"] = clamped
			data["level"] = level
			data["reason"] = "STRONG missing: autonomy one level down"
		}
		if err := e.append(ctx, task, d.Event, in.Actor, data); err != nil {
			return err
		}
	}
	return nil
}

func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// OpenTask is the single task in flight, or an error.
func OpenTask(ctx context.Context, j core.Journal) (string, error) {
	open, err := j.Open(ctx)
	if err != nil {
		return "", err
	}
	if len(open) != 1 {
		return "", fmt.Errorf("want exactly one task in flight, have %d", len(open))
	}
	return open[0], nil
}

type startedData struct {
	Goal       string            `json:"goal"`
	Scope      []string          `json:"scope"`
	Declared   map[core.Axis]int `json:"declared"`
	Level      *core.Level       `json:"level"`
	CeilingSHA string            `json:"ceiling_sha"`
}

func readStarted(events []core.Event) (startedData, error) {
	for _, e := range events {
		if e.Type == "task_started" {
			var d startedData
			err := json.Unmarshal(e.Data, &d)
			return d, err
		}
	}
	return startedData{}, errors.New("no task_started event")
}

// lastWeight is the newest weight recorded by task_started, weight_amended or weight_rescored.
func lastWeight(events []core.Event) (core.Weight, error) {
	var w core.Weight
	found := false
	for _, e := range events {
		if e.Type != "task_started" && e.Type != "weight_amended" && e.Type != "weight_rescored" {
			continue
		}
		var d struct {
			Weight *core.Weight `json:"weight"`
		}
		if json.Unmarshal(e.Data, &d) == nil && d.Weight != nil {
			w, found = *d.Weight, true
		}
	}
	if !found {
		return w, errors.New("no weight recorded for the task")
	}
	return w, nil
}

// lastLevel is the newest level recorded by task_started, weight_amended or weight_rescored.
func lastLevel(events []core.Event) (lvl core.Level, found bool) {
	for _, e := range events {
		if e.Type != "task_started" && e.Type != "weight_amended" && e.Type != "weight_rescored" {
			continue
		}
		var d struct {
			Level *core.Level `json:"level"`
		}
		if json.Unmarshal(e.Data, &d) == nil && d.Level != nil {
			lvl, found = *d.Level, true
		}
	}
	return lvl, found
}

// reweigh re-measures the task against the real diff (rescore: the policy's
// axes, amend: all six) and journals the result. Mode and axes only go up.
func (e Env) reweigh(ctx context.Context, task, typ string, actor core.Actor, events []core.Event, tr verify.Trust, d startedData, declared map[core.Axis]int) (core.Weight, error) {
	prev, err := lastWeight(events)
	if err != nil {
		return prev, err
	}
	changed, err := verify.TaskChanged(ctx, e.Root, tr, true)
	if err != nil {
		return prev, err
	}
	files := slices.Compact(slices.Sorted(slices.Values(append(Expand(d.Scope, e.Tree), changed...))))
	all := map[core.Axis]int{} // what the session declared at start, raised by what it declares now
	for _, m := range []map[core.Axis]int{d.Declared, declared} {
		for a, v := range m {
			all[a] = max(all[a], v)
		}
	}
	in := e.triageInput(scoreIn{d.Goal, files, all, false, 1})
	var w core.Weight
	if typ == "weight_amended" {
		w = triage.Amend(e.Policy.Policy, prev, in)
	} else {
		w = triage.Rescore(e.Policy.Policy, prev, in)
	}
	if w.Mode == prev.Mode && w.Total() == prev.Total() {
		return w, nil // nothing grew: nothing to record
	}
	data := map[string]any{"from": prev.Mode, "to": w.Mode, "mode": w.Mode, "weight": w}
	if before, ok := lastLevel(events); ok { // the level only falls
		lvl, _, _ := e.level(w.Mode, w.Irreversible, events[0].TiersEffective)
		data["level"] = min(before, lvl)
	}
	return w, e.append(ctx, task, typ, actor, data)
}

// Amend (`rr task start --amend`) re-measures all six axes against the real
// diff; the mode only grows. The scope does not change: it is fixed by task_started.
func (e Env) Amend(ctx context.Context, task string, declared map[core.Axis]int, actor core.Actor) (core.Weight, error) {
	events, err := e.Journal.Events(ctx, task)
	if err != nil {
		return core.Weight{}, err
	}
	tr, err := verify.LoadTrust(e.state(), task, events)
	if err != nil {
		return core.Weight{}, err
	}
	d, err := readStarted(events)
	if err != nil {
		return core.Weight{}, err
	}
	return e.reweigh(ctx, task, "weight_amended", actor, events, tr, d, declared)
}

// Note records a human gate: plan_accepted, a review_verdict, or a risk_recorded.
func (e Env) Note(ctx context.Context, task, typ string, actor core.Actor, data map[string]any) error {
	if typ != "plan_accepted" && typ != "review_verdict" && typ != "risk_recorded" {
		return fmt.Errorf("flow: cannot note %q", typ)
	}
	data["by"] = actor
	return e.append(ctx, task, typ, actor, data)
}

// CloseIn is the input of Close. Actor is who runs the closing full run: only a
// human, the runner (autonomy) or CI make it count (errata #25/#26).
type CloseIn struct {
	Task    string
	Actor   core.Actor
	Actors  []core.VerifyAdapter // nil: the built-in adapters
	Session *ledger.SessionData  // optional transcript of this task's session
}

func (e Env) refuse(ctx context.Context, task string, actor core.Actor, code, detail string) error {
	r := &core.Refusal{Code: code, Detail: detail}
	if err := e.append(ctx, task, "refused", actor, map[string]any{"code": code, "detail": detail}); err != nil {
		return fmt.Errorf("%w (and the refusal could not be journaled: %w)", r, err)
	}
	return r
}

// Close rescores, checks the process the mode requires, runs the host-side full
// verify, and only if both facts hold journals task_closed and archives the task.
func (e Env) Close(ctx context.Context, in CloseIn) error {
	events, err := e.Journal.Events(ctx, in.Task)
	if err != nil {
		return err
	}
	tr, err := verify.LoadTrust(e.state(), in.Task, events)
	if err != nil {
		return err
	}
	d, err := readStarted(events)
	if err != nil {
		return err
	}
	if d.CeilingSHA != e.Policy.CeilingSHA {
		return e.refuse(ctx, in.Task, in.Actor, "CEILING_CHANGED", "the ceiling changed since task_started")
	}
	if _, err := e.reweigh(ctx, in.Task, "weight_rescored", in.Actor, events, tr, d, nil); err != nil {
		return err
	}
	if in.Session != nil {
		if err := e.recordSession(ctx, in.Task, in.Actor, *in.Session); err != nil {
			return err
		}
	}
	if events, err = e.Journal.Events(ctx, in.Task); err != nil {
		return err
	}
	mode, err := verify.TaskMode(events)
	if err != nil {
		return err
	}
	review, err := e.process(ctx, in.Task, in.Actor, mode, events)
	if err != nil {
		return err
	}
	facts, err := verify.Close(ctx, verify.CloseInput{Root: e.Root, Task: in.Task, Spec: e.Policy.Policy.Verify, Mode: mode, Trust: tr,
		Journal: e.Journal, Actor: in.Actor, Actors: in.Actors})
	if err != nil {
		return err
	}
	if !facts.Ok() {
		raw, _ := json.Marshal(facts)
		return e.refuse(ctx, in.Task, in.Actor, "FACTS", string(raw))
	}
	if events, err = e.Journal.Events(ctx, in.Task); err != nil {
		return err
	}
	if err := e.append(ctx, in.Task, "task_closed", in.Actor, map[string]any{"facts": facts, "cost": e.cost(events), "review": review}); err != nil {
		return err
	}
	return e.Journal.Close(ctx, in.Task)
}

// process checks plan and review for the final mode and returns the review summary.
// Light has an inline plan and no review stage (recorded, so the required events hold).
func (e Env) process(ctx context.Context, task string, actor core.Actor, mode core.Mode, events []core.Event) (map[string]any, error) {
	has := map[string]bool{}
	last := ""
	for _, ev := range events {
		has[ev.Type] = true
		if ev.Type == "plan_accepted" {
			var d struct {
				Plan string `json:"plan"`
				SHA  string `json:"sha"`
			}
			_ = json.Unmarshal(ev.Data, &d)
			if d.Plan == "written" && d.SHA != "" { // an inline or light accept never satisfies a heavier mode
				has["plan_written"] = true
			}
		}
		if ev.Type == "review_verdict" {
			var d struct {
				Verdict string `json:"verdict"`
				Stage   string `json:"stage"`
			}
			_ = json.Unmarshal(ev.Data, &d)
			if d.Stage == "factory" || d.Stage == "human" { // the factory's per-step verdicts do not count
				last = d.Verdict
			}
		}
	}
	if mode == core.ModeLight { // light: the goal is the plan and there is no review stage; both recorded so the required events hold
		if !has["plan_accepted"] {
			if err := e.append(ctx, task, "plan_accepted", actor, map[string]any{"by": actor, "plan": "inline"}); err != nil {
				return nil, err
			}
		}
		if !has["review_verdict"] {
			last = "SKIPPED"
			if err := e.append(ctx, task, "review_verdict", actor, map[string]any{"verdict": last, "reason": "light mode has no review stage"}); err != nil {
				return nil, err
			}
		}
		return map[string]any{"last": last}, nil
	}
	if !has["plan_written"] {
		return nil, e.refuse(ctx, task, actor, "PLAN_MISSING", "mode "+string(mode)+" needs an accepted plan (rr task accept)")
	}
	if last != "PASS" {
		return nil, e.refuse(ctx, task, actor, "REVIEW_MISSING", "mode "+string(mode)+" needs a last review_verdict of PASS, have "+last)
	}
	return map[string]any{"last": last}, nil
}

// recordSession journals a ledger_session after the ledger accepted the path
// (absolute, *.jsonl, under a known transcript root, parsable).
func (e Env) recordSession(ctx context.Context, task string, actor core.Actor, s ledger.SessionData) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if _, err := ledger.Collect([]core.Event{{Type: ledger.EventSession, Data: raw}}, ledger.TranscriptRoots(e.Home, e.state())); err != nil {
		return err
	}
	return e.append(ctx, task, ledger.EventSession, actor, s)
}

func (e Env) cost(events []core.Event) map[string]any {
	items, err := ledger.Collect(events, ledger.TranscriptRoots(e.Home, e.state()))
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	prices, err := ledger.DefaultPrices()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"by_phase": ledger.Group(items, prices, "phase")}
}
