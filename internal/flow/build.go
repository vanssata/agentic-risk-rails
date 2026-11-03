package flow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/factory"
	"github.com/vanssata/agentic-risk-rails/internal/globs"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// maxPlanBytes bounds a plan file; a plan is a short YAML list of steps.
const maxPlanBytes = 1 << 20

// DES §6 limits: parallel steps on BALANCED, turns per worker.
const (
	factoryParallel = 3
	factoryMaxTurns = 30
)

// PlanPath is the accepted copy of a task's plan, in the state dir.
func (e Env) PlanPath(task string) string {
	return filepath.Join(journal.RunDir(e.state()), task+".plan.yaml")
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// checkPlan parses and validates a plan (ids, cycles, file ownership) and requires
// every file and test of every step to lie inside the task scope: an exact scope
// path or a path matched by a scope glob.
func checkPlan(raw []byte, scope, protected []string) (plan.Plan, error) {
	p, err := plan.Parse(raw)
	if err != nil {
		return p, err
	}
	if err := plan.Check(p); err != nil {
		return p, err
	}
	for _, s := range p.Steps {
		for _, f := range append(append([]string{}, s.Files...), s.Tests...) {
			f = filepath.ToSlash(filepath.Clean(f))
			for _, c := range strings.Split(f, "/") { // nested git dirs re-point git; .rr is rr's state anywhere
				if c == ".git" || c == ".rr" {
					return p, fmt.Errorf("step %q: %q is inside a %s directory", s.ID, f, c)
				}
			}
			for _, pr := range protected {
				if globs.Match(pr, f) {
					return p, fmt.Errorf("step %q: %q is a protected path (%s)", s.ID, f, pr)
				}
			}
			ok := false
			for _, sc := range scope {
				if sc == f || (isGlob(sc) && globs.Match(sc, f)) {
					ok = true
					break
				}
			}
			if !ok {
				return p, fmt.Errorf("step %q: %q is outside the task scope", s.ID, f)
			}
		}
	}
	return p, nil
}

// protected is what no plan may own: core.AlwaysProtected and the policy's protected_paths.
func (e Env) protected() []string {
	return append(slices.Clone(core.AlwaysProtected), e.Policy.Policy.Enforcement.ProtectedPaths...)
}

// Accept is the human plan gate for guarded and heavier tasks (DES §2.3 step 3):
// the plan file must parse, pass plan.Check and stay inside the task scope. It is
// copied into the task's state and journaled as plan_checked and
// plan_accepted {by, plan: "written", sha}; Build runs only that copy.
func (e Env) Accept(ctx context.Context, task, planFile string, actor core.Actor) error {
	events, err := e.Journal.Events(ctx, task)
	if err != nil {
		return err
	}
	d, err := readStarted(events)
	if err != nil {
		return err
	}
	if actor == core.ActorAutonomy {
		if err := e.autonomyCovers(events); err != nil {
			return e.refuse(ctx, task, actor, "AUTONOMY_LEVEL", err.Error())
		}
	}
	st, err := os.Stat(planFile)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > maxPlanBytes {
		return fmt.Errorf("plan %s must be a regular file of at most %d bytes", planFile, maxPlanBytes)
	}
	raw, err := os.ReadFile(planFile)
	if err != nil {
		return err
	}
	p, err := checkPlan(raw, d.Scope, e.protected())
	if err != nil {
		code := "PLAN_INVALID"
		if strings.Contains(err.Error(), "outside the task scope") || strings.Contains(err.Error(), "protected path") {
			code = "PLAN_OUT_OF_SCOPE"
		}
		return e.refuse(ctx, task, actor, code, err.Error())
	}
	waves, err := plan.Waves(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(journal.RunDir(e.state()), 0o755); err != nil {
		return err
	}
	dst := e.PlanPath(task)
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeNew(dst, raw); err != nil {
		return err
	}
	if err := e.append(ctx, task, "plan_checked", actor, map[string]any{"steps": len(p.Steps), "waves": len(waves)}); err != nil {
		return err
	}
	return e.append(ctx, task, "plan_accepted", actor, map[string]any{"by": actor, "plan": "written", "sha": sum(raw)})
}

// acceptedPlan loads the state copy of the plan named by the last written
// plan_accepted and checks its sha. Anything missing or changed refuses.
func (e Env) acceptedPlan(ctx context.Context, task string, actor core.Actor, events []core.Event, scope []string) (plan.Plan, string, error) {
	want := ""
	for _, ev := range events {
		if ev.Type != "plan_accepted" {
			continue
		}
		var d struct {
			Plan string `json:"plan"`
			SHA  string `json:"sha"`
		}
		if json.Unmarshal(ev.Data, &d) == nil && d.Plan == "written" && d.SHA != "" {
			want = d.SHA
		}
	}
	if want == "" {
		return plan.Plan{}, "", e.refuse(ctx, task, actor, "PLAN_MISSING", "no accepted written plan (rr task accept --plan <file>)")
	}
	raw, err := os.ReadFile(e.PlanPath(task))
	if err != nil {
		return plan.Plan{}, "", e.refuse(ctx, task, actor, "PLAN_TAMPERED", "the accepted plan is unreadable: "+err.Error())
	}
	if sum(raw) != want {
		return plan.Plan{}, "", e.refuse(ctx, task, actor, "PLAN_TAMPERED", "the plan changed after plan_accepted")
	}
	p, err := checkPlan(raw, scope, e.protected())
	if err != nil {
		return p, "", e.refuse(ctx, task, actor, "PLAN_INVALID", err.Error())
	}
	return p, want, nil
}

// reviewTier is DES §7.1: BALANCED reviewers for guarded, STRONG from full up.
// STRONG stays the review tier when it is not effective; the factory falls back.
func reviewTier(m core.Mode) core.Tier {
	if m == core.ModeGuarded || m == core.ModeLight {
		return core.TierBalanced
	}
	return core.TierStrong
}

// BuildIn is the input of Build.
type BuildIn struct {
	Impl     core.WorkerRunner
	Reviewer factory.ReadOnlyRunner
	Runtime  string               // claude | codex: the runtime of both workers, for worker_usage
	Tiers    map[core.Tier]string // effective tiers of that runtime
	Actor    core.Actor           // who started the build (human)
}

// Build runs the factory over the accepted plan (DES §2.3 step 4 and 6) at the
// BALANCED tier of the effective tiers, in worktrees under the task's state, and
// journals review_verdict {stage: "factory"}: PASS only if every step of the plan
// ran, was committed and none needs a human; otherwise FAIL, and Build returns a
// FACTORY_FAILED refusal. Any internal error also journals FAIL before returning.
func (e Env) Build(ctx context.Context, task string, in BuildIn) ([]factory.Result, error) {
	events, err := e.Journal.Events(ctx, task)
	if err != nil {
		return nil, err
	}
	d, err := readStarted(events)
	if err != nil {
		return nil, err
	}
	mode, err := verify.TaskMode(events)
	if err != nil {
		return nil, err
	}
	p, planSHA, err := e.acceptedPlan(ctx, task, in.Actor, events, d.Scope)
	if err != nil {
		return nil, err
	}
	if in.Tiers[core.TierBalanced] == "" {
		return nil, &core.Refusal{Code: "NO_TIER", Detail: "no BALANCED model for runtime " + in.Runtime}
	}
	eff := map[core.Tier]bool{}
	for t, m := range in.Tiers {
		eff[t] = m != ""
	}
	work := filepath.Join(journal.RunDir(e.state()), task+".work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	meter := e.meter(task, in.Runtime)
	f := &factory.Factory{
		Config: factory.Config{Task: task, Root: e.Root, WorkDir: work, Tier: core.TierBalanced, ReviewTier: reviewTier(mode), Effective: eff,
			Parallel: factoryParallel, MaxTurns: factoryMaxTurns},
		Implementer: meter.Wrap(in.Impl),
		Reviewer:    meter.WrapRO(in.Reviewer),
		Journal:     e.Journal,
	}
	results, runErr := f.RunWaves(ctx, p)
	verdict, reason := "PASS", ""
	switch {
	case runErr != nil:
		verdict, reason = "FAIL", runErr.Error()
	case len(results) != len(p.Steps):
		verdict, reason = "FAIL", fmt.Sprintf("%d of %d steps ran", len(results), len(p.Steps))
	default:
		for _, r := range results {
			if !r.OK() || r.Human {
				verdict, reason = "FAIL", fmt.Sprintf("step %s not committed: %s", r.Step, r.Blocked)
				break
			}
		}
	}
	steps := make([]map[string]any, 0, len(results))
	for _, r := range results {
		steps = append(steps, map[string]any{"step": r.Step, "commit": r.Commit, "rounds": r.Rounds, "human": r.Human, "blocked": r.Blocked})
	}
	data := map[string]any{"by": core.ActorAutonomy, "stage": "factory", "verdict": verdict, "plan_sha": planSHA, "steps": steps}
	if reason != "" {
		data["reason"] = reason
	}
	if err := e.append(ctx, task, "review_verdict", core.ActorAutonomy, data); err != nil {
		return results, errors.Join(runErr, err)
	}
	if verdict != "PASS" {
		var ref *core.Refusal
		if errors.As(runErr, &ref) && ref.Code == "BUDGET" {
			return results, ref // the human must raise the budget, not retry
		}
		return results, &core.Refusal{Code: "FACTORY_FAILED", Detail: reason}
	}
	return results, nil
}

// autonomyCovers is the plan gate of the unattended runner: the task's level must
// cover its mode (guarded needs L3, full needs L4; light and heavier modes never
// accept by autonomy). The level is the lower of the journaled one and the one
// this host computes now, so a ceiling lowered since task_started counts.
func (e Env) autonomyCovers(events []core.Event) error {
	mode, err := verify.TaskMode(events)
	if err != nil {
		return err
	}
	need := map[core.Mode]core.Level{core.ModeGuarded: core.L3, core.ModeFull: core.L4}[mode]
	if need == 0 {
		return fmt.Errorf("mode %s has no autonomous plan gate", mode)
	}
	w, err := lastWeight(events)
	if err != nil {
		return err
	}
	have, found := lastLevel(events)
	if !found {
		return errors.New("no level recorded for the task")
	}
	now, _, _ := e.level(mode, w.Irreversible, events[0].TiersEffective)
	if have = min(have, now); have < need {
		return fmt.Errorf("level %s does not cover mode %s (needs %s)", have, mode, need)
	}
	return nil
}
