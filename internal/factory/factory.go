// Package factory runs a checked plan: one fresh worker per step in its own
// git worktree, two-stage review with escalation, and an atomic commit per
// step made by rr (the agent cannot commit, errata #14/#16/#17).
package factory

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
)

// MaxReviewRounds: rounds 1-2 at the mode's tier, round 3 one tier up, then a human (DES §6).
const MaxReviewRounds = 3

type Config struct {
	Task      string
	Root      string               // integration checkout; step commits are cherry-picked here
	WorkDir   string               // parent directory of the step worktrees
	Tier      core.Tier            // tier of the mode: implementers and rounds 1-2
	Effective map[core.Tier]string // tiers available; round 3 goes up only if the next tier is here
	Parallel  int                  // steps per wave in flight (DES §6: 3 BALANCED, 6 FAST)
	MaxTurns  int                  // per worker, DES §6: 30
	Budget    core.TokenCount
}

// ReadOnlyRunner yields a runner that cannot modify the worktree. The factory
// never calls a reviewer except through it.
type ReadOnlyRunner interface{ ReadOnly() core.WorkerRunner }

type Factory struct {
	Config
	Implementer core.WorkerRunner
	Reviewer    ReadOnlyRunner // structural: reviewers only ever run through ReadOnly()
	Journal     core.Journal

	mu sync.Mutex // serialises cherry-picks into Root
}

type Result struct {
	Step     string
	Status   core.WorkerStatus // last implementer status
	Commit   string            // SHA on the integration branch; empty if not committed
	Rounds   int               // review rounds used
	Human    bool              // review budget exhausted: a human decides
	Blocked  string            // reason, if the step stopped the wave
	Concerns string            // body of a DONE_WITH_CONCERNS report
}

// OK reports whether the step is committed.
func (r Result) OK() bool { return r.Commit != "" }

// ScopeContext arms the scope guard for a step worker: edits outside the
// step's files are denied.
func ScopeContext(gc core.GuardContext, worktree string, st plan.Step) core.GuardContext {
	gc.Root = worktree
	gc.StepFiles = append([]string{}, st.Files...) // non-nil even when empty: armed
	return gc
}

func (f *Factory) emit(ctx context.Context, typ string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = f.Journal.Append(ctx, core.Event{Schema: 1, Type: typ, Task: f.Task, Actor: core.ActorAgent, Via: "runner", Time: time.Now().UTC(), Data: raw})
	return err
}

// RunWaves runs the plan wave by wave. A BLOCKED step (or an exhausted review
// budget) stops its wave: steps not yet started are skipped and no later wave
// starts. It returns the results of every step that ran.
func (f *Factory) RunWaves(ctx context.Context, p plan.Plan) ([]Result, error) {
	if !plan.ValidID(f.Task) {
		return nil, fmt.Errorf("factory: invalid task id %q", f.Task)
	}
	waves, err := plan.Waves(p)
	if err != nil {
		return nil, err
	}
	var all []Result
	for wi, wave := range waves {
		res, err := f.runWave(ctx, wi, wave)
		all = append(all, res...)
		if err != nil {
			return all, err
		}
		if r, bad := stopper(res); bad {
			return all, f.emit(ctx, "wave_blocked", map[string]any{"wave": wi, "step": r.Step, "reason": r.Blocked})
		}
	}
	return all, nil
}

// stopper returns the step that stopped the wave: the first uncommitted one
// that actually ran, else the first uncommitted one.
func stopper(res []Result) (Result, bool) {
	var first *Result
	for i, r := range res {
		if r.OK() {
			continue
		}
		if !strings.HasPrefix(r.Blocked, "skipped") {
			return r, true
		}
		if first == nil {
			first = &res[i]
		}
	}
	if first != nil {
		return *first, true
	}
	return Result{}, false
}

func (f *Factory) runWave(parent context.Context, wi int, wave []plan.Step) ([]Result, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	sem := make(chan struct{}, max(f.Parallel, 1))
	results := make([]Result, len(wave))
	errs := make([]error, len(wave))
	var wg sync.WaitGroup
	for i, st := range wave {
		results[i] = Result{Step: st.ID, Blocked: "skipped: wave stopped"}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if ctx.Err() != nil {
				return
			}
			results[i], errs[i] = f.runStep(ctx, wi, st)
			if errs[i] != nil && parent.Err() == nil && ctx.Err() != nil {
				// cancelled because another step stopped the wave
				results[i].Blocked, errs[i] = "skipped: wave stopped while running", nil
			}
			if errs[i] != nil || !results[i].OK() {
				cancel()
			}
		}()
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return results, e
		}
	}
	return results, nil
}

// work runs one worker and journals its report.
func (f *Factory) work(ctx context.Context, st plan.Step, role, dir, brief string) (core.WorkerReport, error) {
	rep, err := f.Implementer.Run(ctx, core.WorkerSpec{Role: role, Tier: f.Tier, Brief: brief, Worktree: dir, MaxTurns: f.MaxTurns, Budget: f.Budget})
	if err != nil {
		return rep, fmt.Errorf("factory: %s of step %s: %w", role, st.ID, err)
	}
	err = f.emit(ctx, "step_report", map[string]any{"step": st.ID, "role": role, "status": rep.Status, "tokens": rep.Tokens, "calls": rep.Calls})
	return rep, err
}

func briefOf(st plan.Step) string {
	var b strings.Builder
	fmt.Fprintf(&b, "STEP %s\n%s\n\nFILES (only these may change):\n- %s\n", st.ID, st.Brief, strings.Join(st.Files, "\n- "))
	if len(st.Tests) > 0 {
		fmt.Fprintf(&b, "\nTESTS:\n- %s\n", strings.Join(st.Tests, "\n- "))
	}
	b.WriteString("\nDo not run git commit; rr commits. End your report with a line `STATUS: DONE|DONE_WITH_CONCERNS|BLOCKED|NEEDS_CONTEXT`.\n")
	return b.String()
}

func outside(changed, files []string) []string {
	own := map[string]bool{}
	for _, f := range files {
		own[filepath.ToSlash(filepath.Clean(f))] = true
	}
	var out []string
	for _, c := range changed {
		if !own[filepath.ToSlash(filepath.Clean(c))] {
			out = append(out, c)
		}
	}
	return out
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
