package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

const (
	homeFile = "src/Controller/HomeController.php" // guarded on the reference project
	homePlan = "steps:\n  - id: home\n    brief: tweak the home page\n    files: [" + homeFile + "]\n"
)

// pipeWorkers answers every role of the L3/L4 flow: scouts with a §5.4 report, the
// planner with one fenced yaml block ending in a STATUS line (the planner protocol),
// the implementer edits its worktree, reviewers pass.
type pipeWorkers struct {
	mu    sync.Mutex
	specs []core.WorkerSpec
	plan  string
	edit  string
}

func (w *pipeWorkers) Run(_ context.Context, spec core.WorkerSpec) (core.WorkerReport, error) {
	w.mu.Lock()
	w.specs = append(w.specs, spec)
	w.mu.Unlock()
	rep := core.WorkerReport{Status: core.StatusDone, Tokens: 1000, Calls: 3,
		Usage: core.Usage{Runtime: "claude", Model: "sonnet", Input: 800, Output: 200}}
	switch {
	case strings.HasSuffix(spec.Role, "-scout"):
		rep.Body = scoutReport
	case spec.Role == "planner":
		rep.Body = "plan:\n```yaml\n" + w.plan + "```\nSTATUS: DONE"
	case strings.HasPrefix(spec.Role, "reviewer"):
		rep.Body = "no findings\nVERDICT: PASS\nSTATUS: DONE"
	default:
		if err := os.WriteFile(filepath.Join(spec.Worktree, w.edit), []byte("<?php // edited\n"), 0o644); err != nil {
			return rep, err
		}
		rep.Body = "done\nSTATUS: DONE"
	}
	return rep, nil
}

func (w *pipeWorkers) ReadOnly() core.WorkerRunner { return w }

func (w *pipeWorkers) count(prefix string) (n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range w.specs {
		if strings.Contains(s.Role, prefix) {
			n++
		}
	}
	return n
}

type pipeRun struct {
	root, state string
	host        *fakes.Hosting
	workers     *pipeWorkers
	out         []autonomy.Outcome
	err         error
	head        string
	planStubbed bool
}

// runPipelineQueue drives autonomy.Runner exactly as runQueue wires it (real
// flow.Env behind Start/Close and the pipeline; fake workers instead of containers,
// fake hosting) on a copy of the reference project, at the given ceiling.
func runPipelineQueue(t *testing.T, ceiling core.Level, plan, edit string, task autonomy.Task) *pipeRun {
	root := taskRepo(t)
	// the runner needs a clean checkout: the tiers lock is committed
	testutil.Git(t, root, "add", "-A")
	testutil.Git(t, root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "lock")
	state := t.TempDir()
	eff, err := resolve(t.Context(), root)
	require.NoError(t, err)
	pol := eff.eff
	pol.Policy.Autonomy.Ceiling = &ceiling
	pol.Policy.Autonomy.Unattended.MaxTasksPerDay = nil
	head := strings.TrimSpace(testutil.Git(t, root, "rev-parse", "HEAD"))
	host := &fakes.Hosting{Files: map[string][]byte{head + ":riskrails.yaml": []byte("schema: 1\n")}, Branches: map[string]string{"main": head}}
	tiers := core.EffectiveTiers{Runtime: "claude", Models: map[core.Tier]string{core.TierFast: "haiku", core.TierBalanced: "sonnet", core.TierStrong: "opus"}}
	w := &pipeWorkers{plan: plan, edit: edit}
	in := runFlowIn{Root: root, StateRoot: state, Home: t.TempDir(), Policy: pol, Tiers: tiers}
	start, closeTask := runFlow(in)
	sb := func(argv []string) ([]string, error) {
		return append([]string{"sh", "-c", "exit 0", "--"}, argv...), nil
	}
	r := &autonomy.Runner{Root: root, StateDir: state, RunID: "run1", DefaultBranch: pol.Policy.Project.DefaultBranch, Level: ceiling, Container: true,
		Runtime: &fakes.Runtime{ID: "claude", Enf: core.EnforcementSandbox}, Hosting: host,
		Journal: journal.New(filepath.Join(state, "run")), Tasks: journal.New(state),
		Worker: failWorker{}, Start: start, Pipeline: runPipeline(in, w, w, "claude"),
		Close: func(ctx context.Context, id string) error { return closeTask(verify.WithSandbox(ctx, sb), id) },
		Gens:  []core.Generator{fakes.Generator{ID: "g", Files: []core.File{{Path: ".claude/settings.json", Content: []byte(`{"cmd":"rr guard"}`)}}}},
		Resolve: func(context.Context, []byte) (core.EffectivePolicy, error) {
			return pol, nil
		}}
	run := &pipeRun{root: root, state: state, host: host, workers: w, head: head}
	// flow.Env.Plan is W6-B's: while it is the wave 6 stub, the planner's yaml is
	// written to a file here so the rest of the flow is still proven.
	realPlan := r.Pipeline.Plan
	r.Pipeline.Plan = func(ctx context.Context, id string) (string, error) {
		f, err := realPlan(ctx, id)
		if err != nil && strings.Contains(err.Error(), "Plan not implemented") {
			run.planStubbed = true
			f = filepath.Join(t.TempDir(), "plan.yaml")
			return f, os.WriteFile(f, []byte(plan), 0o600)
		}
		return f, err
	}
	run.out, run.err = r.Run(t.Context(), []autonomy.Task{task})
	return run
}

// failWorker is the light-path worker: guarded and full must never reach it.
type failWorker struct{}

func (failWorker) Run(context.Context, core.WorkerSpec) (core.WorkerReport, error) {
	return core.WorkerReport{}, os.ErrInvalid
}
