package autonomy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// workerFn adapts a func to core.WorkerRunner and counts calls.
type workerFn struct {
	mu    sync.Mutex
	calls int
	fn    func(ctx context.Context, n int, s core.WorkerSpec) (core.WorkerReport, error)
}

func (w *workerFn) Run(ctx context.Context, s core.WorkerSpec) (core.WorkerReport, error) {
	w.mu.Lock()
	w.calls++
	n := w.calls
	w.mu.Unlock()
	return w.fn(ctx, n, s)
}

// lockedHost makes the fake hosting safe for the poller goroutine.
type lockedHost struct {
	mu sync.Mutex
	*fakes.Hosting
}

func (h *lockedHost) ReadFile(ctx context.Context, ref, path string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.Hosting.ReadFile(ctx, ref, path)
}

func (h *lockedHost) set(key string, v []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Files[key] = v
}

func (h *lockedHost) setErr(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ReadErr = err
}

type env struct {
	root   string
	host   *lockedHost
	jr     *fakes.Journal
	clk    *fakeClock
	worker *workerFn
	rt     *fakes.Runtime
	r      *Runner
	pushed []string
	ceil   *string
	pol    core.Policy
}

func done(body string) core.WorkerReport {
	return core.WorkerReport{Status: core.StatusDone, Body: body, Tokens: 100, Calls: 2}
}

func newEnv(t *testing.T) *env {
	root := testutil.GitRepo(t, map[string]string{"riskrails.yaml": "schema: 1\n", "a.txt": "a\n", ".gitignore": ".rr/\n"})
	ceil := "c1"
	pol := pol(core.L2)
	pol.Autonomy.Unattended.MaxTasksPerDay = nil
	e := &env{root: root, host: &lockedHost{Hosting: &fakes.Hosting{Files: map[string][]byte{"main:riskrails.yaml": []byte("schema: 1\n")}}},
		jr: &fakes.Journal{}, clk: newFakeClock(), rt: &fakes.Runtime{ID: "claude", Enf: core.EnforcementSandbox}, ceil: &ceil, pol: pol}
	e.worker = &workerFn{fn: func(_ context.Context, n int, _ core.WorkerSpec) (core.WorkerReport, error) {
		return done("ok"), os.WriteFile(filepath.Join(root, "a.txt"), []byte("changed "+string(rune('0'+n))+"\n"), 0o644)
	}}
	e.r = &Runner{Root: root, StateDir: t.TempDir(), RunID: "run1", DefaultBranch: "main", Level: core.L2, Container: true,
		Runtime: e.rt, Hosting: e.host, Journal: e.jr, Worker: e.worker, Clock: e.clk,
		Gens: []core.Generator{fakes.Generator{ID: "g", Files: []core.File{{Path: ".claude/settings.json", Content: []byte(`{"l2":true}`)}}}},
		Resolve: func(context.Context, []byte) (core.EffectivePolicy, error) {
			return core.EffectivePolicy{Policy: e.pol, InForce: e.pol, PolicySHA: "p", CeilingSHA: *e.ceil}, nil
		},
		Push: func(_ context.Context, _, branch string) error { e.pushed = append(e.pushed, branch); return nil },
	}
	return e
}

func (e *env) refusal(t *testing.T, err error) *core.Refusal {
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	return ref
}

func TestL2RunOpensDraftPR(t *testing.T) {
	e := newEnv(t)
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "fix a\nmore"}})
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "pr", out[0].Status)
	assert.Equal(t, core.L2, out[0].Level)
	assert.Equal(t, []string{"rr/t1"}, e.pushed)
	require.Len(t, e.host.Opened, 1)
	assert.Contains(t, e.host.Opened[0].URL, "rr/t1")
	assert.Contains(t, e.jr.Types("run1"), "draft_pr_opened")
	assert.Contains(t, e.jr.Types("run1"), "journal_anchor")

	files := testutil.Git(t, e.root, "show", "--name-only", "--format=", "rr/t1")
	assert.Equal(t, "a.txt\n", files, "the L2 manifest is never committed")
	_, statErr := os.Stat(filepath.Join(e.root, ".claude/settings.json"))
	assert.True(t, os.IsNotExist(statErr), "container-only manifest removed afterwards")
	assert.Empty(t, testutil.Git(t, e.root, "status", "--porcelain"))
	assert.Equal(t, "main", testutil.Git(t, e.root, "rev-parse", "--abbrev-ref", "main")[:4])
}

func TestManifestIsRenderedAtL2WhileAgentRuns(t *testing.T) {
	e := newEnv(t)
	var seen []byte
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		seen, _ = os.ReadFile(filepath.Join(e.root, ".claude/settings.json"))
		return done("ok"), nil
	}
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.NoError(t, err)
	assert.Equal(t, `{"l2":true}`, string(seen))
	assert.Equal(t, "empty", out[0].Status, blockedReason(t, e))
	assert.Empty(t, e.host.Opened)
}

func TestTrackedManifestIsRestored(t *testing.T) {
	e := newEnv(t)
	require.NoError(t, os.MkdirAll(filepath.Join(e.root, ".claude"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(e.root, ".claude/settings.json"), []byte(`{"l1":true}`), 0o644))
	testutil.Git(t, e.root, "add", "-A")
	testutil.Git(t, e.root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "manifest")
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.NoError(t, err)
	assert.Equal(t, "a.txt\n", testutil.Git(t, e.root, "show", "--name-only", "--format=", "rr/t1"))
}

func TestEnforcementBelowSandboxRefusesL2(t *testing.T) {
	for _, enf := range []core.Enforcement{core.EnforcementCIOnly, core.EnforcementHookOnly} {
		e := newEnv(t)
		e.rt.Enf = enf
		_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
		assert.Equal(t, "ENFORCEMENT", e.refusal(t, err).Code)
		assert.Zero(t, e.worker.calls)
	}
	e := newEnv(t)
	e.r.Level = core.L1
	_, err := e.r.Run(t.Context(), nil)
	assert.Error(t, err, "rr run is L2+")
}

func TestHaltAtStartAndOnReadError(t *testing.T) {
	e := newEnv(t)
	e.host.set("main:.rr/HALT", []byte("stop"))
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Equal(t, "HALT", e.refusal(t, err).Code)
	assert.Zero(t, e.worker.calls)
	assert.Contains(t, e.jr.Types("run1"), "run_halted")

	e = newEnv(t)
	// riskrails.yaml readable, HALT unreadable: switch the failure on after the policy read
	n := 0
	e.r.Resolve = func(context.Context, []byte) (core.EffectivePolicy, error) {
		n++
		if n == 1 {
			e.host.setErr(errors.New("502 bad gateway"))
		}
		return core.EffectivePolicy{Policy: e.pol, PolicySHA: "p", CeilingSHA: "c1"}, nil
	}
	_, err = e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.Error(t, err)
	assert.Zero(t, e.worker.calls, "a hosting error is never 'no halt'")
}

func TestHaltDuringAgentStopsWithin60s(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(ctx context.Context, _ int, _ core.WorkerSpec) (core.WorkerReport, error) {
		<-e.clk.timers // poller is waiting for its next tick
		e.host.set("main:.rr/HALT", []byte("stop"))
		e.clk.Advance(time.Minute)
		<-ctx.Done() // the agent is killed by the halt
		return core.WorkerReport{Status: core.StatusBlocked}, ctx.Err()
	}
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}, {ID: "t2", Brief: "y"}})
	assert.Equal(t, "HALT", e.refusal(t, err).Code)
	assert.Equal(t, 1, e.worker.calls, "the second task never starts")
	assert.Len(t, out, 1)
	assert.Empty(t, e.host.Opened)
	assert.Contains(t, e.jr.Types("run1"), "run_halted")
}

func TestCeilingChangeStopsNextWave(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(_ context.Context, n int, _ core.WorkerSpec) (core.WorkerReport, error) {
		*e.ceil = "c2" // ceiling.yaml changed while task 1 ran
		return done("ok"), os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("x\n"), 0o644)
	}
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}, {ID: "t2", Brief: "y"}})
	assert.Equal(t, "CEILING_CHANGED", e.refusal(t, err).Code)
	assert.Equal(t, 1, e.worker.calls)
	assert.Len(t, out, 1)
	assert.Contains(t, e.jr.Types("run1"), "ceiling_changed")
}

func TestPolicyInForceChangeStopsNextWave(t *testing.T) {
	e := newEnv(t)
	e.r.Push = func(context.Context, string, string) error {
		e.host.set("main:riskrails.yaml", []byte("schema: 1\n# loosened on main\n"))
		return nil
	}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}, {ID: "t2", Brief: "y"}})
	assert.Equal(t, "CEILING_CHANGED", e.refusal(t, err).Code)
	assert.Equal(t, 1, e.worker.calls)
}

func TestIrreversibleAndUncoveredModesAreSkipped(t *testing.T) {
	e := newEnv(t)
	out, err := e.r.Run(t.Context(), []Task{
		{ID: "irr", Brief: "x", Irreversible: true},
		{ID: "gd", Brief: "x", Mode: core.ModeGuarded}, // ceiling L2 does not cover guarded
		{ID: "ok", Brief: "x"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, e.worker.calls)
	assert.Equal(t, []string{"skipped", "skipped", "pr"}, []string{out[0].Status, out[1].Status, out[2].Status})
	assert.Equal(t, core.L0, out[0].Level)
	assert.Equal(t, core.L1, out[1].Level)
}

func TestProtectedPathChangeBlocks(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		return done("ok"), os.WriteFile(filepath.Join(e.root, "riskrails.yaml"), []byte("schema: 1\nloose\n"), 0o644)
	}
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.NoError(t, err)
	assert.Equal(t, "blocked", out[0].Status)
	assert.Empty(t, e.pushed)
	assert.Empty(t, e.host.Opened)
	assert.Contains(t, e.jr.Types("run1"), "task_blocked")
	assert.Equal(t, "schema: 1\n", string(mustRead(t, filepath.Join(e.root, "riskrails.yaml"))))
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}

func TestBlockedWorkerOpensNoPR(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		return core.WorkerReport{Status: core.StatusNeedsContext, Tokens: 5}, nil
	}
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.NoError(t, err)
	assert.Equal(t, "blocked", out[0].Status)
	assert.Empty(t, e.host.Opened)
}

func TestMaxTasksPerDay(t *testing.T) {
	e := newEnv(t)
	one := 1
	e.pol.Autonomy.Unattended.MaxTasksPerDay = &one
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}, {ID: "t2", Brief: "y"}})
	assert.Equal(t, "BUDGET", e.refusal(t, err).Code)
	assert.Len(t, e.host.Opened, 1)
	assert.Equal(t, 1, e.worker.calls)
	assert.NotEmpty(t, out)
	assert.Contains(t, e.jr.Types("run1"), "run_budget_exceeded")
}

func TestTokenBudgetAndWallDeadline(t *testing.T) {
	e := newEnv(t)
	e.pol.Models.Budgets = map[core.Mode]core.TokenCount{core.ModeLight: 50}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Equal(t, "BUDGET", e.refusal(t, err).Code, "worker used 100 > 50")
	assert.Empty(t, e.host.Opened)

	e = newEnv(t)
	var hasDeadline bool
	e.worker.fn = func(ctx context.Context, _ int, _ core.WorkerSpec) (core.WorkerReport, error) {
		_, hasDeadline = ctx.Deadline()
		return done("ok"), nil
	}
	_, err = e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.NoError(t, err)
	assert.True(t, hasDeadline, "max_wall_minutes bounds the wave")
}

func TestJournalCopyDetectsTampering(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(ctx context.Context, n int, _ core.WorkerSpec) (core.WorkerReport, error) {
		if n == 1 { // the agent keeps a real journal for t1 inside the checkout
			j := journal.New(e.root)
			_, err := j.Append(ctx, core.Event{Type: "task_started", Task: "t1", Actor: core.ActorAgent})
			require.NoError(t, err)
		}
		return done("ok"), os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("n\n"), 0o644)
	}
	e.r.Push = func(context.Context, string, string) error { // after t1's copy was taken
		return os.Remove(filepath.Join(e.root, ".rr", "run", "t1.jsonl"))
	}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}, {ID: "t2", Brief: "y"}})
	assert.Equal(t, "JOURNAL_TAMPERED", e.refusal(t, err).Code)
	assert.Equal(t, 1, e.worker.calls)
}

func TestDirtyCheckoutRefused(t *testing.T) {
	e := newEnv(t)
	require.NoError(t, os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("dirty\n"), 0o644))
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Error(t, err)
	assert.Zero(t, e.worker.calls)
}

func TestJournalFailureAborts(t *testing.T) {
	e := newEnv(t)
	e.jr.Err = errors.New("disk full")
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Error(t, err)
	assert.Zero(t, e.worker.calls, "audit-first: no journal, no work")
}

func TestGitPushRefusesNonRRBranch(t *testing.T) {
	assert.Error(t, gitPush(t.Context(), t.TempDir(), "main"))
}
