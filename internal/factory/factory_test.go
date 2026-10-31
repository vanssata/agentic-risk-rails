package factory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/guard"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

type runnerFunc func(core.WorkerSpec) core.WorkerReport

func (f runnerFunc) Run(_ context.Context, s core.WorkerSpec) (core.WorkerReport, error) {
	return f(s), nil
}

func rep(st core.WorkerStatus, body string) core.WorkerReport {
	return core.WorkerReport{Status: st, Body: body}
}

// writer is an implementer that edits the file named in the brief ("STEP <id>")
// and reports per-step statuses; it never commits.
type writer struct {
	mu     sync.Mutex
	roles  []string
	status map[string][]core.WorkerStatus // step -> scripted implementer statuses
	extra  map[string]string              // step -> extra file written outside the step
}

func (w *writer) Run(_ context.Context, s core.WorkerSpec) (core.WorkerReport, error) {
	id := strings.Fields(strings.TrimPrefix(s.Brief, "STEP "))[0]
	w.mu.Lock()
	w.roles = append(w.roles, s.Role+":"+id)
	st := core.StatusDone
	if q := w.status[id]; s.Role == "implementer" && len(q) > 0 {
		st, w.status[id] = q[0], q[1:]
	}
	w.mu.Unlock()
	if s.Role != "code-scout" && st != core.StatusBlocked && st != core.StatusNeedsContext {
		_ = os.WriteFile(filepath.Join(s.Worktree, id+".txt"), []byte(s.Role+"\n"), 0o644)
		if x := w.extra[id]; x != "" {
			_ = os.WriteFile(filepath.Join(s.Worktree, x), []byte("oops"), 0o644)
		}
	}
	return rep(st, "body of "+id), nil
}

func (w *writer) count(prefix string) (n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.roles {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func step(id string, after ...string) plan.Step {
	return plan.Step{ID: id, Brief: "do " + id, Files: []string{id + ".txt"}, After: after}
}

func newFactory(t *testing.T, impl, reviewer core.WorkerRunner) (*Factory, *fakes.Journal) {
	t.Helper()
	j := &fakes.Journal{}
	return &Factory{
		Config: Config{
			Task: "t1", Root: testutil.GitRepo(t, map[string]string{"README.md": "x\n"}), WorkDir: t.TempDir(),
			Tier: core.TierBalanced, Effective: map[core.Tier]string{core.TierBalanced: "sonnet", core.TierStrong: "opus"},
			Parallel: 2, MaxTurns: 30,
		},
		Implementer: impl, Reviewer: reviewer, Journal: j,
	}, j
}

func reviews(bodies ...string) *fakes.WorkerRunner {
	r := &fakes.WorkerRunner{}
	for _, b := range bodies {
		r.Reports = append(r.Reports, rep(core.StatusDone, b))
	}
	return r
}

const (
	pass1 = "no findings\nVERDICT: PASS"
	fail1 = "BLOCKER: x\nVERDICT: FAIL"
)

func TestReviewLoopBranches(t *testing.T) {
	tests := []struct {
		name       string
		reviews    []string
		strong     bool
		wantRounds int
		wantHuman  bool
		wantTiers  []core.Tier
		wantFixers int
		wantIndep  bool
	}{
		{"pass in round 1", []string{pass1, pass1}, true, 1, false, []core.Tier{"BALANCED", "BALANCED"}, 0, false},
		{"spec fails then passes", []string{fail1, pass1, pass1}, true, 2, false, []core.Tier{"BALANCED", "BALANCED", "BALANCED"}, 1, false},
		{"quality fails in round 1", []string{pass1, fail1, pass1, pass1}, true, 2, false, []core.Tier{"BALANCED", "BALANCED", "BALANCED", "BALANCED"}, 1, false},
		{"round 3 goes a tier up", []string{fail1, fail1, pass1, pass1}, true, 3, false, []core.Tier{"BALANCED", "BALANCED", "STRONG", "STRONG"}, 2, false},
		{"round 3 without next tier: same tier, independent", []string{fail1, fail1, pass1, pass1}, false, 3, false, []core.Tier{"BALANCED", "BALANCED", "BALANCED", "BALANCED"}, 2, true},
		{"round 3 fails: human", []string{fail1}, true, 3, true, []core.Tier{"BALANCED", "BALANCED", "STRONG"}, 2, false},
		{"missing verdict is a fail", []string{"looks fine to me"}, true, 3, true, nil, 2, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			impl := &writer{}
			rv := reviews(tc.reviews...)
			f, j := newFactory(t, impl, rv)
			if !tc.strong {
				delete(f.Effective, core.TierStrong)
			}
			res, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{step("a")}})
			require.NoError(t, err)
			require.Len(t, res, 1)
			assert.Equal(t, tc.wantRounds, res[0].Rounds)
			assert.Equal(t, tc.wantHuman, res[0].Human)
			assert.Equal(t, !tc.wantHuman, res[0].OK())
			assert.Equal(t, tc.wantFixers, impl.count("fixer:"))
			for i, want := range tc.wantTiers {
				assert.Equal(t, want, rv.Specs[i].Tier, "reviewer call %d", i)
			}
			last := rv.Specs[len(rv.Specs)-1]
			assert.Equal(t, tc.wantIndep, tc.wantRounds == 3 && strings.Contains(last.Brief, "independent reviewer"))
			assert.Equal(t, "reviewer-spec", rv.Specs[0].Role)
			types := j.Types("t1")
			if tc.wantHuman {
				assert.Contains(t, types, "review_budget")
				assert.NotContains(t, types, "step_committed")
				assert.Empty(t, strings.TrimSpace(testutil.Git(t, f.Root, "log", "--format=%s", "-1", "--", "a.txt")))
			} else {
				assert.NotContains(t, types, "review_budget")
			}
		})
	}
}

func TestStopsAfterSpecFailureWithoutQuality(t *testing.T) {
	rv := reviews(fail1, pass1, pass1)
	f, _ := newFactory(t, &writer{}, rv)
	_, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{step("a")}})
	require.NoError(t, err)
	var roles []string
	for _, s := range rv.Specs {
		roles = append(roles, s.Role)
	}
	assert.Equal(t, []string{"reviewer-spec", "reviewer-spec", "reviewer-quality"}, roles)
}

func TestWorkerStatuses(t *testing.T) {
	tests := []struct {
		name      string
		statuses  []core.WorkerStatus
		extra     string
		wantOK    bool
		wantBlock string
		wantScout int
		concerns  bool
	}{
		{"done", []core.WorkerStatus{"DONE"}, "", true, "", 0, false},
		{"done with concerns proceeds", []core.WorkerStatus{"DONE_WITH_CONCERNS"}, "", true, "", 0, true},
		{"needs context: scout, retry once", []core.WorkerStatus{"NEEDS_CONTEXT", "DONE"}, "", true, "", 1, false},
		{"needs context twice blocks", []core.WorkerStatus{"NEEDS_CONTEXT", "NEEDS_CONTEXT"}, "", false, "NEEDS_CONTEXT", 1, false},
		{"blocked", []core.WorkerStatus{"BLOCKED"}, "", false, "BLOCKED", 0, false},
		{"unknown status fails closed", []core.WorkerStatus{"WHATEVER"}, "", false, "WHATEVER", 0, false},
		{"edit outside the step", []core.WorkerStatus{"DONE"}, "other.txt", false, "scope", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			impl := &writer{status: map[string][]core.WorkerStatus{"a": tc.statuses}, extra: map[string]string{"a": tc.extra}}
			f, _ := newFactory(t, impl, reviews(pass1))
			res, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{step("a")}})
			require.NoError(t, err)
			require.Len(t, res, 1)
			assert.Equal(t, tc.wantOK, res[0].OK())
			assert.Contains(t, res[0].Blocked, tc.wantBlock)
			assert.Equal(t, tc.wantScout, impl.count("code-scout:"))
			assert.Equal(t, tc.concerns, res[0].Concerns != "")
			if !tc.wantOK {
				_, statErr := os.Stat(filepath.Join(f.Root, "a.txt"))
				assert.True(t, os.IsNotExist(statErr), "nothing lands in the integration checkout")
			}
		})
	}
}

func TestBlockedStopsWave(t *testing.T) {
	impl := &writer{status: map[string][]core.WorkerStatus{"b": {"BLOCKED"}}}
	f, j := newFactory(t, impl, reviews(pass1))
	p := plan.Plan{Steps: []plan.Step{step("a"), step("b"), step("c", "a", "b")}}
	res, err := f.RunWaves(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, 0, impl.count("implementer:c"), "wave 2 never starts")
	for _, r := range res {
		assert.NotEqual(t, "c", r.Step)
	}
	assert.Contains(t, j.Types("t1"), "wave_blocked")
	for _, e := range j.ByTask["t1"] {
		if e.Type == "wave_blocked" {
			assert.Contains(t, string(e.Data), `"step":"b"`)
		}
	}
}

func TestAtomicCommitPerStep(t *testing.T) {
	f, j := newFactory(t, &writer{}, reviews(pass1))
	res, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{step("a"), step("b"), step("c", "a")}})
	require.NoError(t, err)
	for _, r := range res {
		require.True(t, r.OK(), r.Blocked)
	}
	log := strings.Fields(testutil.Git(t, f.Root, "log", "--format=%H"))
	require.Len(t, log, 4) // init + 3 steps
	got := map[string]string{}
	for _, sha := range log[:3] {
		files := strings.TrimSpace(testutil.Git(t, f.Root, "show", "--name-only", "--format=%s", sha))
		subj, names, _ := strings.Cut(files, "\n")
		got[subj] = strings.TrimSpace(names)
	}
	assert.Equal(t, map[string]string{"step a": "a.txt", "step b": "b.txt", "step c": "c.txt"}, got)
	assert.Empty(t, strings.TrimSpace(testutil.Git(t, f.Root, "status", "--porcelain")))
	assert.Equal(t, 3, strings.Count(strings.Join(j.Types("t1"), ","), "step_committed"))
	// worktrees and branches are cleaned up
	assert.Equal(t, 1, strings.Count(testutil.Git(t, f.Root, "worktree", "list"), "\n"))
}

func TestParallelLimit(t *testing.T) {
	var cur, peak atomic.Int32
	impl := runnerFunc(func(s core.WorkerSpec) core.WorkerReport {
		id := strings.Fields(strings.TrimPrefix(s.Brief, "STEP "))[0]
		if s.Role == "implementer" {
			n := cur.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(60 * time.Millisecond)
			cur.Add(-1)
		}
		_ = os.WriteFile(filepath.Join(s.Worktree, id+".txt"), []byte("x"), 0o644)
		return rep(core.StatusDone, "ok")
	})
	f, _ := newFactory(t, impl, reviews(pass1))
	f.Parallel = 2
	res, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{step("a"), step("b"), step("c"), step("d")}})
	require.NoError(t, err)
	for _, r := range res {
		assert.True(t, r.OK(), r.Blocked)
	}
	assert.EqualValues(t, 2, peak.Load())
}

func TestJournalFailureStopsBeforeWork(t *testing.T) {
	impl := &writer{}
	f, j := newFactory(t, impl, reviews(pass1))
	j.Err = assert.AnError
	_, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{step("a")}})
	require.Error(t, err)
	assert.Equal(t, 0, impl.count(""), "audit-first: no worker runs when the journal fails")
}

func TestScopeContextArmsGuard(t *testing.T) {
	root := t.TempDir()
	gc := ScopeContext(core.GuardContext{Policy: fakes.StrictPolicy(), Level: core.L1, Root: "/elsewhere"}, root, step("a"))
	g := guard.New()
	edit := func(name string) core.Decision {
		return g.Check(context.Background(), core.ToolCall{Tool: "Edit", Paths: []string{filepath.Join(root, name)}, Content: "x"}, gc).Decision
	}
	assert.Equal(t, core.Allow, edit("a.txt"))
	assert.Equal(t, core.Deny, edit("b.txt"))
	empty := ScopeContext(core.GuardContext{}, root, plan.Step{ID: "z"})
	assert.NotNil(t, empty.StepFiles, "a step without files is armed, not disarmed")
}
