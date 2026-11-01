package autonomy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

// Wave 4.2 real run: the run's own journal stays open for the whole run, so the
// tasks it starts need a journal root of their own, or the first task is
// REFUSE {TASK_IN_FLIGHT} on the run itself. Real journals (the fake one does
// not check in-flight tasks).
func TestRunJournalDoesNotBlockItsTasks(t *testing.T) {
	e := newEnv(t)
	state := e.r.StateDir
	e.r.Journal = journal.New(filepath.Join(state, "run"))
	e.r.Tasks = journal.New(state)
	modes := map[string]core.Mode{"skip": core.ModeGuarded, "go": core.ModeLight}
	e.r.Start = func(ctx context.Context, t Task) (core.Weight, error) {
		if _, err := e.r.Tasks.Append(ctx, core.Event{Type: "task_started", Task: t.ID, Actor: core.ActorAutonomy}); err != nil {
			return core.Weight{}, err
		}
		return core.Weight{Mode: modes[t.ID]}, nil
	}
	e.r.Close = func(ctx context.Context, id string) error { return e.r.Tasks.Close(ctx, id) }
	out, err := e.r.Run(t.Context(), []Task{{ID: "skip", Brief: "x", Files: []string{"a.txt"}}, {ID: "go", Brief: "x", Files: []string{"a.txt"}}})
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, "skipped", out[0].Status)
	assert.Equal(t, "pr", out[1].Status)
	for _, id := range []string{"skip", "go"} {
		_, err := os.Stat(filepath.Join(journal.TasksDir(state), id+".jsonl"))
		assert.NoError(t, err, "task %s closed in the task journal", id)
	}
	_, err = os.Stat(filepath.Join(journal.TasksDir(filepath.Join(state, "run")), "run1.jsonl"))
	assert.NoError(t, err, "the run is closed in its own journal")
}

func TestRunRefusesWithoutTaskJournal(t *testing.T) {
	e := newEnv(t)
	e.r.Tasks = nil
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.Error(t, err)
	assert.Zero(t, e.worker.calls)
}

// A worker that failed before reporting usage still refuses BUDGET (fail-closed),
// but the journal and the error say why it failed (wave 4.2: claude refused to
// start and the reason was lost).
func TestUnknownUsageKeepsTheWorkerReason(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		return core.WorkerReport{Status: core.StatusBlocked, Body: "claude: no JSON result: Error: sandbox required but unavailable\nmore"}, nil
	}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	ref := e.refusal(t, err)
	assert.Equal(t, "BUDGET", ref.Code)
	assert.Contains(t, ref.Detail, "worker BLOCKED: claude: no JSON result: Error: sandbox required but unavailable")
	assert.NotContains(t, ref.Detail, "more")
	evs, _ := e.jr.Events(t.Context(), "run1")
	var got string
	for _, ev := range evs {
		if ev.Type == "run_budget_exceeded" {
			got = string(ev.Data)
		}
	}
	assert.Contains(t, got, `"worker":"BLOCKED: claude: no JSON result`)
}

// The worker parses only a last `STATUS:` line, so the brief must ask for it
// (wave 4.2: a real claude finished the task and was BLOCKED without it).
func TestBriefAsksForTheStatusLine(t *testing.T) {
	e := newEnv(t)
	var brief string
	e.worker.fn = func(_ context.Context, _ int, s core.WorkerSpec) (core.WorkerReport, error) {
		brief = s.Brief
		return done("ok"), os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("b\n"), 0o644)
	}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "fix a"}})
	require.NoError(t, err)
	assert.Contains(t, brief, "fix a")
	assert.Contains(t, brief, "End your report with a line `STATUS: DONE|DONE_WITH_CONCERNS|BLOCKED|NEEDS_CONTEXT`.")
	assert.Contains(t, brief, "Do not run git commit")
}

func TestQueueDeclaredAxesAreValidated(t *testing.T) {
	for _, d := range []map[core.Axis]int{{"blast": 0}, {core.AxisDomain: 3}, {core.AxisDomain: -1}} {
		e := newEnv(t)
		_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x", Declared: d}})
		require.Error(t, err, "%v", d)
		assert.Zero(t, e.worker.calls)
	}
}

// errata #52: the PR shows the triage of the real files, not the queue's claim.
func TestPRBodyShowsTheTriageWeight(t *testing.T) {
	e := newEnv(t)
	e.r.Start = func(context.Context, Task) (core.Weight, error) {
		return core.Weight{Mode: core.ModeLight, Axes: map[core.Axis]int{core.AxisCoverage: 1}, Measured: true}, nil
	}
	h := &bodyHost{lockedHost: e.host}
	e.r.Hosting = h
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x", Files: []string{"a.txt"}, Declared: map[core.Axis]int{core.AxisDomain: 0}}})
	require.NoError(t, err)
	require.Len(t, h.bodies, 1)
	b := h.bodies[0]
	assert.Contains(t, b, "- mode: light (triage of the real files)")
	assert.Contains(t, b, "- weight: W=1, declared by the queue: domain=0, irreversible=false")
	assert.NotContains(t, b, "declared only")
	assert.Equal(t, [][]string{{"rr", "rr:L2", "rr:mode:light"}}, e.host.Labels)

	b = prBody(Task{ID: "t1", Mode: core.ModeLight}, core.L2, core.WorkerReport{Status: core.StatusDone}, core.Weight{})
	assert.Contains(t, b, "- mode: light (from the queue: not triaged)")
}

// bodyHost keeps the bodies of the PRs it opens (the fake keeps only the PR).
type bodyHost struct {
	*lockedHost
	bodies []string
}

func (h *bodyHost) OpenDraftPR(ctx context.Context, head, base, title, body string, labels []string) (core.PullRequest, error) {
	h.bodies = append(h.bodies, body)
	return h.lockedHost.OpenDraftPR(ctx, head, base, title, body, labels)
}
