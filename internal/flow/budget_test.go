package flow

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
)

func usage(t *testing.T, e Env, task string, tokens int64, model string) {
	t.Helper()
	require.NoError(t, e.append(context.Background(), task, ledger.EventWorker, core.ActorAutonomy,
		ledger.WorkerData{Phase: "research", Role: "code-scout", Tier: core.TierBalanced, Runtime: "claude", Tokens: tokens, Usage: core.Usage{Model: model}}))
}

func TestBudgetBeforeEveryWorker(t *testing.T) {
	for name, tc := range map[string]struct {
		budget core.TokenCount
		prior  []int64
		model  string
		refuse bool
	}{
		"under":               {100, []int64{40, 59}, "m", false},
		"reached":             {100, []int64{40, 60}, "m", true}, // sum >= budget
		"over":                {100, []int64{150}, "m", true},
		"unknown usage":       {100, []int64{1}, "", true},
		"no budget no limit":  {0, []int64{1 << 40}, "m", false},
		"unknown, no limit":   {0, []int64{1}, "", false},
		"no runs yet":         {100, nil, "m", false},
		"exactly one below":   {100, []int64{99}, "m", false},
		"across several runs": {100, []int64{30, 30, 30, 10}, "m", true},
	} {
		t.Run(name, func(t *testing.T) {
			e, task := planEnv(t, core.ModeGuarded, core.L3, tc.budget)
			for _, n := range tc.prior {
				usage(t, e, task, n, tc.model)
			}
			inner := planner("```yaml\n" + goodYAML + "```\nSTATUS: DONE")
			_, err := e.meter(task, "claude").Wrap(inner).Run(context.Background(), core.WorkerSpec{Role: "code-scout", Tier: core.TierBalanced})
			if !tc.refuse {
				require.NoError(t, err)
				return
			}
			var ref *core.Refusal
			require.ErrorAs(t, err, &ref)
			assert.Equal(t, "BUDGET", ref.Code)
			assert.Empty(t, inner.Specs, "the worker did not start")
			assert.Contains(t, eventTypes(t, e, task), "budget_exceeded")
		})
	}
}

func TestBudgetFullIrreversibleUsesFull(t *testing.T) {
	e, task := planEnv(t, core.ModeFullIrreversible, core.L0, 0)
	e.Policy.Policy.Models.Budgets = map[core.Mode]core.TokenCount{core.ModeFull: 10}
	usage(t, e, task, 10, "m")
	_, err := e.meter(task, "claude").Wrap(planner("x")).Run(context.Background(), core.WorkerSpec{Role: "code-scout", Tier: core.TierBalanced})
	require.ErrorContains(t, err, "BUDGET")
}

func TestBudgetFailsClosed(t *testing.T) {
	e, task := planEnv(t, core.ModeGuarded, core.L3, 100)
	inner := planner("x")
	// no such task: the journal cannot say what was spent
	_, err := e.meter("nope", "claude").Wrap(inner).Run(context.Background(), core.WorkerSpec{Role: "code-scout", Tier: core.TierBalanced})
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	assert.Equal(t, "BUDGET", ref.Code)
	assert.Empty(t, inner.Specs)
	_ = task
}

func TestWorkerUsageJournaledWhenCtxCancelled(t *testing.T) {
	e, task := planEnv(t, core.ModeGuarded, core.L3, 0)
	ctx, cancel := context.WithCancel(context.Background())
	inner := &cancellingRunner{cancel: cancel}
	_, err := e.meter(task, "claude").Wrap(inner).Run(ctx, core.WorkerSpec{Role: "implementer", Step: "s1", Tier: core.TierBalanced})
	require.Error(t, err)
	evs, err := e.Journal.Events(context.Background(), task)
	require.NoError(t, err)
	var d ledger.WorkerData
	for _, ev := range evs {
		if ev.Type == ledger.EventWorker {
			require.NoError(t, json.Unmarshal(ev.Data, &d))
		}
	}
	assert.Equal(t, "s1", d.Step)
	assert.Equal(t, int64(7), d.Tokens)
}

type cancellingRunner struct{ cancel func() }

func (c *cancellingRunner) Run(ctx context.Context, _ core.WorkerSpec) (core.WorkerReport, error) {
	c.cancel()
	return core.WorkerReport{Tokens: 7, Usage: core.Usage{Model: "m"}}, errors.New("killed: " + ctx.Err().Error())
}

func TestMeterPlannerPhase(t *testing.T) {
	rec := &journalRecorder{}
	inner := &fakes.WorkerRunner{Reports: []core.WorkerReport{{Status: core.StatusDone}}}
	_, err := Meter{Emit: rec.emit}.Wrap(inner).Run(context.Background(), core.WorkerSpec{Role: "planner"})
	require.NoError(t, err)
	assert.Equal(t, "plan", rec.data[0].Phase)
}

func TestBuildReturnsBudgetRefusal(t *testing.T) {
	e, task := planEnv(t, core.ModeGuarded, core.L3, 100)
	usage(t, e, task, 100, "m")
	// no accepted plan: Build refuses earlier; here only the mapping matters, see the e2e in cmd/rr
	_, err := e.Build(context.Background(), task, BuildIn{})
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	assert.Equal(t, "PLAN_MISSING", ref.Code)
}

// Owner decision (wave 6): a run with unknown usage is charged a pessimistic
// penalty — budget_per_scout for a scout, else a tenth of the mode's budget —
// so one failed worker does not lock the task for good.
func TestBudgetChargesUnknownUsage(t *testing.T) {
	per := core.TokenCount(300)
	for name, tc := range map[string]struct {
		phase  string
		scout  *core.TokenCount
		prior  int64 // known tokens before the unknown run
		refuse bool
	}{
		"scout charged budget_per_scout, room left": {"research", &per, 0, false},
		"scout charged budget_per_scout, spent":     {"research", &per, 700, true},
		"implementer charged a tenth":               {"implement", &per, 0, false},
		"a tenth on top of 900 reaches the budget":  {"implement", &per, 900, true},
		"no budget_per_scout: a tenth":              {"research", nil, 899, false},
	} {
		t.Run(name, func(t *testing.T) {
			e, task := planEnv(t, core.ModeGuarded, core.L3, 1000)
			e.Policy.Policy.Research.BudgetPerScout = tc.scout
			if tc.prior > 0 {
				usage(t, e, task, tc.prior, "m")
			}
			require.NoError(t, e.append(context.Background(), task, ledger.EventWorker, core.ActorAutonomy,
				ledger.WorkerData{Phase: tc.phase, Role: "x", Tier: core.TierBalanced, Runtime: "claude", Status: core.StatusBlocked}))
			err := e.budgetCheck(task)(context.Background())
			if !tc.refuse {
				require.NoError(t, err)
				return
			}
			var ref *core.Refusal
			require.ErrorAs(t, err, &ref)
			assert.Equal(t, "BUDGET", ref.Code)
		})
	}
}
