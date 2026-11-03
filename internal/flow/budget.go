package flow

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

func init() {
	journal.MustRegister(journal.Spec{Type: "budget_exceeded", Module: "flow",
		Doc: "mode, budget, used, unknown_runs: a worker did not start because the task's token budget is spent or its usage is unknown"})
}

// budgetFor is models.budgets for the mode; full_irreversible uses full's.
// 0 or absent = no limit.
func (e Env) budgetFor(mode core.Mode) core.TokenCount {
	b := e.Policy.Policy.Models.Budgets
	if v, ok := b[mode]; ok {
		return v
	}
	if mode == core.ModeFullIrreversible {
		return b[core.ModeFull]
	}
	return 0
}

// budgetCheck is run before every worker (DES §3.2: over budget = REFUSE). It sums
// the tokens of every worker_usage of the task, across research, plan and build.
// A run with unknown usage (empty Model) is charged unknownCharge (owner decision,
// wave 6: a pessimistic penalty, so one failed worker does not lock the task);
// any error refuses: a budget that cannot be proven kept is not kept.
func (e Env) budgetCheck(task string) func(context.Context) error {
	return func(ctx context.Context) error {
		events, err := e.Journal.Events(ctx, task)
		if err != nil {
			return &core.Refusal{Code: "BUDGET", Detail: "task journal unreadable: " + err.Error()}
		}
		mode, err := verify.TaskMode(events)
		if err != nil {
			return &core.Refusal{Code: "BUDGET", Detail: err.Error()}
		}
		budget := e.budgetFor(mode)
		if budget <= 0 {
			return nil
		}
		var used int64
		unknown := 0
		for _, ev := range events {
			if ev.Type != ledger.EventWorker {
				continue
			}
			var d ledger.WorkerData
			if err := json.Unmarshal(ev.Data, &d); err != nil {
				return &core.Refusal{Code: "BUDGET", Detail: "unreadable worker_usage: " + err.Error()}
			}
			if d.Usage.Model == "" {
				unknown++
				used += max(d.Tokens, e.unknownCharge(d.Phase, budget))
				continue
			}
			used += d.Tokens
		}
		if used < int64(budget) {
			return nil
		}
		detail := fmt.Sprintf("%d of %d tokens used in mode %s, %d runs with unknown usage charged as spent; raise models.budgets (a human, LOOSEN) to continue", used, budget, mode, unknown)
		if err := e.append(context.WithoutCancel(ctx), task, "budget_exceeded", core.ActorAutonomy,
			map[string]any{"mode": mode, "budget": budget, "used": used, "unknown_runs": unknown}); err != nil {
			return fmt.Errorf("%w (and budget_exceeded could not be journaled: %w)", &core.Refusal{Code: "BUDGET", Detail: detail}, err)
		}
		return &core.Refusal{Code: "BUDGET", Detail: detail}
	}
}

// unknownCharge is what a worker run with unknown usage costs: research.budget_per_scout
// for a scout, otherwise a tenth of the mode's budget.
func (e Env) unknownCharge(phase string, budget core.TokenCount) int64 {
	if p := e.Policy.Policy.Research.BudgetPerScout; phase == "research" && p != nil && *p > 0 {
		return int64(*p)
	}
	return max(int64(budget)/10, 1)
}
