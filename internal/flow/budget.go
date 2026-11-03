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
// A run with unknown usage (empty Model) counts as unbounded, and so does any
// error: a budget that cannot be proven kept refuses.
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
			used += d.Tokens
			if d.Usage.Model == "" {
				unknown++
			}
		}
		if used < int64(budget) && unknown == 0 {
			return nil
		}
		detail := fmt.Sprintf("%d of %d tokens used in mode %s, %d runs with unknown usage; raise models.budgets (a human, LOOSEN) to continue", used, budget, mode, unknown)
		if err := e.append(context.WithoutCancel(ctx), task, "budget_exceeded", core.ActorAutonomy,
			map[string]any{"mode": mode, "budget": budget, "used": used, "unknown_runs": unknown}); err != nil {
			return fmt.Errorf("%w (and budget_exceeded could not be journaled: %w)", &core.Refusal{Code: "BUDGET", Detail: detail}, err)
		}
		return &core.Refusal{Code: "BUDGET", Detail: detail}
	}
}
